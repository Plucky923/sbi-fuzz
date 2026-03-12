use common::{SBI_COVERAGE_BUFFER_ADDR, SBI_COVERAGE_PC_CAPACITY};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const INSTRUMENT_PATCH: &str = include_str!("./instrument.patch");
const OPENSBI_TRACE_PC_FLAG: &str = "CFLAGS += -fsanitize-coverage=trace-pc\n";
const OPENSBI_OBJECTS_LINE: &str = "libsbi-objs-y += sbi_cov.o\n";

pub fn instrument_kasan(path: PathBuf) {
    if !path.is_dir() {
        panic!("The specified path is not a directory, expected OpenSBI source code");
    }

    let patch_state = apply_opensbi_patch(&path);
    install_shared_coverage_trace_pc(&path);

    println!(
        "OpenSBI instrumentation ready ({patch_state}); shared coverage at 0x{SBI_COVERAGE_BUFFER_ADDR:x}, capacity {SBI_COVERAGE_PC_CAPACITY}. Run `make PLATFORM=generic LLVM=1` to build."
    );
}

fn apply_opensbi_patch(path: &Path) -> &'static str {
    let temp_patch_path = path.join("temp_patch.patch");
    fs::write(&temp_patch_path, INSTRUMENT_PATCH).expect("write instrument patch");

    let check_output = Command::new("git")
        .current_dir(path)
        .args(["apply", "--check", "temp_patch.patch"])
        .output()
        .expect("check instrument patch");

    let patch_state = if check_output.status.success() {
        let output = Command::new("git")
            .current_dir(path)
            .args(["apply", "temp_patch.patch"])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("apply instrument patch");
        if !output.status.success() {
            fs::remove_file(&temp_patch_path).expect("remove temporary patch file");
            panic!("failed to apply OpenSBI instrument patch");
        }
        "applied KASAN patch"
    } else {
        let reverse_check = Command::new("git")
            .current_dir(path)
            .args(["apply", "--reverse", "--check", "temp_patch.patch"])
            .output()
            .expect("check reversed instrument patch");
        if reverse_check.status.success() || kasan_patch_markers_present(path) {
            "KASAN patch already present"
        } else {
            fs::remove_file(&temp_patch_path).expect("remove temporary patch file");
            panic!(
                "failed to apply OpenSBI instrument patch; target tree is neither clean nor already instrumented"
            );
        }
    };

    fs::remove_file(&temp_patch_path).expect("remove temporary patch file");
    patch_state
}

fn kasan_patch_markers_present(path: &Path) -> bool {
    path.join("lib/kasan/kasan.c").is_file()
        && fs::read_to_string(path.join("Makefile"))
            .map(|content| content.contains("KASAN_CC_FLAGS :="))
            .unwrap_or(false)
}

fn install_shared_coverage_trace_pc(path: &Path) {
    let coverage_source_path = path.join("lib/sbi/sbi_cov.c");
    fs::write(&coverage_source_path, render_opensbi_trace_pc_source())
        .expect("write OpenSBI trace-pc coverage source");

    ensure_line_after(
        &path.join("lib/sbi/objects.mk"),
        "libsbi-objs-y += sbi_console.o\n",
        OPENSBI_OBJECTS_LINE,
    );
    ensure_line_after(
        &path.join("Makefile"),
        "CFLAGS += $(KASAN_CC_FLAGS)\n",
        OPENSBI_TRACE_PC_FLAG,
    );
}

fn ensure_line_after(path: &Path, anchor: &str, line: &str) {
    let mut content = fs::read_to_string(path).expect("read OpenSBI source file");
    if content.contains(line) {
        return;
    }

    if let Some(pos) = content.find(anchor) {
        content.insert_str(pos + anchor.len(), line);
    } else {
        if !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(line);
    }

    fs::write(path, content).expect("write OpenSBI source file");
}

fn render_opensbi_trace_pc_source() -> String {
    format!(
        "/*\n \
* SPDX-License-Identifier: BSD-2-Clause\n \
*\n \
* Shared-memory sanitizer coverage hooks for sbifuzz.\n \
*/\n\n\
#include <sbi/sbi_types.h>\n\n\
#if defined(__clang__)\n\
#define SBIFUZZ_NO_SANITIZE __attribute__((disable_sanitizer_instrumentation))\n\
#else\n\
#define SBIFUZZ_NO_SANITIZE\n\
#endif\n\n\
#define SBIFUZZ_COVERAGE_ADDR {:#x}UL\n\
#define SBIFUZZ_COVERAGE_CAPACITY {}\n\n\
struct sbifuzz_coverage_buffer {{\n\
\tvolatile unsigned long count;\n\
\tvolatile unsigned long pcs[SBIFUZZ_COVERAGE_CAPACITY];\n\
}};\n\n\
static SBIFUZZ_NO_SANITIZE struct sbifuzz_coverage_buffer *sbifuzz_cov_buffer(void)\n{{\n\
\treturn (struct sbifuzz_coverage_buffer *)SBIFUZZ_COVERAGE_ADDR;\n\
}}\n\n\
static SBIFUZZ_NO_SANITIZE void sbifuzz_cov_record_pc(unsigned long pc)\n{{\n\
\tstruct sbifuzz_coverage_buffer *buf = sbifuzz_cov_buffer();\n\
\tunsigned long count = buf->count;\n\n\
\tif (count >= SBIFUZZ_COVERAGE_CAPACITY)\n\
\t\treturn;\n\
\tif (count > 0 && buf->pcs[count - 1] == pc)\n\
\t\treturn;\n\n\
\tbuf->pcs[count] = pc;\n\
\tbuf->count = count + 1;\n\
}}\n\n\
void SBIFUZZ_NO_SANITIZE __attribute__((used)) __sanitizer_cov_trace_pc(void)\n{{\n\
\tsbifuzz_cov_record_pc((unsigned long)__builtin_return_address(0));\n\
}}\n",
        SBI_COVERAGE_BUFFER_ADDR, SBI_COVERAGE_PC_CAPACITY
    )
}
