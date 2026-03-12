use std::env;
use std::path::{Path, PathBuf};

fn opensbi_root(manifest_dir: &Path) -> PathBuf {
    let candidates = [
        manifest_dir.join("../playground/opensbi-fuzz/output/opensbi"),
        manifest_dir.join("../playground/opensbi-sanitizer-demo/output/opensbi"),
    ];

    for candidate in candidates {
        if candidate.is_dir() {
            return candidate;
        }
    }

    panic!(
        "OpenSBI source tree not found under playground outputs; run `make -C playground/opensbi-fuzz prepare` first"
    );
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let opensbi = opensbi_root(&manifest_dir);
    let native_dir = manifest_dir.join("src/native");
    let native_include = native_dir.join("include");
    let libfdt_dir = opensbi.join("lib/utils/libfdt");
    let opensbi_include = opensbi.join("include");

    let ecall_sources = [
        "lib/sbi/sbi_ecall.c",
        "lib/sbi/sbi_ecall_base.c",
        "lib/sbi/sbi_ecall_time.c",
        "lib/sbi/sbi_ecall_ipi.c",
        "lib/sbi/sbi_ecall_rfence.c",
        "lib/sbi/sbi_ecall_hsm.c",
        "lib/sbi/sbi_ecall_dbcn.c",
        "lib/sbi/sbi_ecall_pmu.c",
    ];
    let libfdt_sources = [
        "fdt.c",
        "fdt_addresses.c",
        "fdt_check.c",
        "fdt_empty_tree.c",
        "fdt_ro.c",
        "fdt_rw.c",
        "fdt_strerror.c",
        "fdt_sw.c",
        "fdt_wip.c",
    ];

    for source in &ecall_sources {
        println!("cargo:rerun-if-changed={}", opensbi.join(source).display());
    }
    for source in &libfdt_sources {
        println!(
            "cargo:rerun-if-changed={}",
            libfdt_dir.join(source).display()
        );
    }
    println!(
        "cargo:rerun-if-changed={}",
        native_dir.join("opensbi_host_shim.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        native_dir.join("rustsbi_fdt_shim.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        native_include.join("sbi/riscv_asm.h").display()
    );

    let mut build = cc::Build::new();
    build
        .include(&native_include)
        .include(&opensbi_include)
        .include(&libfdt_dir)
        .file(native_dir.join("opensbi_host_shim.c"))
        .file(native_dir.join("rustsbi_fdt_shim.c"))
        .define("__riscv_xlen", "64")
        .define("OPENSBI_VERSION_MAJOR", "1")
        .define("OPENSBI_VERSION_MINOR", "6")
        .warnings(false);

    for source in &ecall_sources {
        build.file(opensbi.join(source));
    }
    for source in &libfdt_sources {
        build.file(libfdt_dir.join(source));
    }

    build.compile("sbifuzz_host_harness");
}
