# SBI Extension Quick Reference

## Extension IDs (EID)

| Hex       | Decimal    | Name   | Description                  | rustsbi Trait | Internal Fn        |
|-----------|------------|--------|------------------------------|---------------|--------------------|
| 0x10      | 16         | base   | Base Extension               | (built-in)    | —                  |
| 0x735049  | 7557193    | ipi    | IPI Extension                | `Ipi`         | `_rustsbi_ipi`     |
| 0x52464E43| 1380339267 | rfence | RFENCE Extension             | `Fence`       | `_rustsbi_fence`   |
| 0x48534D  | 4738381    | hsm    | Hart State Management        | `Hsm`         | `_rustsbi_hsm`     |
| 0x54494D45| 1414093125 | timer  | Timer Extension              | `Timer`       | `_rustsbi_timer`   |
| 0x53525354| 1397113172 | reset  | System Reset                 | `Reset`       | `_rustsbi_reset`   |
| 0x4442434E| 1145527118 | dbcn   | Debug Console                | `Console`     | `_rustsbi_console` |
| 0x504D55  | 5263701    | pmu    | Performance Monitoring       | —             | —                  |
| 0x53555350| 1397969744 | susp   | System Suspend               | —             | —                  |

## Common Spec Violations

### HartMaskInvalidNotRejected
**Trigger**: IPI or RFENCE call with a `hart_mask` that references an invalid hart ID.  
**Expected**: `SBI_ERR_INVALID_PARAM` (`-3`)  
**Actual (bug)**: `SBI_SUCCESS` (`0`)

**Spec citation** (RISC-V SBI Specification, Binary Encoding §3.1, Table 2):
> Any SBI function taking hart mask arguments may return the error values listed in the Hart Mask Errors below which are in addition to function specific error values.
>
> | Error code | Description |
> |---|---|
> | `SBI_ERR_INVALID_PARAM` | At least one hartid constructed from `hart_mask_base` and `hart_mask`, is not valid, i.e. either the hartid is not enabled by the platform or is not available to the supervisor. |

### WrongErrorCode (HSM hart_start on started hart)
**Trigger**: `sbi_hart_start` is called on a hart that is already started.  
**Expected**: `SBI_ERR_ALREADY_AVAILABLE` (`-6`)  
**Actual (bug)**: `SBI_ERR_INVALID_PARAM` (`-3`)

**Spec citation** (RISC-V SBI Specification, Hart State Management Extension §9.1, Table 19):
> | Error code | Description |
> |---|---|
> | `SBI_SUCCESS` | Hart was previously in stopped state. It will start executing from `start_addr`. |
> | `SBI_ERR_INVALID_PARAM` | `hartid` is not a valid hartid as the corresponding hart cannot be started in supervisor mode. |
> | `SBI_ERR_ALREADY_AVAILABLE` | The given `hartid` is already started. |

### WrongValue
**Trigger**: A Base extension probe or version query returns an unexpected value.

## Standalone Reproducer Oracle Logic

### Hart mask validity check
```rust
fn check_hart_mask_invalid(hart_mask: u64, hart_mask_base: u64) -> Option<u64> {
    const MAX_HARTS: u64 = 64; // platform-dependent; fuzzer uses 64
    if hart_mask == 0 { return None; }
    if hart_mask_base >= MAX_HARTS { return Some(hart_mask_base); }
    for bit in 0..64 {
        if (hart_mask >> bit) & 1 == 0 { continue; }
        let hart_id = hart_mask_base.saturating_add(bit);
        if hart_id >= MAX_HARTS { return Some(hart_id); }
    }
    None
}
```

If `check_hart_mask_invalid` returns `Some(invalid_hart)`, the SBI implementation MUST NOT return `SBI_SUCCESS` (`error == 0`). It must return `SBI_ERR_INVALID_PARAM` (`-3`).
