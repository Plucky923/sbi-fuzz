use common::{ArgumentKind, CallSchema, load_call_schema_registry_from_dir, resolve_call_schema};
use std::fs;
use tempfile::tempdir;

#[test]
fn load_schema_registry_supports_exact_and_wildcard_entries() {
    let temp_dir = tempdir().expect("create tempdir");
    fs::write(
        temp_dir.path().join("custom.toml"),
        r#"
[[calls]]
eid = 0x48534D
fid = 0x0
arg0 = "hart_id"
arg1 = "address_low"
arg2 = "opaque"

[[calls]]
eid = 0x735049
arg0 = "hart_mask_address"
"#,
    )
    .expect("write schema file");

    let registry =
        load_call_schema_registry_from_dir(temp_dir.path()).expect("load schema registry");
    assert_eq!(registry.entry_count(), 2);
    assert_eq!(
        registry.schema_for_call(0x48534D, 0x0),
        Some(CallSchema::new(
            ArgumentKind::HartId,
            ArgumentKind::AddressLow,
            ArgumentKind::Opaque,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ))
    );
    assert_eq!(
        registry.schema_for_call(0x735049, 0x99),
        Some(CallSchema::new(
            ArgumentKind::HartMaskAddress,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
            ArgumentKind::Value,
        ))
    );
}

#[test]
fn resolve_call_schema_prefers_registry_override_over_builtin_schema() {
    let temp_dir = tempdir().expect("create tempdir");
    fs::write(
        temp_dir.path().join("override.toml"),
        r#"
[[calls]]
eid = 0x48534D
fid = 0x0
arg0 = "hart_id"
arg1 = "address_low"
arg2 = "opaque"
"#,
    )
    .expect("write schema file");

    let registry =
        load_call_schema_registry_from_dir(temp_dir.path()).expect("load schema registry");
    let resolved = resolve_call_schema(Some(&registry), 0x48534D, 0x0);
    assert_eq!(resolved.arg0, ArgumentKind::HartId);
    assert_eq!(resolved.arg1, ArgumentKind::AddressLow);
    assert_eq!(resolved.arg2, ArgumentKind::Opaque);
}
