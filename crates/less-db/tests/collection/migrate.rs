//! Tests for the collection migration engine.

use std::collections::BTreeMap;

use less_db::{
    collection::{
        builder::collection,
        migrate::{
            migrate, migrate_or_throw, needs_migration, test_migration, test_migration_chain,
        },
    },
    error::LessDbError,
    schema::node::t,
};

// ============================================================================
// Helpers
// ============================================================================

fn schema(
    pairs: &[(&str, less_db::schema::node::SchemaNode)],
) -> BTreeMap<String, less_db::schema::node::SchemaNode> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn with_auto_fields(data: serde_json::Value) -> serde_json::Value {
    let mut obj = data.as_object().cloned().unwrap_or_default();
    obj.insert("id".into(), serde_json::json!("test-id"));
    obj.insert(
        "createdAt".into(),
        serde_json::json!("2024-01-01T00:00:00Z"),
    );
    obj.insert(
        "updatedAt".into(),
        serde_json::json!("2024-01-01T00:00:00Z"),
    );
    serde_json::Value::Object(obj)
}

// ============================================================================
// No Migration Needed
// ============================================================================

#[test]
fn returns_document_as_is_when_at_current_version() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .build();

    let result = migrate(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John" })),
        1,
        None,
    )
    .expect("migrate failed");

    assert_eq!(result.data["name"], "John");
    assert_eq!(result.data["id"], "test-id");
    assert_eq!(result.steps_applied, 0);
    assert_eq!(result.migrated_from, 1);
    assert_eq!(result.migrated_to, 1);
}

#[test]
fn validates_document_even_without_migration() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string()), ("age", t::number())]))
        .build();

    let result = migrate(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John", "age": "not a number" })),
        1,
        None,
    );

    assert!(result.is_err());
}

// ============================================================================
// Single Step Migration
// ============================================================================

#[test]
fn migrates_from_v1_to_v2() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(
            2,
            schema(&[("first_name", t::string()), ("last_name", t::string())]),
            |prev| {
                let name = prev
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let parts: Vec<&str> = name.splitn(2, ' ').collect();
                Ok(serde_json::json!({
                    "first_name": parts.first().copied().unwrap_or(""),
                    "last_name": parts.get(1).copied().unwrap_or(""),
                }))
            },
        )
        .build();

    let result = migrate(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John Doe" })),
        1,
        None,
    )
    .expect("migrate failed");

    assert_eq!(result.data["first_name"], "John");
    assert_eq!(result.data["last_name"], "Doe");
    assert_eq!(result.data["id"], "test-id"); // auto-fields preserved
    assert_eq!(result.steps_applied, 1);
}

// ============================================================================
// Multi-Step Migration
// ============================================================================

#[test]
fn migrates_through_multiple_versions() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(
            2,
            schema(&[("first_name", t::string()), ("last_name", t::string())]),
            |prev| {
                let name = prev
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let parts: Vec<&str> = name.splitn(2, ' ').collect();
                Ok(serde_json::json!({
                    "first_name": parts.first().copied().unwrap_or(""),
                    "last_name": parts.get(1).copied().unwrap_or(""),
                }))
            },
        )
        .v(
            3,
            schema(&[
                ("first_name", t::string()),
                ("last_name", t::string()),
                ("display_name", t::string()),
            ]),
            |prev| {
                let first = prev
                    .get("first_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let last = prev.get("last_name").and_then(|v| v.as_str()).unwrap_or("");
                Ok(serde_json::json!({
                    "first_name": first,
                    "last_name": last,
                    "display_name": format!("{} {}", first, last).trim().to_string(),
                }))
            },
        )
        .build();

    let result = migrate(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John Doe" })),
        1,
        None,
    )
    .expect("migrate failed");

    assert_eq!(result.data["first_name"], "John");
    assert_eq!(result.data["last_name"], "Doe");
    assert_eq!(result.data["display_name"], "John Doe");
    assert_eq!(result.steps_applied, 2);
    assert_eq!(result.migrated_from, 1);
    assert_eq!(result.migrated_to, 3);
}

#[test]
fn migrates_from_intermediate_version() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(
            2,
            schema(&[("first_name", t::string()), ("last_name", t::string())]),
            |prev| {
                let name = prev
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let parts: Vec<&str> = name.splitn(2, ' ').collect();
                Ok(serde_json::json!({
                    "first_name": parts.first().copied().unwrap_or(""),
                    "last_name": parts.get(1).copied().unwrap_or(""),
                }))
            },
        )
        .v(
            3,
            schema(&[
                ("first_name", t::string()),
                ("last_name", t::string()),
                ("display_name", t::string()),
            ]),
            |prev| {
                let first = prev
                    .get("first_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let last = prev.get("last_name").and_then(|v| v.as_str()).unwrap_or("");
                Ok(serde_json::json!({
                    "first_name": first,
                    "last_name": last,
                    "display_name": format!("{} {}", first, last).trim().to_string(),
                }))
            },
        )
        .build();

    let result = migrate(
        &users,
        with_auto_fields(serde_json::json!({ "first_name": "Jane", "last_name": "Smith" })),
        2,
        None,
    )
    .expect("migrate failed");

    assert_eq!(result.data["display_name"], "Jane Smith");
    assert_eq!(result.steps_applied, 1);
}

// ============================================================================
// Error Handling
// ============================================================================

#[test]
fn returns_error_for_version_zero() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .build();

    let result = migrate(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John" })),
        0,
        None,
    );

    assert!(result.is_err());
    if let Err(LessDbError::Migration(e)) = result {
        assert!(e.source.to_string().contains("Invalid source version") || e.failed_at == 0);
    } else {
        panic!("Expected MigrationError");
    }
}

#[test]
fn returns_error_for_future_version() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .build();

    let result = migrate(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John" })),
        5,
        None,
    );

    assert!(result.is_err());
    assert!(matches!(result, Err(LessDbError::Migration(_))));
}

// Note: fractional version test skipped — u32 type in Rust prevents fractional versions.

#[test]
fn captures_migration_function_errors() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(2, schema(&[("first_name", t::string())]), |_prev| {
            Err("Migration failed!".into())
        })
        .build();

    let result = migrate(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John" })),
        1,
        Some("user-123"),
    );

    assert!(result.is_err());
    if let Err(LessDbError::Migration(e)) = result {
        assert_eq!(e.collection, "users");
        assert_eq!(e.record_id, "user-123");
        assert_eq!(e.failed_at, 2);
    } else {
        panic!("Expected MigrationError");
    }
}

#[test]
fn returns_validation_error_if_migrated_data_is_invalid() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(
            2,
            schema(&[("name", t::string()), ("age", t::number())]),
            |prev| {
                Ok(serde_json::json!({
                    "name": prev.get("name").cloned().unwrap_or_default(),
                    "age": "not a number",  // intentionally invalid
                }))
            },
        )
        .build();

    let result = migrate(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John" })),
        1,
        None,
    );

    assert!(result.is_err());
    assert!(matches!(result, Err(LessDbError::Migration(_))));
}

// ============================================================================
// migrate_or_throw
// ============================================================================

#[test]
fn migrate_or_throw_returns_data_on_success() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .build();

    let data = migrate_or_throw(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John" })),
        1,
    )
    .expect("should succeed");

    assert_eq!(data["name"], "John");
    assert_eq!(data["id"], "test-id");
}

#[test]
fn migrate_or_throw_returns_error_on_failure() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .build();

    // Pass invalid data (name should be string, not number)
    let result = migrate_or_throw(
        &users,
        with_auto_fields(serde_json::json!({ "name": 123 })),
        1,
    );

    assert!(result.is_err());
}

// ============================================================================
// needs_migration
// ============================================================================

#[test]
fn needs_migration_returns_false_when_at_current_version() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(
            2,
            schema(&[("name", t::string()), ("email", t::string())]),
            |prev| Ok(serde_json::json!({ "name": prev.get("name").cloned().unwrap_or_default(), "email": "" })),
        )
        .build();

    assert!(!needs_migration(&users, 2));
}

#[test]
fn needs_migration_returns_true_when_below_current_version() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(
            2,
            schema(&[("name", t::string()), ("email", t::string())]),
            |prev| Ok(serde_json::json!({ "name": prev.get("name").cloned().unwrap_or_default(), "email": "" })),
        )
        .build();

    assert!(needs_migration(&users, 1));
}

// ============================================================================
// test_migration helper
// ============================================================================

#[test]
fn test_migration_helper_passes_on_success() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(
            2,
            schema(&[("first_name", t::string()), ("last_name", t::string())]),
            |prev| {
                let name = prev
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let parts: Vec<&str> = name.splitn(2, ' ').collect();
                Ok(serde_json::json!({
                    "first_name": parts.first().copied().unwrap_or(""),
                    "last_name": parts.get(1).copied().unwrap_or(""),
                }))
            },
        )
        .build();

    test_migration(
        &users,
        1,
        with_auto_fields(serde_json::json!({ "name": "John Doe" })),
        |output| {
            assert_eq!(output["first_name"], "John");
            assert_eq!(output["last_name"], "Doe");
        },
    );
}

#[test]
fn test_migration_chain_tests_full_chain_from_v1() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(
            2,
            schema(&[("first_name", t::string()), ("last_name", t::string())]),
            |prev| {
                let name = prev
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let parts: Vec<&str> = name.splitn(2, ' ').collect();
                Ok(serde_json::json!({
                    "first_name": parts.first().copied().unwrap_or(""),
                    "last_name": parts.get(1).copied().unwrap_or(""),
                }))
            },
        )
        .v(
            3,
            schema(&[
                ("first_name", t::string()),
                ("last_name", t::string()),
                ("initials", t::string()),
            ]),
            |prev| {
                let first = prev
                    .get("first_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let last = prev.get("last_name").and_then(|v| v.as_str()).unwrap_or("");
                let initials = format!(
                    "{}{}",
                    first.chars().next().unwrap_or_default(),
                    last.chars().next().unwrap_or_default()
                );
                Ok(serde_json::json!({
                    "first_name": first,
                    "last_name": last,
                    "initials": initials,
                }))
            },
        )
        .build();

    test_migration_chain(
        &users,
        with_auto_fields(serde_json::json!({ "name": "John Doe" })),
        |output| {
            assert_eq!(output["first_name"], "John");
            assert_eq!(output["last_name"], "Doe");
            assert_eq!(output["initials"], "JD");
        },
    );
}

// ============================================================================
// test-migration error paths
// ============================================================================

#[test]
#[should_panic(expected = "Migration failed")]
fn test_migration_throws_on_migration_failure() {
    let broken = collection("broken")
        .v(1, schema(&[("name", t::string())]))
        .v(2, schema(&[("first", t::string())]), |_| Err("boom".into()))
        .build();

    test_migration(&broken, 1, serde_json::json!({ "name": "John" }), |_| {});
}

#[test]
#[should_panic(expected = "Migration chain failed")]
fn test_migration_chain_throws_on_migration_failure() {
    let broken = collection("broken")
        .v(1, schema(&[("name", t::string())]))
        .v(2, schema(&[("first", t::string())]), |_| Err("boom".into()))
        .build();

    test_migration_chain(&broken, serde_json::json!({ "name": "John" }), |_| {});
}
