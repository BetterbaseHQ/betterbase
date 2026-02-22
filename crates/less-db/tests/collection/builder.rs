//! Tests for the collection builder API.

use std::collections::BTreeMap;

use less_db::{
    collection::builder::{collection, get_version_schema, to_object_schema},
    index::types::IndexableValue,
    schema::node::{t, SchemaNode},
};

// ============================================================================
// Helpers
// ============================================================================

/// Build a schema from key-value pairs.
fn schema(pairs: &[(&str, SchemaNode)]) -> BTreeMap<String, SchemaNode> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

// ============================================================================
// Basic Usage
// ============================================================================

#[test]
fn creates_collection_with_v1_schema() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string()), ("email", t::string())]))
        .build();

    assert_eq!(users.name, "users");
    assert_eq!(users.current_version, 1);
    assert_eq!(users.versions.len(), 1);
    assert_eq!(users.versions[0].version, 1);
    assert!(users.versions[0].migrate.is_none());
}

#[test]
fn creates_collection_with_multiple_versions() {
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
                let first = parts.first().copied().unwrap_or("").to_string();
                let last = parts.get(1).copied().unwrap_or("").to_string();
                Ok(serde_json::json!({ "first_name": first, "last_name": last }))
            },
        )
        .build();

    assert_eq!(users.name, "users");
    assert_eq!(users.current_version, 2);
    assert_eq!(users.versions.len(), 2);
    assert_eq!(users.versions[0].version, 1);
    assert_eq!(users.versions[1].version, 2);
    assert!(users.versions[1].migrate.is_some());
}

#[test]
fn supports_three_version_chain() {
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
                    "display_name": format!("{first} {last}").trim().to_string(),
                }))
            },
        )
        .build();

    assert_eq!(users.current_version, 3);
    assert_eq!(users.versions.len(), 3);
}

#[test]
#[should_panic(expected = "Version must be 2, got 3")]
fn panics_on_non_sequential_version_numbers() {
    collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(3, schema(&[("name", t::string())]), Ok);
}

#[test]
#[should_panic(expected = "Collection name cannot be empty")]
fn panics_on_empty_collection_name() {
    collection("");
}

#[test]
#[should_panic(expected = "Collection name cannot be empty")]
fn panics_on_whitespace_only_collection_name() {
    collection("   ");
}

#[test]
#[should_panic(expected = "invalid characters")]
fn panics_on_collection_name_with_special_characters() {
    collection("my'; DROP TABLE");
}

#[test]
#[should_panic(expected = "invalid characters")]
fn panics_on_collection_name_starting_with_number() {
    collection("123abc");
}

// ============================================================================
// Auto-Fields
// ============================================================================

#[test]
fn auto_fields_added_by_build() {
    let items = collection("items")
        .v(1, schema(&[("title", t::string())]))
        .build();

    assert!(matches!(
        items.current_schema.get("id"),
        Some(SchemaNode::Key)
    ));
    assert!(matches!(
        items.current_schema.get("createdAt"),
        Some(SchemaNode::CreatedAt)
    ));
    assert!(matches!(
        items.current_schema.get("updatedAt"),
        Some(SchemaNode::UpdatedAt)
    ));
}

#[test]
#[should_panic(expected = "reserved")]
fn rejects_reserved_id_field() {
    collection("items").v(1, schema(&[("id", t::string()), ("name", t::string())]));
}

#[test]
#[should_panic(expected = "reserved")]
fn rejects_reserved_created_at_field() {
    collection("items").v(
        1,
        schema(&[("createdAt", t::date()), ("name", t::string())]),
    );
}

#[test]
#[should_panic(expected = "reserved")]
fn rejects_reserved_updated_at_field() {
    collection("items").v(
        1,
        schema(&[("updatedAt", t::date()), ("name", t::string())]),
    );
}

#[test]
#[should_panic(expected = "reserved")]
fn rejects_reserved_fields_in_later_versions() {
    collection("items")
        .v(1, schema(&[("name", t::string())]))
        .v(2, schema(&[("id", t::string()), ("name", t::string())]), Ok);
}

#[test]
#[should_panic(expected = "invalid characters")]
fn rejects_field_names_with_special_characters() {
    collection("items").v(1, schema(&[("name'; DROP TABLE", t::string())]));
}

#[test]
#[should_panic(expected = "invalid characters")]
fn rejects_field_names_starting_with_number() {
    collection("items").v(1, schema(&[("123field", t::string())]));
}

#[test]
fn accepts_field_names_with_underscores() {
    let items = collection("items")
        .v(
            1,
            schema(&[("_private", t::string()), ("my_field", t::string())]),
        )
        .build();
    assert!(matches!(
        items.current_schema.get("_private"),
        Some(SchemaNode::String)
    ));
}

// ============================================================================
// Complex Schemas
// ============================================================================

#[test]
fn supports_nested_objects() {
    let mut settings = BTreeMap::new();
    settings.insert("theme".to_string(), t::string());
    settings.insert("notifications".to_string(), t::boolean());

    let mut user_props = BTreeMap::new();
    user_props.insert("name".to_string(), t::string());
    user_props.insert("settings".to_string(), t::object(settings));

    let profiles = collection("profiles")
        .v(1, schema(&[("user", t::object(user_props))]))
        .build();

    assert!(matches!(
        profiles.current_schema.get("user"),
        Some(SchemaNode::Object(_))
    ));
}

#[test]
fn supports_arrays() {
    let posts = collection("posts")
        .v(
            1,
            schema(&[("title", t::string()), ("tags", t::array(t::string()))]),
        )
        .build();

    assert!(matches!(
        posts.current_schema.get("tags"),
        Some(SchemaNode::Array(_))
    ));
}

#[test]
fn supports_optionals() {
    let users = collection("users")
        .v(
            1,
            schema(&[("name", t::string()), ("bio", t::optional(t::string()))]),
        )
        .build();

    assert!(matches!(
        users.current_schema.get("bio"),
        Some(SchemaNode::Optional(_))
    ));
}

// ============================================================================
// Index Validation
// ============================================================================

#[test]
#[should_panic(expected = "already defined")]
fn rejects_duplicate_index_names() {
    collection("test")
        .v(1, schema(&[("email", t::string()), ("name", t::string())]))
        .index(&["email"])
        .index(&["email"]);
}

#[test]
#[should_panic(expected = "unknown field")]
fn rejects_unknown_field_in_index() {
    collection("test")
        .v(1, schema(&[("email", t::string())]))
        .index(&["nonexistent"]);
}

#[test]
#[should_panic(expected = "non-indexable type")]
fn rejects_non_indexable_field_type_in_index() {
    collection("test")
        .v(1, schema(&[("data", t::array(t::string()))]))
        .index(&["data"]);
}

#[test]
#[should_panic(expected = "sparse and compound")]
fn rejects_sparse_compound_index() {
    collection("test")
        .v(1, schema(&[("a", t::string()), ("b", t::string())]))
        .index_with(&["a", "b"], None, false, true);
}

#[test]
#[should_panic(expected = "already defined")]
fn rejects_duplicate_computed_index_names() {
    collection("test")
        .v(1, schema(&[("name", t::string())]))
        .computed("idx", |doc| {
            doc.get("name")
                .and_then(|v| v.as_str())
                .map(|s| IndexableValue::String(s.to_lowercase()))
        })
        .computed("idx", |doc| {
            doc.get("name")
                .and_then(|v| v.as_str())
                .map(|s| IndexableValue::String(s.to_uppercase()))
        });
}

#[test]
#[should_panic(expected = "conflicts with field")]
fn rejects_computed_index_name_conflicting_with_field_name() {
    collection("test")
        .v(1, schema(&[("name", t::string())]))
        .computed("name", |doc| {
            doc.get("name")
                .and_then(|v| v.as_str())
                .map(|s| IndexableValue::String(s.to_lowercase()))
        })
        .build();
}

#[test]
#[should_panic(expected = "invalid characters")]
fn rejects_unsafe_computed_index_names() {
    collection("items")
        .v(1, schema(&[("email", t::string())]))
        .computed("bad'; DROP TABLE", |doc| {
            doc.get("email")
                .and_then(|v| v.as_str())
                .map(|s| IndexableValue::String(s.to_string()))
        });
}

#[test]
#[should_panic(expected = "invalid characters")]
fn rejects_unsafe_explicit_index_names() {
    collection("items")
        .v(1, schema(&[("email", t::string())]))
        .index_with(&["email"], Some("idx'; DROP"), false, false);
}

#[test]
fn can_index_auto_fields() {
    // Auto-fields (id, createdAt, updatedAt) should be indexable
    let coll = collection("items")
        .v(1, schema(&[("title", t::string())]))
        .index(&["createdAt"])
        .index(&["id"])
        .build();

    assert_eq!(coll.indexes.len(), 2);
}

// ============================================================================
// get_version_schema and to_object_schema
// ============================================================================

#[test]
fn get_version_schema_returns_schema_for_valid_version() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .v(
            2,
            schema(&[("first_name", t::string()), ("last_name", t::string())]),
            Ok,
        )
        .build();

    let s = get_version_schema(&users, 1);
    assert!(s.is_some());
    assert!(s.unwrap().contains_key("name"));
}

#[test]
fn get_version_schema_returns_none_for_invalid_version() {
    let users = collection("users")
        .v(1, schema(&[("name", t::string())]))
        .build();

    assert!(get_version_schema(&users, 99).is_none());
}

#[test]
fn to_object_schema_wraps_shape() {
    let shape = schema(&[("name", t::string())]);
    let obj = to_object_schema(shape.clone());
    assert!(matches!(obj, SchemaNode::Object(_)));
    if let SchemaNode::Object(props) = obj {
        assert!(props.contains_key("name"));
    }
}
