//! Tests for the autofill module.

use std::collections::BTreeMap;
use std::sync::Arc;

use less_db::{
    collection::autofill::{autofill, autofill_for_update, generate_uuid, AutofillOptions},
    schema::node::{created_at_schema, key_schema, t, updated_at_schema, SchemaNode},
};
use serde_json::json;

// ============================================================================
// Helpers
// ============================================================================

fn schema(pairs: &[(&str, SchemaNode)]) -> BTreeMap<String, SchemaNode> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn opts_with_now(now: &str) -> AutofillOptions {
    AutofillOptions {
        now: Some(now.to_string()),
        is_new: true,
        generate_key: None,
    }
}

// ============================================================================
// generate_uuid
// ============================================================================

#[test]
fn generates_valid_uuidv4_format() {
    let uuid = generate_uuid();
    let re =
        regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .unwrap();
    assert!(re.is_match(&uuid), "Not a valid UUIDv4: {uuid}");
}

#[test]
fn generates_unique_values() {
    let uuids: std::collections::HashSet<String> = (0..100).map(|_| generate_uuid()).collect();
    assert_eq!(uuids.len(), 100);
}

// ============================================================================
// Key Field
// ============================================================================

#[test]
fn generates_key_when_missing() {
    let s = schema(&[("id", key_schema()), ("name", t::string())]);
    let result = autofill(&s, &json!({ "name": "John" }), &AutofillOptions::default());

    let id = result["id"].as_str().unwrap();
    assert!(!id.is_empty());
    assert_eq!(result["name"], "John");
}

#[test]
fn preserves_existing_key() {
    let s = schema(&[("id", key_schema()), ("name", t::string())]);
    let result = autofill(
        &s,
        &json!({ "id": "custom-id", "name": "John" }),
        &AutofillOptions::default(),
    );

    assert_eq!(result["id"], "custom-id");
}

#[test]
fn generates_key_for_empty_string() {
    let s = schema(&[("id", key_schema()), ("name", t::string())]);
    let result = autofill(
        &s,
        &json!({ "id": "", "name": "John" }),
        &AutofillOptions::default(),
    );

    assert_ne!(result["id"].as_str().unwrap(), "");
}

#[test]
fn uses_custom_key_generator() {
    let s = schema(&[("id", key_schema()), ("name", t::string())]);
    let opts = AutofillOptions {
        now: None,
        is_new: true,
        generate_key: Some(Arc::new(|| "custom-key".to_string())),
    };
    let result = autofill(&s, &json!({ "name": "John" }), &opts);

    assert_eq!(result["id"], "custom-key");
}

// ============================================================================
// createdAt Field
// ============================================================================

#[test]
fn sets_created_at_for_new_records() {
    let s = schema(&[("name", t::string()), ("createdAt", created_at_schema())]);
    let result = autofill(
        &s,
        &json!({ "name": "John" }),
        &opts_with_now("2024-01-15T10:30:00Z"),
    );

    assert_eq!(result["createdAt"], "2024-01-15T10:30:00Z");
}

#[test]
fn preserves_existing_created_at() {
    let s = schema(&[("name", t::string()), ("createdAt", created_at_schema())]);
    let result = autofill(
        &s,
        &json!({ "name": "John", "createdAt": "2024-01-01T00:00:00Z" }),
        &opts_with_now("2024-01-15T10:30:00Z"),
    );

    assert_eq!(result["createdAt"], "2024-01-01T00:00:00Z");
}

#[test]
fn sets_created_at_if_missing_even_for_updates() {
    let s = schema(&[("name", t::string()), ("createdAt", created_at_schema())]);
    let opts = AutofillOptions {
        now: Some("2024-01-15T10:30:00Z".to_string()),
        is_new: false,
        generate_key: None,
    };
    let result = autofill(&s, &json!({ "name": "John" }), &opts);

    assert_eq!(result["createdAt"], "2024-01-15T10:30:00Z");
}

// ============================================================================
// updatedAt Field
// ============================================================================

#[test]
fn always_sets_updated_at() {
    let s = schema(&[("name", t::string()), ("updatedAt", updated_at_schema())]);
    let result = autofill(
        &s,
        &json!({ "name": "John" }),
        &opts_with_now("2024-01-15T10:30:00Z"),
    );

    assert_eq!(result["updatedAt"], "2024-01-15T10:30:00Z");
}

#[test]
fn overwrites_existing_updated_at() {
    let s = schema(&[("name", t::string()), ("updatedAt", updated_at_schema())]);
    let result = autofill(
        &s,
        &json!({ "name": "John", "updatedAt": "2024-01-01T00:00:00Z" }),
        &opts_with_now("2024-01-15T10:30:00Z"),
    );

    assert_eq!(result["updatedAt"], "2024-01-15T10:30:00Z");
}

// ============================================================================
// Nested Objects
// ============================================================================

#[test]
fn autofills_keys_in_nested_objects() {
    let mut user_props = BTreeMap::new();
    user_props.insert("id".to_string(), key_schema());
    user_props.insert("name".to_string(), t::string());

    let s = schema(&[("user", t::object(user_props))]);
    let result = autofill(
        &s,
        &json!({ "user": { "name": "John" } }),
        &AutofillOptions::default(),
    );

    let id = result["user"]["id"].as_str().unwrap();
    assert!(!id.is_empty());
}

// ============================================================================
// Arrays
// ============================================================================

#[test]
fn autofills_keys_in_array_elements() {
    let mut item_props = BTreeMap::new();
    item_props.insert("id".to_string(), key_schema());
    item_props.insert("title".to_string(), t::string());

    let s = schema(&[("items", t::array(t::object(item_props)))]);
    let result = autofill(
        &s,
        &json!({ "items": [{ "title": "First" }, { "title": "Second" }] }),
        &AutofillOptions::default(),
    );

    let items = result["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let id0 = items[0]["id"].as_str().unwrap();
    let id1 = items[1]["id"].as_str().unwrap();
    assert!(!id0.is_empty());
    assert!(!id1.is_empty());
    assert_ne!(id0, id1);
}

// ============================================================================
// Optional Fields
// ============================================================================

#[test]
fn handles_undefined_optional_with_auto_field_inside() {
    let mut meta_props = BTreeMap::new();
    meta_props.insert("id".to_string(), key_schema());
    meta_props.insert("value".to_string(), t::string());

    let s = schema(&[
        ("name", t::string()),
        ("metadata", t::optional(t::object(meta_props))),
    ]);
    let result = autofill(&s, &json!({ "name": "John" }), &AutofillOptions::default());

    // metadata is null/absent — should stay null
    assert!(result["metadata"].is_null());
}

#[test]
fn autofills_when_optional_is_present() {
    let mut meta_props = BTreeMap::new();
    meta_props.insert("id".to_string(), key_schema());
    meta_props.insert("value".to_string(), t::string());

    let s = schema(&[
        ("name", t::string()),
        ("metadata", t::optional(t::object(meta_props))),
    ]);
    let result = autofill(
        &s,
        &json!({ "name": "John", "metadata": { "value": "test" } }),
        &AutofillOptions::default(),
    );

    let id = result["metadata"]["id"].as_str().unwrap();
    assert!(!id.is_empty());
}

// ============================================================================
// Records
// ============================================================================

#[test]
fn autofills_values_in_records() {
    let mut entry_props = BTreeMap::new();
    entry_props.insert("id".to_string(), key_schema());
    entry_props.insert("count".to_string(), t::number());

    let s = schema(&[("entries", t::record(t::object(entry_props)))]);
    let result = autofill(
        &s,
        &json!({ "entries": { "a": { "count": 1 }, "b": { "count": 2 } } }),
        &AutofillOptions::default(),
    );

    let id_a = result["entries"]["a"]["id"].as_str().unwrap();
    let id_b = result["entries"]["b"]["id"].as_str().unwrap();
    assert!(!id_a.is_empty());
    assert!(!id_b.is_empty());
    assert_ne!(id_a, id_b);
}

// ============================================================================
// Unions
// ============================================================================

#[test]
fn autofills_keys_inside_union_object_variants() {
    let mut user_props = BTreeMap::new();
    user_props.insert("type".to_string(), t::literal_str("user"));
    user_props.insert("id".to_string(), key_schema());
    user_props.insert("name".to_string(), t::string());

    let mut group_props = BTreeMap::new();
    group_props.insert("type".to_string(), t::literal_str("group"));
    group_props.insert("id".to_string(), key_schema());
    group_props.insert("title".to_string(), t::string());

    let s = schema(&[(
        "item",
        t::union(vec![t::object(user_props), t::object(group_props)]),
    )]);

    let result = autofill(
        &s,
        &json!({ "item": { "type": "user", "name": "John" } }),
        &AutofillOptions::default(),
    );

    let id = result["item"]["id"].as_str().unwrap();
    assert!(!id.is_empty());
}

#[test]
fn passes_through_union_value_when_no_variant_matches() {
    let mut a_props = BTreeMap::new();
    a_props.insert("kind".to_string(), t::literal_str("a"));

    let mut b_props = BTreeMap::new();
    b_props.insert("kind".to_string(), t::literal_str("b"));

    let s = schema(&[(
        "value",
        t::union(vec![t::object(a_props), t::object(b_props)]),
    )]);

    // Value with kind "c" doesn't match any variant — should be returned as-is
    let result = autofill(
        &s,
        &json!({ "value": { "kind": "c" } }),
        &AutofillOptions::default(),
    );

    assert_eq!(result["value"]["kind"], "c");
}

// ============================================================================
// autofill_for_update
// ============================================================================

#[test]
fn autofill_for_update_preserves_created_at() {
    let s = schema(&[
        ("name", t::string()),
        ("createdAt", created_at_schema()),
        ("updatedAt", updated_at_schema()),
    ]);

    let opts = AutofillOptions {
        now: Some("2024-01-15T10:30:00Z".to_string()),
        is_new: false,
        generate_key: None,
    };

    let result = autofill_for_update(
        &s,
        &json!({ "name": "John", "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z" }),
        &opts,
    );

    assert_eq!(result["createdAt"], "2024-01-01T00:00:00Z");
    assert_eq!(result["updatedAt"], "2024-01-15T10:30:00Z");
}

// ============================================================================
// Full Example
// ============================================================================

#[test]
fn handles_typical_document_schema() {
    let mut author_props = BTreeMap::new();
    author_props.insert("id".to_string(), key_schema());
    author_props.insert("name".to_string(), t::string());

    let s = schema(&[
        ("id", key_schema()),
        ("title", t::string()),
        ("content", t::string()),
        ("tags", t::array(t::string())),
        ("author", t::object(author_props)),
        ("createdAt", created_at_schema()),
        ("updatedAt", updated_at_schema()),
    ]);

    let result = autofill(
        &s,
        &json!({
            "title": "Test Post",
            "content": "Hello world",
            "tags": ["test", "example"],
            "author": { "name": "John" },
        }),
        &opts_with_now("2024-01-15T10:30:00Z"),
    );

    assert!(result["id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(result["author"]["id"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert_eq!(result["createdAt"], "2024-01-15T10:30:00Z");
    assert_eq!(result["updatedAt"], "2024-01-15T10:30:00Z");
    assert_eq!(result["title"], "Test Post");
    assert_eq!(result["tags"], json!(["test", "example"]));
}

// ============================================================================
// Extra fields stripped (matching JS behavior)
// ============================================================================

#[test]
fn strips_extra_fields_not_in_schema() {
    let s = schema(&[("id", key_schema()), ("name", t::string())]);
    let result = autofill(
        &s,
        &json!({ "name": "John", "extra_field": "should be stripped", "another": 42 }),
        &AutofillOptions::default(),
    );

    assert_eq!(result["name"], "John");
    assert!(result["id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(result.get("extra_field").is_none());
    assert!(result.get("another").is_none());
}

#[test]
fn strips_extra_fields_in_nested_objects() {
    let mut inner_props = BTreeMap::new();
    inner_props.insert("name".to_string(), t::string());

    let s = schema(&[("nested", t::object(inner_props))]);
    let result = autofill(
        &s,
        &json!({ "nested": { "name": "John", "extra": "gone" } }),
        &AutofillOptions::default(),
    );

    assert_eq!(result["nested"]["name"], "John");
    assert!(result["nested"].get("extra").is_none());
}

// ============================================================================
// Union variant matching with discriminated unions
// ============================================================================

#[test]
fn autofills_first_matching_variant_in_union() {
    // Both variants are objects, so matchesVariant matches the first one
    // for any object value (same as JS behavior)
    let mut user_props = BTreeMap::new();
    user_props.insert("type".to_string(), t::literal_str("user"));
    user_props.insert("id".to_string(), key_schema());
    user_props.insert("name".to_string(), t::string());

    let mut group_props = BTreeMap::new();
    group_props.insert("type".to_string(), t::literal_str("group"));
    group_props.insert("id".to_string(), key_schema());
    group_props.insert("title".to_string(), t::string());

    let s = schema(&[(
        "item",
        t::union(vec![t::object(user_props), t::object(group_props)]),
    )]);

    // With a user-typed object: matches first variant, fills user schema
    let result = autofill(
        &s,
        &json!({ "item": { "type": "user", "name": "John" } }),
        &AutofillOptions::default(),
    );
    let id = result["item"]["id"].as_str().unwrap();
    assert!(!id.is_empty());
    assert_eq!(result["item"]["type"], "user");
    assert_eq!(result["item"]["name"], "John");
}

#[test]
fn union_with_scalar_variants_passes_through() {
    let s = schema(&[("value", t::union(vec![t::string(), t::number()]))]);

    let result = autofill(
        &s,
        &json!({ "value": 42 }),
        &opts_with_now("2024-01-01T00:00:00Z"),
    );
    assert_eq!(result["value"], 42);

    let result = autofill(
        &s,
        &json!({ "value": "hello" }),
        &opts_with_now("2024-01-01T00:00:00Z"),
    );
    assert_eq!(result["value"], "hello");
}

// ============================================================================
// Non-object data
// ============================================================================

#[test]
fn non_object_data_returns_as_is() {
    let s = schema(&[("name", t::string())]);
    let result = autofill(&s, &json!("just a string"), &AutofillOptions::default());
    assert_eq!(result, json!("just a string"));
}

// ============================================================================
// Depth Limits
// ============================================================================

#[test]
#[should_panic(expected = "Maximum autofill depth exceeded")]
fn panics_on_extremely_deep_nesting() {
    // Build 102 levels of nested objects (exceeds max of 100)
    let mut inner = t::object({
        let mut m = BTreeMap::new();
        m.insert("value".to_string(), t::string());
        m
    });
    for _ in 0..101 {
        let mut m = BTreeMap::new();
        m.insert("nested".to_string(), inner);
        inner = t::object(m);
    }

    let s = schema(&[("root", inner)]);

    // Build corresponding deeply nested value
    let mut value: serde_json::Value = json!({ "value": "test" });
    for _ in 0..101 {
        value = json!({ "nested": value });
    }

    autofill(&s, &json!({ "root": value }), &AutofillOptions::default());
}

#[test]
fn allows_reasonable_nesting_depth() {
    let mut inner = t::object({
        let mut m = BTreeMap::new();
        m.insert("value".to_string(), t::string());
        m
    });
    for _ in 0..10 {
        let mut m = BTreeMap::new();
        m.insert("nested".to_string(), inner);
        inner = t::object(m);
    }

    let s = schema(&[("root", inner)]);

    let mut value: serde_json::Value = json!({ "value": "test" });
    for _ in 0..10 {
        value = json!({ "nested": value });
    }

    let result = autofill(&s, &json!({ "root": value }), &AutofillOptions::default());
    assert!(result.is_object());
}
