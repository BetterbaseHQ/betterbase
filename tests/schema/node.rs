use less_db::schema::node::t;
use less_db::schema::node::{
    created_at_schema, is_auto_field, is_immutable_field, is_indexable_node, is_timestamp_field,
    key_schema, updated_at_schema, LiteralValue, SchemaNode,
};
use std::collections::BTreeMap;

// ============================================================================
// Builder API
// ============================================================================

#[test]
fn string_schema_tag() {
    assert_eq!(t::string(), SchemaNode::String);
}

#[test]
fn number_schema_tag() {
    assert_eq!(t::number(), SchemaNode::Number);
}

#[test]
fn boolean_schema_tag() {
    assert_eq!(t::boolean(), SchemaNode::Boolean);
}

#[test]
fn date_schema_tag() {
    assert_eq!(t::date(), SchemaNode::Date);
}

#[test]
fn bytes_schema_tag() {
    assert_eq!(t::bytes(), SchemaNode::Bytes);
}

#[test]
fn optional_wraps_inner() {
    let schema = t::optional(t::string());
    assert_eq!(schema, SchemaNode::Optional(Box::new(SchemaNode::String)));
}

#[test]
fn array_wraps_element() {
    let schema = t::array(t::number());
    assert_eq!(schema, SchemaNode::Array(Box::new(SchemaNode::Number)));
}

#[test]
fn record_wraps_value() {
    let schema = t::record(t::boolean());
    assert_eq!(schema, SchemaNode::Record(Box::new(SchemaNode::Boolean)));
}

#[test]
fn object_holds_properties() {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), t::string());
    props.insert("age".to_string(), t::number());
    let schema = t::object(props.clone());
    assert_eq!(schema, SchemaNode::Object(props));
}

#[test]
fn literal_str_variant() {
    let schema = t::literal_str("active");
    assert_eq!(
        schema,
        SchemaNode::Literal(LiteralValue::String("active".to_string()))
    );
}

#[test]
fn literal_num_variant() {
    let schema = t::literal_num(42.0);
    assert_eq!(schema, SchemaNode::Literal(LiteralValue::Number(42.0)));
}

#[test]
fn literal_bool_variant() {
    let schema = t::literal_bool(true);
    assert_eq!(schema, SchemaNode::Literal(LiteralValue::Bool(true)));
}

#[test]
fn union_holds_variants() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert_eq!(
        schema,
        SchemaNode::Union(vec![SchemaNode::String, SchemaNode::Number])
    );
}

#[test]
#[should_panic(expected = "Union must have at least one variant")]
fn union_panics_on_empty() {
    t::union(vec![]);
}

// ============================================================================
// Auto-Field Constructors
// ============================================================================

#[test]
fn key_schema_tag() {
    assert_eq!(key_schema(), SchemaNode::Key);
}

#[test]
fn created_at_schema_tag() {
    assert_eq!(created_at_schema(), SchemaNode::CreatedAt);
}

#[test]
fn updated_at_schema_tag() {
    assert_eq!(updated_at_schema(), SchemaNode::UpdatedAt);
}

// ============================================================================
// Predicates
// ============================================================================

#[test]
fn is_auto_field_key() {
    assert!(is_auto_field(&key_schema()));
}

#[test]
fn is_auto_field_created_at() {
    assert!(is_auto_field(&created_at_schema()));
}

#[test]
fn is_auto_field_updated_at() {
    assert!(is_auto_field(&updated_at_schema()));
}

#[test]
fn is_auto_field_rejects_others() {
    assert!(!is_auto_field(&t::string()));
    assert!(!is_auto_field(&t::number()));
    assert!(!is_auto_field(&t::date()));
    assert!(!is_auto_field(&t::optional(t::string())));
}

#[test]
fn is_timestamp_field_created_at() {
    assert!(is_timestamp_field(&created_at_schema()));
}

#[test]
fn is_timestamp_field_updated_at() {
    assert!(is_timestamp_field(&updated_at_schema()));
}

#[test]
fn is_timestamp_field_rejects_key() {
    assert!(!is_timestamp_field(&key_schema()));
}

#[test]
fn is_timestamp_field_rejects_date() {
    // Plain Date is not a timestamp auto-field
    assert!(!is_timestamp_field(&t::date()));
}

#[test]
fn is_immutable_field_key() {
    assert!(is_immutable_field(&key_schema()));
}

#[test]
fn is_immutable_field_created_at() {
    assert!(is_immutable_field(&created_at_schema()));
}

#[test]
fn is_immutable_field_rejects_updated_at() {
    assert!(!is_immutable_field(&updated_at_schema()));
}

#[test]
fn is_immutable_field_rejects_others() {
    assert!(!is_immutable_field(&t::string()));
}

#[test]
fn is_indexable_node_string() {
    assert!(is_indexable_node(&t::string()));
}

#[test]
fn is_indexable_node_number() {
    assert!(is_indexable_node(&t::number()));
}

#[test]
fn is_indexable_node_boolean() {
    assert!(is_indexable_node(&t::boolean()));
}

#[test]
fn is_indexable_node_date() {
    assert!(is_indexable_node(&t::date()));
}

#[test]
fn is_indexable_node_key() {
    assert!(is_indexable_node(&key_schema()));
}

#[test]
fn is_indexable_node_created_at() {
    assert!(is_indexable_node(&created_at_schema()));
}

#[test]
fn is_indexable_node_updated_at() {
    assert!(is_indexable_node(&updated_at_schema()));
}

#[test]
fn is_indexable_node_literal() {
    assert!(is_indexable_node(&t::literal_str("x")));
    assert!(is_indexable_node(&t::literal_num(1.0)));
    assert!(is_indexable_node(&t::literal_bool(false)));
}

#[test]
fn is_indexable_node_rejects_array() {
    assert!(!is_indexable_node(&t::array(t::string())));
}

#[test]
fn is_indexable_node_rejects_object() {
    assert!(!is_indexable_node(&t::object(BTreeMap::new())));
}

#[test]
fn is_indexable_node_rejects_optional() {
    assert!(!is_indexable_node(&t::optional(t::string())));
}

#[test]
fn is_indexable_node_rejects_bytes() {
    assert!(!is_indexable_node(&t::bytes()));
}
