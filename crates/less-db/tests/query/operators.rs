//! Tests for query operators — ported from less-db-js/tests/query/operators.test.ts

use less_db::error::{LessDbError, QueryError};
use less_db::query::operators::{
    compare_values, deep_equals, filter_records, get_field_value, is_operator,
    matches_computed_filter, matches_filter,
};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;

// ============================================================================
// compare_values
// ============================================================================

#[test]
fn compare_both_null() {
    assert_eq!(compare_values(&Value::Null, &Value::Null), Ordering::Equal);
}

#[test]
fn compare_null_sorts_to_end_positive() {
    assert_eq!(compare_values(&Value::Null, &json!(1)), Ordering::Greater);
}

#[test]
fn compare_null_sorts_to_end_negative() {
    assert_eq!(compare_values(&json!(1), &Value::Null), Ordering::Less);
}

#[test]
fn compare_numbers() {
    assert_eq!(compare_values(&json!(1), &json!(2)), Ordering::Less);
    assert_eq!(compare_values(&json!(2), &json!(1)), Ordering::Greater);
    assert_eq!(compare_values(&json!(5), &json!(5)), Ordering::Equal);
}

#[test]
fn compare_negative_numbers() {
    assert_eq!(compare_values(&json!(-5), &json!(5)), Ordering::Less);
    assert_eq!(compare_values(&json!(-1), &json!(-2)), Ordering::Greater);
}

#[test]
fn compare_decimals() {
    assert_eq!(compare_values(&json!(1.5), &json!(1.6)), Ordering::Less);
    assert_eq!(compare_values(&json!(1.5), &json!(1.5)), Ordering::Equal);
}

#[test]
fn compare_strings_lexicographic() {
    assert_eq!(
        compare_values(&json!("apple"), &json!("banana")),
        Ordering::Less
    );
    assert_eq!(
        compare_values(&json!("banana"), &json!("apple")),
        Ordering::Greater
    );
    assert_eq!(
        compare_values(&json!("test"), &json!("test")),
        Ordering::Equal
    );
}

#[test]
fn compare_empty_strings() {
    assert_eq!(compare_values(&json!(""), &json!("a")), Ordering::Less);
    assert_eq!(compare_values(&json!("a"), &json!("")), Ordering::Greater);
}

#[test]
fn compare_strings_binary_order() {
    // Z (90) < a (97) in binary/Unicode
    assert_eq!(compare_values(&json!("Z"), &json!("a")), Ordering::Less);
    assert_eq!(compare_values(&json!("B"), &json!("a")), Ordering::Less);
}

#[test]
fn compare_dates_as_iso_strings() {
    // Dates stored as ISO strings — lexicographic order works for ISO 8601
    assert_eq!(
        compare_values(&json!("2024-01-01"), &json!("2024-12-31")),
        Ordering::Less
    );
    assert_eq!(
        compare_values(&json!("2024-12-31"), &json!("2024-01-01")),
        Ordering::Greater
    );
    assert_eq!(
        compare_values(
            &json!("2024-06-15T10:30:00Z"),
            &json!("2024-06-15T10:30:00Z")
        ),
        Ordering::Equal
    );
}

#[test]
fn compare_booleans_false_lt_true() {
    assert_eq!(compare_values(&json!(false), &json!(true)), Ordering::Less);
    assert_eq!(
        compare_values(&json!(true), &json!(false)),
        Ordering::Greater
    );
    assert_eq!(compare_values(&json!(true), &json!(true)), Ordering::Equal);
    assert_eq!(
        compare_values(&json!(false), &json!(false)),
        Ordering::Equal
    );
}

#[test]
fn compare_cross_type_number_lt_string() {
    // number(0) < string(1) < bool(2) < other(3)
    assert_eq!(compare_values(&json!(42), &json!("hello")), Ordering::Less);
    assert_eq!(
        compare_values(&json!("hello"), &json!(42)),
        Ordering::Greater
    );
}

#[test]
fn compare_cross_type_string_lt_bool() {
    assert_eq!(
        compare_values(&json!("hello"), &json!(true)),
        Ordering::Less
    );
    assert_eq!(
        compare_values(&json!(true), &json!("hello")),
        Ordering::Greater
    );
}

#[test]
fn compare_cross_type_bool_lt_object() {
    // object has rank 3 (other)
    assert_eq!(compare_values(&json!(true), &json!({})), Ordering::Less);
    assert_eq!(compare_values(&json!({}), &json!(true)), Ordering::Greater);
}

#[test]
fn compare_cross_type_number_lt_object() {
    assert_eq!(compare_values(&json!(42), &json!({})), Ordering::Less);
}

#[test]
fn compare_cross_type_consistent() {
    let values = [json!(42), json!("hello"), json!(true), json!({})];
    for i in 0..values.len() {
        for j in (i + 1)..values.len() {
            let forward = compare_values(&values[i], &values[j]);
            let backward = compare_values(&values[j], &values[i]);
            // Signs must be opposite
            assert_ne!(forward, backward, "i={i}, j={j}");
        }
    }
}

// ============================================================================
// deep_equals
// ============================================================================

#[test]
fn deep_equals_primitives() {
    assert!(deep_equals(&json!("hello"), &json!("hello")));
    assert!(!deep_equals(&json!("hello"), &json!("world")));
    assert!(deep_equals(&json!(42), &json!(42)));
    assert!(!deep_equals(&json!(42), &json!(43)));
    assert!(deep_equals(&json!(true), &json!(true)));
    assert!(!deep_equals(&json!(true), &json!(false)));
    assert!(deep_equals(&Value::Null, &Value::Null));
    assert!(!deep_equals(&Value::Null, &json!("null")));
}

#[test]
fn deep_equals_arrays() {
    assert!(deep_equals(&json!([]), &json!([])));
    assert!(deep_equals(&json!([1, 2, 3]), &json!([1, 2, 3])));
    assert!(!deep_equals(&json!([1, 2, 3]), &json!([1, 2, 4])));
    assert!(!deep_equals(&json!([1, 2, 3]), &json!([1, 2])));
}

#[test]
fn deep_equals_nested_arrays() {
    assert!(deep_equals(
        &json!([[1, 2], [3, 4]]),
        &json!([[1, 2], [3, 4]])
    ));
    assert!(!deep_equals(
        &json!([[1, 2], [3, 4]]),
        &json!([[1, 2], [3, 5]])
    ));
}

#[test]
fn deep_equals_objects() {
    assert!(deep_equals(&json!({}), &json!({})));
    assert!(deep_equals(
        &json!({"a": 1, "b": 2}),
        &json!({"a": 1, "b": 2})
    ));
    assert!(!deep_equals(
        &json!({"a": 1, "b": 2}),
        &json!({"a": 1, "b": 3})
    ));
}

#[test]
fn deep_equals_missing_keys() {
    assert!(!deep_equals(&json!({"a": 1}), &json!({"a": 1, "b": 2})));
    assert!(!deep_equals(&json!({"a": 1, "b": 2}), &json!({"a": 1})));
}

#[test]
fn deep_equals_nested_objects() {
    assert!(deep_equals(
        &json!({"a": {"b": {"c": 1}}}),
        &json!({"a": {"b": {"c": 1}}})
    ));
    assert!(!deep_equals(
        &json!({"a": {"b": {"c": 1}}}),
        &json!({"a": {"b": {"c": 2}}})
    ));
}

// ============================================================================
// is_operator
// ============================================================================

#[test]
fn is_operator_detects_operator_objects() {
    assert!(is_operator(&json!({"$eq": 5})));
    assert!(is_operator(&json!({"$gte": 20, "$lte": 30})));
    assert!(!is_operator(&json!({"name": "Alice"})));
    assert!(!is_operator(&json!({}))); // empty — not an operator
    assert!(!is_operator(&json!("string")));
    assert!(!is_operator(&json!(42)));
    assert!(!is_operator(&json!(null)));
}

// ============================================================================
// get_field_value
// ============================================================================

#[test]
fn get_field_value_top_level() {
    let record = json!({"name": "Alice"});
    assert_eq!(get_field_value(&record, "name"), Some(&json!("Alice")));
}

#[test]
fn get_field_value_nested_dot_notation() {
    let record = json!({"user": {"name": "Alice"}});
    assert_eq!(get_field_value(&record, "user.name"), Some(&json!("Alice")));
}

#[test]
fn get_field_value_deeply_nested() {
    let record = json!({"a": {"b": {"c": {"d": 42}}}});
    assert_eq!(get_field_value(&record, "a.b.c.d"), Some(&json!(42)));
}

#[test]
fn get_field_value_missing_field() {
    let record = json!({"name": "Alice"});
    assert_eq!(get_field_value(&record, "age"), None);
}

#[test]
fn get_field_value_missing_nested() {
    assert_eq!(get_field_value(&json!({"user": {}}), "user.name"), None);
    assert_eq!(get_field_value(&json!({"user": null}), "user.name"), None);
}

#[test]
fn get_field_value_null_record() {
    assert_eq!(get_field_value(&Value::Null, "name"), None);
}

// ============================================================================
// matches_filter — basic operators
// ============================================================================

fn alice() -> Value {
    json!({
        "id": "1",
        "name": "Alice",
        "age": 30,
        "active": true,
        "tags": ["admin", "verified"],
        "address": {"city": "Portland", "zip": "97201"}
    })
}

#[test]
fn matches_filter_implicit_eq_string() {
    assert!(matches_filter(&alice(), &json!({"name": "Alice"})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"name": "Bob"})).unwrap());
}

#[test]
fn matches_filter_implicit_eq_number() {
    assert!(matches_filter(&alice(), &json!({"age": 30})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": 31})).unwrap());
}

#[test]
fn matches_filter_implicit_eq_bool() {
    assert!(matches_filter(&alice(), &json!({"active": true})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"active": false})).unwrap());
}

#[test]
fn matches_filter_eq_explicit() {
    assert!(matches_filter(&alice(), &json!({"name": {"$eq": "Alice"}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"name": {"$eq": "Bob"}})).unwrap());
}

#[test]
fn matches_filter_ne() {
    assert!(matches_filter(&alice(), &json!({"name": {"$ne": "Bob"}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"name": {"$ne": "Alice"}})).unwrap());
}

#[test]
fn matches_filter_gt() {
    assert!(matches_filter(&alice(), &json!({"age": {"$gt": 25}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": {"$gt": 30}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": {"$gt": 35}})).unwrap());
}

#[test]
fn matches_filter_gte() {
    assert!(matches_filter(&alice(), &json!({"age": {"$gte": 25}})).unwrap());
    assert!(matches_filter(&alice(), &json!({"age": {"$gte": 30}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": {"$gte": 35}})).unwrap());
}

#[test]
fn matches_filter_lt() {
    assert!(matches_filter(&alice(), &json!({"age": {"$lt": 35}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": {"$lt": 30}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": {"$lt": 25}})).unwrap());
}

#[test]
fn matches_filter_lte() {
    assert!(matches_filter(&alice(), &json!({"age": {"$lte": 35}})).unwrap());
    assert!(matches_filter(&alice(), &json!({"age": {"$lte": 30}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": {"$lte": 25}})).unwrap());
}

#[test]
fn matches_filter_in() {
    assert!(matches_filter(&alice(), &json!({"age": {"$in": [25, 30, 35]}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": {"$in": [25, 35, 40]}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": {"$in": []}})).unwrap());
}

#[test]
fn matches_filter_nin() {
    assert!(matches_filter(&alice(), &json!({"age": {"$nin": [25, 35, 40]}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"age": {"$nin": [25, 30, 35]}})).unwrap());
    assert!(matches_filter(&alice(), &json!({"age": {"$nin": []}})).unwrap());
}

#[test]
fn matches_filter_contains() {
    assert!(matches_filter(&alice(), &json!({"tags": {"$contains": "admin"}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"tags": {"$contains": "guest"}})).unwrap());
    // Non-array field returns false
    assert!(!matches_filter(&alice(), &json!({"name": {"$contains": "A"}})).unwrap());
}

#[test]
fn matches_filter_contains_any() {
    assert!(matches_filter(
        &alice(),
        &json!({"tags": {"$containsAny": ["admin", "guest"]}})
    )
    .unwrap());
    assert!(!matches_filter(
        &alice(),
        &json!({"tags": {"$containsAny": ["guest", "banned"]}})
    )
    .unwrap());
    // Empty search array → false
    assert!(!matches_filter(&alice(), &json!({"tags": {"$containsAny": []}})).unwrap());
}

#[test]
fn matches_filter_multiple_fields_implicit_and() {
    assert!(matches_filter(&alice(), &json!({"name": "Alice", "age": 30})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"name": "Alice", "age": 25})).unwrap());
}

#[test]
fn matches_filter_and() {
    assert!(matches_filter(
        &alice(),
        &json!({"$and": [{"name": "Alice"}, {"age": {"$gte": 25}}]})
    )
    .unwrap());
    assert!(!matches_filter(
        &alice(),
        &json!({"$and": [{"name": "Alice"}, {"age": {"$gte": 35}}]})
    )
    .unwrap());
}

#[test]
fn matches_filter_or() {
    assert!(matches_filter(&alice(), &json!({"$or": [{"name": "Bob"}, {"age": 30}]})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"$or": [{"name": "Bob"}, {"age": 25}]})).unwrap());
}

#[test]
fn matches_filter_not() {
    assert!(matches_filter(&alice(), &json!({"$not": {"name": "Bob"}})).unwrap());
    assert!(!matches_filter(&alice(), &json!({"$not": {"name": "Alice"}})).unwrap());
    // Complex condition
    assert!(matches_filter(&alice(), &json!({"$not": {"age": {"$lt": 25}}})).unwrap());
}

#[test]
fn matches_filter_nested_logical_operators() {
    // (name = "Alice" AND age >= 25) OR active = false
    assert!(matches_filter(
        &alice(),
        &json!({"$or": [{"$and": [{"name": "Alice"}, {"age": {"$gte": 25}}]}, {"active": false}]})
    )
    .unwrap());

    // (name = "Bob" AND age >= 25) OR active = false
    assert!(!matches_filter(
        &alice(),
        &json!({"$or": [{"$and": [{"name": "Bob"}, {"age": {"$gte": 25}}]}, {"active": false}]})
    )
    .unwrap());
}

#[test]
fn matches_filter_combines_or_with_field_conditions() {
    let user = json!({"name": "Alice", "age": 30, "active": true});
    assert!(matches_filter(
        &user,
        &json!({"$or": [{"age": 25}, {"age": 30}], "name": "Alice"})
    )
    .unwrap());
    assert!(!matches_filter(
        &user,
        &json!({"$or": [{"age": 25}, {"age": 30}], "name": "Bob"})
    )
    .unwrap());
    assert!(!matches_filter(
        &user,
        &json!({"$or": [{"age": 25}, {"age": 35}], "name": "Alice"})
    )
    .unwrap());
}

#[test]
fn matches_filter_combines_and_with_field_conditions() {
    let user = json!({"name": "Alice", "age": 30, "active": true});
    assert!(matches_filter(
        &user,
        &json!({"$and": [{"age": {"$gte": 25}}, {"age": {"$lte": 35}}], "active": true})
    )
    .unwrap());
    assert!(!matches_filter(
        &user,
        &json!({"$and": [{"age": {"$gte": 25}}, {"age": {"$lte": 35}}], "active": false})
    )
    .unwrap());
}

#[test]
fn matches_filter_and_empty_array_vacuous_true() {
    // $and: [] iterates zero sub-filters — vacuous truth, always passes.
    // Consistent with MongoDB: an empty conjunction is trivially satisfied.
    assert!(matches_filter(&alice(), &json!({"$and": []})).unwrap());
}

#[test]
fn matches_filter_or_empty_array_vacuous_false() {
    // $or: [] has no passing sub-filter — vacuous false, always fails.
    // Consistent with MongoDB: an empty disjunction is trivially unsatisfied.
    assert!(!matches_filter(&alice(), &json!({"$or": []})).unwrap());
}

#[test]
fn matches_filter_unknown_operator_returns_err() {
    let user = json!({"name": "Alice", "age": 30});
    let result = matches_filter(&user, &json!({"name": {"$eqq": "Alice"}}));
    assert!(result.is_err());
    match result.unwrap_err() {
        LessDbError::Query(QueryError::UnknownOperator(op)) => {
            assert_eq!(op, "$eqq");
        }
        e => panic!("Expected UnknownOperator, got: {:?}", e),
    }
}

#[test]
fn matches_filter_unknown_operator_typo() {
    let user = json!({"age": 30});
    let result = matches_filter(&user, &json!({"age": {"$greaterThan": 25}}));
    assert!(result.is_err());
}

// ============================================================================
// null/undefined edge cases
// ============================================================================

#[test]
fn matches_filter_null_field_with_null_value() {
    let record = json!({"name": null, "age": 30});
    assert!(matches_filter(&record, &json!({"name": null})).unwrap());
    assert!(!matches_filter(&record, &json!({"name": "Alice"})).unwrap());
}

#[test]
fn matches_filter_eq_null() {
    let record = json!({"name": null});
    assert!(matches_filter(&record, &json!({"name": {"$eq": null}})).unwrap());
    assert!(!matches_filter(&record, &json!({"name": {"$ne": null}})).unwrap());
}

#[test]
fn matches_filter_comparison_with_null_values() {
    let record = json!({"value": null});
    // MongoDB: comparisons with null return false
    assert!(!matches_filter(&record, &json!({"value": {"$gt": 10}})).unwrap());
    assert!(!matches_filter(&record, &json!({"value": {"$lt": 10}})).unwrap());
    assert!(!matches_filter(&record, &json!({"value": {"$gte": 10}})).unwrap());
    assert!(!matches_filter(&record, &json!({"value": {"$lte": 10}})).unwrap());
    // SQL-style null propagation
    assert!(!matches_filter(&record, &json!({"value": {"$gte": null}})).unwrap());
    assert!(!matches_filter(&record, &json!({"value": {"$lte": null}})).unwrap());
}

#[test]
fn matches_filter_gte_lte_null_on_missing_field_consistent() {
    let record = json!({"name": "Alice"});
    // In Rust JSON, absent field is treated as null (no undefined type).
    // $gte/$lte/$gt/$lt: null return false due to SQL-style null propagation.
    // (In JS, $eq: null would also return false for undefined, but in Rust
    // absent fields are treated as null, so $eq: null matches absent fields.)
    assert!(!matches_filter(&record, &json!({"age": {"$gte": null}})).unwrap());
    assert!(!matches_filter(&record, &json!({"age": {"$lte": null}})).unwrap());
    assert!(!matches_filter(&record, &json!({"age": {"$gt": null}})).unwrap());
    assert!(!matches_filter(&record, &json!({"age": {"$lt": null}})).unwrap());
}

#[test]
fn matches_filter_in_with_null() {
    let record = json!({"value": null});
    assert!(matches_filter(&record, &json!({"value": {"$in": [null, 1, 2]}})).unwrap());
    assert!(!matches_filter(&record, &json!({"value": {"$in": [1, 2, 3]}})).unwrap());
}

#[test]
fn matches_filter_nin_with_null() {
    let record = json!({"value": null});
    assert!(matches_filter(&record, &json!({"value": {"$nin": [1, 2, 3]}})).unwrap());
    assert!(!matches_filter(&record, &json!({"value": {"$nin": [null, 1, 2]}})).unwrap());
}

// ============================================================================
// $in/$nin on array fields (MongoDB behavior)
// ============================================================================

#[test]
fn matches_filter_in_on_array_field() {
    let user = json!({"tags": ["admin", "verified", "active"]});
    // ANY element in tags matches the $in list
    assert!(matches_filter(&user, &json!({"tags": {"$in": ["admin", "guest"]}})).unwrap());
    assert!(matches_filter(&user, &json!({"tags": {"$in": ["verified"]}})).unwrap());
    assert!(!matches_filter(&user, &json!({"tags": {"$in": ["guest", "banned"]}})).unwrap());
}

#[test]
fn matches_filter_nin_on_array_field() {
    let user = json!({"tags": ["admin", "verified", "active"]});
    // NO element in tags is in the $nin list
    assert!(matches_filter(&user, &json!({"tags": {"$nin": ["guest", "banned"]}})).unwrap());
    assert!(!matches_filter(&user, &json!({"tags": {"$nin": ["admin", "guest"]}})).unwrap());
}

#[test]
fn matches_filter_in_empty_operand_on_array() {
    let user = json!({"tags": ["admin"]});
    assert!(!matches_filter(&user, &json!({"tags": {"$in": []}})).unwrap());
}

#[test]
fn matches_filter_nin_empty_operand_on_array() {
    let user = json!({"tags": ["admin"]});
    assert!(matches_filter(&user, &json!({"tags": {"$nin": []}})).unwrap());
}

// ============================================================================
// Array element lifting
// ============================================================================

#[test]
fn matches_filter_eq_lifts_on_array() {
    let record = json!({"scores": [70, 85, 60]});
    assert!(matches_filter(&record, &json!({"scores": {"$eq": 85}})).unwrap());
    assert!(!matches_filter(&record, &json!({"scores": {"$eq": 99}})).unwrap());
}

#[test]
fn matches_filter_implicit_eq_lifts_on_array() {
    let record = json!({"scores": [70, 85, 60]});
    assert!(matches_filter(&record, &json!({"scores": 85})).unwrap());
    assert!(!matches_filter(&record, &json!({"scores": 99})).unwrap());
}

#[test]
fn matches_filter_ne_all_elements_must_satisfy() {
    let record = json!({"scores": [70, 85, 60]});
    assert!(matches_filter(&record, &json!({"scores": {"$ne": 99}})).unwrap());
    assert!(!matches_filter(&record, &json!({"scores": {"$ne": 85}})).unwrap());
}

#[test]
fn matches_filter_gt_any_element() {
    let record = json!({"scores": [70, 85, 60]});
    assert!(matches_filter(&record, &json!({"scores": {"$gt": 80}})).unwrap()); // 85 > 80
    assert!(!matches_filter(&record, &json!({"scores": {"$gt": 90}})).unwrap());
}

#[test]
fn matches_filter_gte_any_element() {
    let record = json!({"scores": [70, 85, 60]});
    assert!(matches_filter(&record, &json!({"scores": {"$gte": 85}})).unwrap());
    assert!(!matches_filter(&record, &json!({"scores": {"$gte": 86}})).unwrap());
}

#[test]
fn matches_filter_lt_any_element() {
    let record = json!({"scores": [70, 85, 60]});
    assert!(matches_filter(&record, &json!({"scores": {"$lt": 65}})).unwrap()); // 60 < 65
    assert!(!matches_filter(&record, &json!({"scores": {"$lt": 60}})).unwrap());
}

#[test]
fn matches_filter_lte_any_element() {
    let record = json!({"scores": [70, 85, 60]});
    assert!(matches_filter(&record, &json!({"scores": {"$lte": 60}})).unwrap());
    assert!(!matches_filter(&record, &json!({"scores": {"$lte": 59}})).unwrap());
}

#[test]
fn matches_filter_empty_array_no_element_satisfies() {
    assert!(!matches_filter(&json!({"scores": []}), &json!({"scores": {"$gt": 0}})).unwrap());
    assert!(!matches_filter(&json!({"scores": []}), &json!({"scores": {"$eq": 0}})).unwrap());
}

#[test]
fn matches_filter_ne_empty_array_true() {
    assert!(matches_filter(&json!({"scores": []}), &json!({"scores": {"$ne": 0}})).unwrap());
}

#[test]
fn matches_filter_compound_range_array_lifts_independently() {
    // $gte and $lte are evaluated independently with array-element lifting
    // 50 satisfies $lte: 90, and 95 satisfies $gte: 60 — different elements
    assert!(matches_filter(
        &json!({"scores": [50, 95]}),
        &json!({"scores": {"$gte": 60, "$lte": 90}})
    )
    .unwrap());
    // Single element satisfies both
    assert!(matches_filter(
        &json!({"scores": [75]}),
        &json!({"scores": {"$gte": 60, "$lte": 90}})
    )
    .unwrap());
    // No element satisfies $gte: 60
    assert!(!matches_filter(
        &json!({"scores": [10, 20]}),
        &json!({"scores": {"$gte": 60, "$lte": 90}})
    )
    .unwrap());
}

#[test]
fn matches_filter_ne_combined_with_gte_on_array() {
    // $ne uses all() (ALL must not be 85), $gte uses any() (ANY >= 60)
    assert!(matches_filter(
        &json!({"scores": [70, 90]}),
        &json!({"scores": {"$ne": 85, "$gte": 60}})
    )
    .unwrap());
    assert!(!matches_filter(
        &json!({"scores": [70, 85]}),
        &json!({"scores": {"$ne": 85, "$gte": 60}})
    )
    .unwrap());
    assert!(!matches_filter(
        &json!({"scores": [10, 20]}),
        &json!({"scores": {"$ne": 85, "$gte": 60}})
    )
    .unwrap());
}

// ============================================================================
// Compound operators on same field
// ============================================================================

#[test]
fn matches_filter_range_gte_lte() {
    let user = json!({"age": 30});
    assert!(matches_filter(&user, &json!({"age": {"$gte": 25, "$lte": 35}})).unwrap());
    assert!(!matches_filter(&user, &json!({"age": {"$gte": 25, "$lte": 29}})).unwrap());
    assert!(!matches_filter(&user, &json!({"age": {"$gte": 31, "$lte": 35}})).unwrap());
}

#[test]
fn matches_filter_range_gt_lt() {
    let user = json!({"age": 30});
    assert!(matches_filter(&user, &json!({"age": {"$gt": 25, "$lt": 35}})).unwrap());
    assert!(!matches_filter(&user, &json!({"age": {"$gt": 30, "$lt": 35}})).unwrap());
    assert!(!matches_filter(&user, &json!({"age": {"$gt": 25, "$lt": 30}})).unwrap());
}

#[test]
fn matches_filter_compound_with_contains() {
    let user = json!({"tags": ["admin", "verified", "active"]});
    assert!(matches_filter(
        &user,
        &json!({"tags": {"$contains": "admin", "$containsAny": ["verified", "guest"]}})
    )
    .unwrap());
    assert!(!matches_filter(
        &user,
        &json!({"tags": {"$contains": "admin", "$containsAny": ["guest", "banned"]}})
    )
    .unwrap());
}

// ============================================================================
// $exists operator
// ============================================================================

#[test]
fn exists_matches_defined_field() {
    assert!(matches_filter(
        &json!({"name": "Alice", "age": 30}),
        &json!({"age": {"$exists": true}})
    )
    .unwrap());
}

#[test]
fn exists_does_not_match_undefined_field() {
    assert!(!matches_filter(
        &json!({"name": "Alice"}),
        &json!({"age": {"$exists": true}})
    )
    .unwrap());
}

#[test]
fn exists_false_matches_missing_field() {
    assert!(matches_filter(
        &json!({"name": "Alice"}),
        &json!({"age": {"$exists": false}})
    )
    .unwrap());
}

#[test]
fn exists_false_does_not_match_defined_field() {
    assert!(!matches_filter(
        &json!({"name": "Alice", "age": 30}),
        &json!({"age": {"$exists": false}})
    )
    .unwrap());
}

#[test]
fn exists_true_matches_null_field() {
    // Field exists even if null
    assert!(matches_filter(&json!({"name": null}), &json!({"name": {"$exists": true}})).unwrap());
}

#[test]
fn exists_false_does_not_match_null_field() {
    assert!(!matches_filter(&json!({"name": null}), &json!({"name": {"$exists": false}})).unwrap());
}

#[test]
fn exists_with_nested_paths() {
    assert!(matches_filter(
        &json!({"user": {"name": "Alice"}}),
        &json!({"user.name": {"$exists": true}})
    )
    .unwrap());
    assert!(!matches_filter(
        &json!({"user": {}}),
        &json!({"user.name": {"$exists": true}})
    )
    .unwrap());
}

// ============================================================================
// $regex operator
// ============================================================================

#[test]
fn regex_matches_basic_pattern() {
    assert!(matches_filter(
        &json!({"name": "Alice"}),
        &json!({"name": {"$regex": "Ali"}})
    )
    .unwrap());
}

#[test]
fn regex_does_not_match_missing_pattern() {
    assert!(!matches_filter(
        &json!({"name": "Alice"}),
        &json!({"name": {"$regex": "Bob"}})
    )
    .unwrap());
}

#[test]
fn regex_case_sensitive_by_default() {
    assert!(!matches_filter(
        &json!({"name": "Alice"}),
        &json!({"name": {"$regex": "alice"}})
    )
    .unwrap());
    assert!(matches_filter(
        &json!({"name": "Alice"}),
        &json!({"name": {"$regex": "Alice"}})
    )
    .unwrap());
}

#[test]
fn regex_returns_false_for_null() {
    assert!(!matches_filter(&json!({"name": null}), &json!({"name": {"$regex": "test"}})).unwrap());
}

#[test]
fn regex_returns_false_for_missing_field() {
    assert!(!matches_filter(&json!({}), &json!({"name": {"$regex": "test"}})).unwrap());
}

#[test]
fn regex_invalid_pattern_returns_error() {
    let result = matches_filter(
        &json!({"name": "Alice"}),
        &json!({"name": {"$regex": "[invalid"}}),
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        LessDbError::Query(QueryError::InvalidRegex(_)) => {}
        e => panic!("Expected InvalidRegex, got: {:?}", e),
    }
}

#[test]
fn regex_returns_false_for_non_string_value() {
    assert!(!matches_filter(&json!({"count": 42}), &json!({"count": {"$regex": "42"}})).unwrap());
    assert!(!matches_filter(
        &json!({"active": true}),
        &json!({"active": {"$regex": "true"}})
    )
    .unwrap());
}

// ============================================================================
// $size operator
// ============================================================================

#[test]
fn size_matches_exact_length() {
    assert!(matches_filter(&json!({"tags": ["a", "b"]}), &json!({"tags": {"$size": 2}})).unwrap());
    assert!(!matches_filter(&json!({"tags": ["a", "b"]}), &json!({"tags": {"$size": 3}})).unwrap());
}

#[test]
fn size_matches_empty_array() {
    assert!(matches_filter(&json!({"tags": []}), &json!({"tags": {"$size": 0}})).unwrap());
}

#[test]
fn size_returns_false_for_non_array() {
    assert!(!matches_filter(&json!({"name": "Alice"}), &json!({"name": {"$size": 5}})).unwrap());
}

#[test]
fn size_returns_false_for_null() {
    assert!(!matches_filter(&json!({"tags": null}), &json!({"tags": {"$size": 0}})).unwrap());
    assert!(!matches_filter(&json!({}), &json!({"tags": {"$size": 0}})).unwrap());
}

// ============================================================================
// $all operator
// ============================================================================

#[test]
fn all_matches_all_present() {
    assert!(matches_filter(
        &json!({"tags": ["a", "b", "c"]}),
        &json!({"tags": {"$all": ["a", "b"]}})
    )
    .unwrap());
}

#[test]
fn all_fails_when_some_missing() {
    assert!(!matches_filter(
        &json!({"tags": ["a", "b"]}),
        &json!({"tags": {"$all": ["a", "c"]}})
    )
    .unwrap());
}

#[test]
fn all_empty_operand_vacuous_truth() {
    assert!(matches_filter(&json!({"tags": ["a"]}), &json!({"tags": {"$all": []}})).unwrap());
    assert!(matches_filter(&json!({"tags": []}), &json!({"tags": {"$all": []}})).unwrap());
}

#[test]
fn all_returns_false_for_non_array() {
    assert!(!matches_filter(&json!({"name": "Alice"}), &json!({"name": {"$all": ["A"]}})).unwrap());
}

#[test]
fn all_uses_deep_equality_for_objects() {
    let record = json!({"items": [{"id": 1}, {"id": 2}, {"id": 3}]});
    assert!(matches_filter(&record, &json!({"items": {"$all": [{"id": 1}, {"id": 3}]}})).unwrap());
    assert!(!matches_filter(&record, &json!({"items": {"$all": [{"id": 1}, {"id": 4}]}})).unwrap());
}

// ============================================================================
// filter_records
// ============================================================================

fn users() -> Vec<Value> {
    vec![
        json!({"id": "1", "name": "Alice", "age": 30, "active": true}),
        json!({"id": "2", "name": "Bob", "age": 25, "active": true}),
        json!({"id": "3", "name": "Charlie", "age": 35, "active": false}),
        json!({"id": "4", "name": "Diana", "age": 28, "active": true}),
    ]
}

#[test]
fn filter_records_exact_match() {
    let result = filter_records(&users(), &json!({"name": "Alice"})).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0]["name"], "Alice");
}

#[test]
fn filter_records_comparison() {
    let result = filter_records(&users(), &json!({"age": {"$gte": 30}})).unwrap();
    assert_eq!(result.len(), 2);
    let names: Vec<&str> = result.iter().map(|u| u["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"Alice"));
    assert!(names.contains(&"Charlie"));
}

#[test]
fn filter_records_multiple_conditions() {
    let result = filter_records(&users(), &json!({"age": {"$lt": 30}, "active": true})).unwrap();
    assert_eq!(result.len(), 2);
    let names: Vec<&str> = result.iter().map(|u| u["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"Bob"));
    assert!(names.contains(&"Diana"));
}

#[test]
fn filter_records_no_matches() {
    let result = filter_records(&users(), &json!({"age": {"$gt": 100}})).unwrap();
    assert_eq!(result.len(), 0);
}

#[test]
fn filter_records_empty_filter_returns_all() {
    let result = filter_records(&users(), &json!({})).unwrap();
    assert_eq!(result.len(), 4);
}

// ============================================================================
// matches_computed_filter
// ============================================================================

fn make_computed(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[test]
fn computed_filter_null_condition_matches_null_value() {
    let computed = make_computed(&[("score", Value::Null)]);
    assert!(
        matches_computed_filter(Some(&computed), &make_computed(&[("score", Value::Null)]))
            .unwrap()
    );
}

#[test]
fn computed_filter_null_condition_fails_non_null_value() {
    let computed = make_computed(&[("score", json!(80))]);
    assert!(
        !matches_computed_filter(Some(&computed), &make_computed(&[("score", Value::Null)]))
            .unwrap()
    );
}

#[test]
fn computed_filter_direct_equality() {
    let computed = make_computed(&[("name", json!("Alice"))]);
    assert!(
        matches_computed_filter(Some(&computed), &make_computed(&[("name", json!("Alice"))]))
            .unwrap()
    );
    assert!(
        !matches_computed_filter(Some(&computed), &make_computed(&[("name", json!("Bob"))]))
            .unwrap()
    );
}

#[test]
fn computed_filter_operator_eq() {
    let computed = make_computed(&[("name", json!("Alice"))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("name", json!({"$eq": "Alice"}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("name", json!({"$eq": "Bob"}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_operator_ne() {
    let computed = make_computed(&[("name", json!("Alice"))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("name", json!({"$ne": "Bob"}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("name", json!({"$ne": "Alice"}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_operator_gt() {
    let computed = make_computed(&[("score", json!(80))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$gt": 70}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$gt": 80}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$gt": null}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_operator_gte() {
    let computed = make_computed(&[("score", json!(80))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$gte": 80}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$gte": 81}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_null_gte_null_returns_false() {
    let computed = make_computed(&[("score", Value::Null)]);
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$gte": null}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$lte": null}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$gt": null}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$lt": null}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_missing_field_gte_null_returns_false() {
    let computed = make_computed(&[]);
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$gte": null}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$lte": null}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_operator_lt() {
    let computed = make_computed(&[("score", json!(80))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$lt": 90}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$lt": 80}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$lt": null}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_operator_lte() {
    let computed = make_computed(&[("score", json!(80))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$lte": 80}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$lte": 79}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_operator_in() {
    let computed = make_computed(&[("status", json!("active"))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("status", json!({"$in": ["active", "pending"]}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("status", json!({"$in": ["closed"]}))])
    )
    .unwrap());
    // Non-array operand → false
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("status", json!({"$in": "active"}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_operator_nin_non_array_returns_true() {
    let computed = make_computed(&[("score", json!(80))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$nin": "not-array"}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_unknown_operator_returns_err() {
    let computed = make_computed(&[("score", json!(80))]);
    let result = matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$unknown": 1}))]),
    );
    assert!(result.is_err());
}

#[test]
fn computed_filter_exists_true() {
    let computed = make_computed(&[("score", json!(80))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$exists": true}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_exists_true_missing_field() {
    let computed = make_computed(&[]);
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$exists": true}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_exists_false_missing_field() {
    let computed = make_computed(&[]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$exists": false}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_regex_matches_string() {
    let computed = make_computed(&[("name", json!("Alice"))]);
    assert!(matches_computed_filter(
        Some(&computed),
        &make_computed(&[("name", json!({"$regex": "Ali"}))])
    )
    .unwrap());
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("name", json!({"$regex": "Bob"}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_regex_false_for_null() {
    let computed = make_computed(&[("name", Value::Null)]);
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("name", json!({"$regex": "test"}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_size_false_for_scalar() {
    let computed = make_computed(&[("score", json!(80))]);
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$size": 1}))])
    )
    .unwrap());
}

#[test]
fn computed_filter_all_false_for_scalar() {
    let computed = make_computed(&[("score", json!(80))]);
    assert!(!matches_computed_filter(
        Some(&computed),
        &make_computed(&[("score", json!({"$all": [80]}))])
    )
    .unwrap());
}
