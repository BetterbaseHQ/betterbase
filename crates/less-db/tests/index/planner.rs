//! Tests for the index query planner — ported from less-db-js/tests/index/planner.test.ts

use less_db::index::planner::{explain_plan, extract_conditions, plan_query};
use less_db::index::types::{
    ComputedIndex, FieldIndex, IndexDefinition, IndexField, IndexScanType, IndexSortOrder,
    IndexableValue,
};
use less_db::query::types::{SortDirection, SortEntry};
use serde_json::json;
use std::sync::Arc;

// ============================================================================
// Test helpers
// ============================================================================

fn field_index(name: &str, fields: &[&str], unique: bool, sparse: bool) -> IndexDefinition {
    IndexDefinition::Field(FieldIndex {
        name: name.to_string(),
        fields: fields
            .iter()
            .map(|f| IndexField {
                field: f.to_string(),
                order: IndexSortOrder::Asc,
            })
            .collect(),
        unique,
        sparse,
    })
}

fn computed_index(
    name: &str,
    compute: impl Fn(&serde_json::Value) -> Option<IndexableValue> + Send + Sync + 'static,
    unique: bool,
    sparse: bool,
) -> IndexDefinition {
    IndexDefinition::Computed(ComputedIndex {
        name: name.to_string(),
        compute: Arc::new(compute),
        unique,
        sparse,
    })
}

fn sort_entry(field: &str, direction: SortDirection) -> SortEntry {
    SortEntry {
        field: field.to_string(),
        direction,
    }
}

// ============================================================================
// extractConditions — condition extraction
// ============================================================================

#[test]
fn extract_equality_conditions() {
    let filter = json!({"status": "active", "email": "test@example.com"});
    let conds = extract_conditions(Some(&filter));
    assert_eq!(
        conds.equalities.get("status"),
        Some(&IndexableValue::String("active".to_string()))
    );
    assert_eq!(
        conds.equalities.get("email"),
        Some(&IndexableValue::String("test@example.com".to_string()))
    );
    assert!(conds.ranges.is_empty());
    assert!(conds.ins.is_empty());
    assert!(conds.residual.is_none());
}

#[test]
fn extract_eq_operator() {
    let filter = json!({"status": {"$eq": "active"}});
    let conds = extract_conditions(Some(&filter));
    assert_eq!(
        conds.equalities.get("status"),
        Some(&IndexableValue::String("active".to_string()))
    );
}

#[test]
fn extract_range_conditions() {
    let filter = json!({"age": {"$gte": 18, "$lt": 65}, "score": {"$gt": 100}});
    let conds = extract_conditions(Some(&filter));
    let age_range = conds.ranges.get("age").unwrap();
    assert!(age_range.0.as_ref().unwrap().inclusive);
    assert_eq!(
        age_range.0.as_ref().unwrap().value,
        IndexableValue::Number(18.0)
    );
    assert!(!age_range.1.as_ref().unwrap().inclusive);
    assert_eq!(
        age_range.1.as_ref().unwrap().value,
        IndexableValue::Number(65.0)
    );

    let score_range = conds.ranges.get("score").unwrap();
    assert!(!score_range.0.as_ref().unwrap().inclusive);
    assert_eq!(
        score_range.0.as_ref().unwrap().value,
        IndexableValue::Number(100.0)
    );
}

#[test]
fn extract_in_conditions() {
    let filter = json!({"status": {"$in": ["active", "pending", "review"]}});
    let conds = extract_conditions(Some(&filter));
    let in_vals = conds.ins.get("status").unwrap();
    assert_eq!(in_vals.len(), 3);
    assert!(in_vals.contains(&IndexableValue::String("active".to_string())));
}

#[test]
fn extract_computed_filter_conditions() {
    let filter = json!({"status": "active", "$computed": {"email_lower": "test@example.com"}});
    let conds = extract_conditions(Some(&filter));
    assert_eq!(
        conds.equalities.get("status"),
        Some(&IndexableValue::String("active".to_string()))
    );
    let computed = conds.computed.get("email_lower").unwrap();
    assert_eq!(
        computed.equality,
        Some(IndexableValue::String("test@example.com".to_string()))
    );
}

#[test]
fn extract_computed_with_range_operators() {
    let filter = json!({"$computed": {"score": {"$gte": 100, "$lt": 200}}});
    let conds = extract_conditions(Some(&filter));
    let computed = conds.computed.get("score").unwrap();
    let (lower, upper) = computed.range.as_ref().unwrap();
    assert!(lower.as_ref().unwrap().inclusive);
    assert_eq!(lower.as_ref().unwrap().value, IndexableValue::Number(100.0));
    assert!(!upper.as_ref().unwrap().inclusive);
    assert_eq!(upper.as_ref().unwrap().value, IndexableValue::Number(200.0));
}

#[test]
fn extract_logical_operators_go_to_residual() {
    let filter = json!({"status": "active", "$or": [{"name": "Alice"}, {"name": "Bob"}]});
    let conds = extract_conditions(Some(&filter));
    assert!(conds.equalities.contains_key("status"));
    let residual = conds.residual.as_ref().unwrap();
    assert!(residual.get("$or").is_some());
}

#[test]
fn extract_ne_and_nin_go_to_residual() {
    let filter = json!({"status": {"$ne": "deleted"}, "role": {"$nin": ["admin", "superuser"]}});
    let conds = extract_conditions(Some(&filter));
    assert!(conds.equalities.is_empty());
    let residual = conds.residual.as_ref().unwrap();
    assert!(residual.get("status").is_some());
    assert!(residual.get("role").is_some());
}

#[test]
fn extract_empty_filter() {
    let conds = extract_conditions(None);
    assert!(conds.equalities.is_empty());
    assert!(conds.ranges.is_empty());
    assert!(conds.ins.is_empty());
    assert!(conds.computed.is_empty());
    assert!(conds.residual.is_none());
}

#[test]
fn extract_boolean_values() {
    let filter = json!({"active": true});
    let conds = extract_conditions(Some(&filter));
    assert_eq!(
        conds.equalities.get("active"),
        Some(&IndexableValue::Bool(true))
    );
}

#[test]
fn extract_numeric_values() {
    let filter = json!({"count": 42});
    let conds = extract_conditions(Some(&filter));
    assert_eq!(
        conds.equalities.get("count"),
        Some(&IndexableValue::Number(42.0))
    );
}

#[test]
fn extract_null_values_to_residual() {
    let filter = json!({"status": null});
    let conds = extract_conditions(Some(&filter));
    assert!(conds.equalities.is_empty());
    // null goes to residual, not dropped
    let residual = conds.residual.as_ref().unwrap();
    assert!(residual.get("status").map(|v| v.is_null()).unwrap_or(false));
}

#[test]
fn extract_mixed_dollar_and_non_dollar_keys_treated_as_direct_value() {
    // An object with both $ and non-$ keys is NOT an operator — goes to residual
    let filter = json!({"field": {"value": 1, "$gt": 5}});
    let conds = extract_conditions(Some(&filter));
    // Should NOT be extracted as equality or range
    assert!(!conds.equalities.contains_key("field"));
    assert!(!conds.ranges.contains_key("field"));
    // Should be in residual
    assert!(conds.residual.is_some());
}

// ============================================================================
// planQuery — index selection
// ============================================================================

#[test]
fn plan_unique_exact_match_best_cost() {
    let indexes = vec![
        field_index("email_unique", &["email"], true, false),
        field_index("status", &["status"], false, false),
    ];
    let filter = json!({"email": "test@example.com"});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert_eq!(plan.scan.as_ref().unwrap().index.name(), "email_unique");
    assert_eq!(plan.scan.as_ref().unwrap().scan_type, IndexScanType::Exact);
    assert_eq!(plan.estimated_cost, 1.0);
}

#[test]
fn plan_compound_index_over_single_field() {
    let indexes = vec![
        field_index("status", &["status"], false, false),
        field_index("status_created", &["status", "createdAt"], false, false),
    ];
    let filter = json!({"status": "active", "createdAt": {"$gte": "2024-01-01"}});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert_eq!(plan.scan.as_ref().unwrap().index.name(), "status_created");
}

#[test]
fn plan_uses_prefix_of_compound_index() {
    let indexes = vec![field_index(
        "status_priority_created",
        &["status", "priority", "createdAt"],
        false,
        false,
    )];
    let filter = json!({"status": "active"});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert_eq!(
        plan.scan.as_ref().unwrap().index.name(),
        "status_priority_created"
    );
    assert_eq!(plan.scan.as_ref().unwrap().scan_type, IndexScanType::Prefix);
}

#[test]
fn plan_cannot_use_index_without_leftmost_prefix() {
    let indexes = vec![field_index(
        "status_created",
        &["status", "createdAt"],
        false,
        false,
    )];
    // Only filtering on createdAt — missing status prefix
    let filter = json!({"createdAt": {"$gte": "2024-01-01"}});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert!(plan.scan.is_none());
    assert_eq!(plan.estimated_cost, 6.0);
}

#[test]
fn plan_full_scan_when_no_indexes() {
    let filter = json!({"status": "active"});
    let plan = plan_query(Some(&filter), None, &[]);
    assert!(plan.scan.is_none());
    assert_eq!(plan.estimated_cost, 6.0);
}

#[test]
fn plan_computed_index_for_computed_filter() {
    let indexes = vec![computed_index(
        "email_lower",
        |doc| {
            doc.get("email")
                .and_then(|v| v.as_str())
                .map(|s| IndexableValue::String(s.to_lowercase()))
        },
        true,
        false,
    )];
    let filter = json!({"$computed": {"email_lower": "test@example.com"}});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert_eq!(plan.scan.as_ref().unwrap().index.name(), "email_lower");
    assert_eq!(plan.scan.as_ref().unwrap().scan_type, IndexScanType::Exact);
}

// ============================================================================
// $in handling
// ============================================================================

#[test]
fn plan_multi_point_lookup_for_small_in() {
    let indexes = vec![field_index("status", &["status"], false, false)];
    let filter = json!({"status": {"$in": ["active", "pending"]}});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert_eq!(plan.scan.as_ref().unwrap().index.name(), "status");
    let in_vals = plan.scan.as_ref().unwrap().in_values.as_ref().unwrap();
    assert!(in_vals.contains(&IndexableValue::String("active".to_string())));
    assert!(in_vals.contains(&IndexableValue::String("pending".to_string())));
}

#[test]
fn plan_equality_prefix_with_in() {
    let indexes = vec![field_index(
        "org_status",
        &["orgId", "status"],
        false,
        false,
    )];
    let filter = json!({"orgId": "org1", "status": {"$in": ["active", "pending"]}});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert_eq!(plan.scan.as_ref().unwrap().index.name(), "org_status");
    let eq_vals = plan
        .scan
        .as_ref()
        .unwrap()
        .equality_values
        .as_ref()
        .unwrap();
    assert_eq!(eq_vals[0], IndexableValue::String("org1".to_string()));
    let in_vals = plan.scan.as_ref().unwrap().in_values.as_ref().unwrap();
    assert_eq!(in_vals.len(), 2);
}

// ============================================================================
// Sort handling
// ============================================================================

#[test]
fn plan_index_provides_sort_when_match() {
    let indexes = vec![field_index(
        "status_created",
        &["status", "createdAt"],
        false,
        false,
    )];
    let filter = json!({"status": "active"});
    let sort = vec![sort_entry("createdAt", SortDirection::Asc)];
    let plan = plan_query(Some(&filter), Some(&sort), &indexes);
    assert!(plan.index_provides_sort, "index should provide sort");
    assert!(
        plan.post_sort.is_none(),
        "post_sort should be None when index provides sort"
    );
}

#[test]
fn plan_sort_only_uses_index_when_sort_matches() {
    // Sort-only query with asc index + asc sort
    let indexes = vec![field_index("age", &["age"], false, false)];
    let sort = vec![sort_entry("age", SortDirection::Asc)];
    let plan = plan_query(None, Some(&sort), &indexes);
    assert!(plan.scan.is_some(), "should use index for sort-only query");
    assert_eq!(plan.scan.as_ref().unwrap().index.name(), "age");
    assert!(plan.index_provides_sort);
    assert!(plan.estimated_cost < 6.0);
}

#[test]
fn plan_no_index_for_sort_when_field_mismatched() {
    let indexes = vec![field_index("status", &["status"], false, false)];
    let sort = vec![sort_entry("age", SortDirection::Asc)];
    let plan = plan_query(None, Some(&sort), &indexes);
    assert!(plan.scan.is_none());
    assert_eq!(plan.estimated_cost, 6.0);
}

// ============================================================================
// Post-filter handling
// ============================================================================

#[test]
fn plan_includes_uncovered_conditions_in_post_filter() {
    let indexes = vec![field_index("status", &["status"], false, false)];
    let filter = json!({"status": "active", "name": "Alice"});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert_eq!(plan.scan.as_ref().unwrap().index.name(), "status");
    let post = plan.post_filter.as_ref().unwrap();
    assert_eq!(post.get("name"), Some(&json!("Alice")));
}

#[test]
fn plan_logical_operators_in_post_filter() {
    let indexes = vec![field_index("status", &["status"], false, false)];
    let filter = json!({"status": "active", "$or": [{"name": "Alice"}, {"name": "Bob"}]});
    let plan = plan_query(Some(&filter), None, &indexes);
    let post = plan.post_filter.as_ref().unwrap();
    assert!(post.get("$or").is_some());
}

#[test]
fn plan_null_post_filter_when_all_conditions_covered() {
    let indexes = vec![field_index("status", &["status"], false, false)];
    let filter = json!({"status": "active"});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert!(plan.post_filter.is_none());
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn plan_multiple_indexes_picks_best() {
    let indexes = vec![
        field_index("status", &["status"], false, false),
        field_index("email_unique", &["email"], true, false),
        field_index("status_email", &["status", "email"], false, false),
    ];
    // Both status and email in filter — unique email index should win
    let filter = json!({"status": "active", "email": "test@example.com"});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert_eq!(plan.scan.as_ref().unwrap().index.name(), "email_unique");
    assert_eq!(plan.estimated_cost, 1.0);
}

// ============================================================================
// Regression: null filter values preserved in residual
// ============================================================================

#[test]
fn extract_null_filter_value_in_residual_not_dropped() {
    let filter = json!({"status": null, "email": "test@example.com"});
    let conds = extract_conditions(Some(&filter));
    // email should be extracted
    assert_eq!(
        conds.equalities.get("email"),
        Some(&IndexableValue::String("test@example.com".to_string()))
    );
    // status: null should be in residual, not dropped
    let residual = conds.residual.as_ref().unwrap();
    assert!(residual.get("status").map(|v| v.is_null()).unwrap_or(false));
}

#[test]
fn plan_null_condition_survives_into_post_filter() {
    let indexes = vec![field_index("idx_email", &["email"], false, false)];
    let filter = json!({"status": null, "email": "test@example.com"});
    let plan = plan_query(Some(&filter), None, &indexes);
    assert_eq!(plan.scan.as_ref().unwrap().index.name(), "idx_email");
    let post = plan.post_filter.as_ref().unwrap();
    assert!(post.get("status").map(|v| v.is_null()).unwrap_or(false));
}

// ============================================================================
// explainPlan
// ============================================================================

#[test]
fn explain_full_scan() {
    let plan = plan_query(Some(&json!({"status": "active"})), None, &[]);
    let output = explain_plan(&plan);
    assert!(output.contains("Full table scan"), "output: {output}");
    assert!(output.contains("Estimated cost: 6/6"), "output: {output}");
}

#[test]
fn explain_index_scan() {
    let indexes = vec![field_index("status", &["status"], false, false)];
    let plan = plan_query(Some(&json!({"status": "active"})), None, &indexes);
    let output = explain_plan(&plan);
    assert!(output.contains("Index: status"), "output: {output}");
    assert!(output.contains("Scan type: exact"), "output: {output}");
    assert!(
        output.contains(r#"Equality values: "active""#),
        "output: {output}"
    );
}

#[test]
fn explain_range_scan() {
    let indexes = vec![field_index("age", &["age"], false, false)];
    let plan = plan_query(
        Some(&json!({"age": {"$gte": 18, "$lt": 65}})),
        None,
        &indexes,
    );
    let output = explain_plan(&plan);
    assert!(output.contains("Scan type: range"), "output: {output}");
    assert!(output.contains("Range: >= 18 AND < 65"), "output: {output}");
}

#[test]
fn explain_in_values() {
    let indexes = vec![field_index("idx_status", &["status"], false, false)];
    let plan = plan_query(
        Some(&json!({"status": {"$in": ["active", "pending"]}})),
        None,
        &indexes,
    );
    let output = explain_plan(&plan);
    assert!(output.contains("IN values:"), "output: {output}");
    assert!(output.contains(r#""active""#), "output: {output}");
    assert!(output.contains(r#""pending""#), "output: {output}");
}

#[test]
fn explain_date_strings_in_equality() {
    let indexes = vec![field_index("idx_createdAt", &["createdAt"], false, false)];
    let plan = plan_query(
        Some(&json!({"createdAt": "2024-06-15T00:00:00.000Z"})),
        None,
        &indexes,
    );
    let output = explain_plan(&plan);
    assert!(
        output.contains("2024-06-15T00:00:00.000Z"),
        "output: {output}"
    );
}

#[test]
fn explain_date_strings_in_range_bounds() {
    let indexes = vec![field_index("idx_createdAt", &["createdAt"], false, false)];
    let plan = plan_query(
        Some(
            &json!({"createdAt": {"$gte": "2024-01-01T00:00:00.000Z", "$lte": "2024-12-31T23:59:59.999Z"}}),
        ),
        None,
        &indexes,
    );
    let output = explain_plan(&plan);
    assert!(output.contains("Range:"), "output: {output}");
    assert!(
        output.contains("2024-01-01T00:00:00.000Z"),
        "output: {output}"
    );
    assert!(
        output.contains("2024-12-31T23:59:59.999Z"),
        "output: {output}"
    );
}

#[test]
fn explain_shows_post_filter_yes() {
    let indexes = vec![field_index("status", &["status"], false, false)];
    let plan = plan_query(
        Some(&json!({"status": "active", "age": {"$gt": 20}})),
        None,
        &indexes,
    );
    let output = explain_plan(&plan);
    assert!(output.contains("Post-filter: yes"), "output: {output}");
}

#[test]
fn explain_shows_index_provides_sort_yes() {
    let indexes = vec![field_index("status", &["status"], false, false)];
    let plan = plan_query(
        Some(&json!({})),
        Some(&[sort_entry("status", SortDirection::Asc)]),
        &indexes,
    );
    let output = explain_plan(&plan);
    assert!(
        output.contains("Index provides sort: yes"),
        "output: {output}"
    );
}

// ============================================================================
// $in edge cases
// ============================================================================

#[test]
fn extract_in_over_limit_goes_to_residual() {
    // $in with 21 values exceeds MAX_IN_VALUES (20) → residual
    let values: Vec<serde_json::Value> = (0..21).map(|i| json!(format!("v{i}"))).collect();
    let filter = json!({"status": {"$in": values}});
    let conds = extract_conditions(Some(&filter));
    assert!(
        conds.ins.is_empty(),
        "over-limit $in should not be extracted"
    );
    assert!(
        conds.residual.is_some(),
        "over-limit $in should go to residual"
    );
}

#[test]
fn extract_in_with_non_indexable_element_goes_to_residual() {
    // $in with an array element (non-indexable) → whole list to residual
    let filter = json!({"status": {"$in": ["active", [1, 2]]}});
    let conds = extract_conditions(Some(&filter));
    assert!(
        conds.ins.is_empty(),
        "non-indexable element should drop entire $in"
    );
    assert!(conds.residual.is_some());
}

#[test]
fn extract_in_empty_array_goes_to_residual() {
    let filter = json!({"status": {"$in": []}});
    let conds = extract_conditions(Some(&filter));
    assert!(conds.ins.is_empty(), "empty $in should not be extracted");
}

// ============================================================================
// $lte (inclusive upper bound) and $lt-only
// ============================================================================

#[test]
fn extract_lte_condition() {
    let filter = json!({"age": {"$lte": 50}});
    let conds = extract_conditions(Some(&filter));
    let range = conds.ranges.get("age").expect("age range should exist");
    let upper = range.1.as_ref().expect("upper bound should exist");
    assert!(upper.inclusive, "$lte should be inclusive");
    assert!(range.0.is_none(), "no lower bound");
}

#[test]
fn extract_lt_only_condition() {
    let filter = json!({"age": {"$lt": 100}});
    let conds = extract_conditions(Some(&filter));
    let range = conds.ranges.get("age").expect("age range should exist");
    let upper = range.1.as_ref().expect("upper bound should exist");
    assert!(!upper.inclusive, "$lt should be exclusive");
    assert!(range.0.is_none(), "no lower bound");
}

// ============================================================================
// Sort direction mismatch
// ============================================================================

#[test]
fn plan_no_index_for_sort_when_direction_mismatches() {
    // Index is ASC, query asks DESC → index cannot provide sort
    let indexes = vec![field_index("status", &["status"], false, false)];
    let plan = plan_query(
        Some(&json!({})),
        Some(&[sort_entry("status", SortDirection::Desc)]),
        &indexes,
    );
    // Index should NOT provide sort since direction mismatches
    assert!(
        !plan.index_provides_sort,
        "ASC index should not provide DESC sort"
    );
}

// ============================================================================
// Compound index with two equalities + sort
// ============================================================================

#[test]
fn plan_compound_two_equalities_with_sort() {
    let indexes = vec![IndexDefinition::Field(FieldIndex {
        name: "compound".to_string(),
        fields: vec![
            IndexField {
                field: "status".to_string(),
                order: IndexSortOrder::Asc,
            },
            IndexField {
                field: "category".to_string(),
                order: IndexSortOrder::Asc,
            },
            IndexField {
                field: "createdAt".to_string(),
                order: IndexSortOrder::Asc,
            },
        ],
        unique: false,
        sparse: false,
    })];

    let plan = plan_query(
        Some(&json!({"status": "active", "category": "tech"})),
        Some(&[sort_entry("createdAt", SortDirection::Asc)]),
        &indexes,
    );

    assert!(plan.scan.is_some(), "compound index should be selected");
    assert!(
        plan.index_provides_sort,
        "compound index should provide sort after equality prefix"
    );
}

// ============================================================================
// $in over-limit falls back to full scan in plan_query
// ============================================================================

#[test]
fn plan_in_over_limit_falls_back_to_full_scan() {
    let indexes = vec![field_index("status", &["status"], false, false)];
    let values: Vec<serde_json::Value> = (0..21).map(|i| json!(format!("v{i}"))).collect();
    let plan = plan_query(Some(&json!({"status": {"$in": values}})), None, &indexes);
    // Over-limit $in goes to residual, so index can't help → no index scan
    assert!(plan.scan.is_none(), "should fall back to full scan");
    assert!(
        plan.post_filter.is_some(),
        "should have post-filter for residual $in"
    );
}
