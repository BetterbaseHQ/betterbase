//! Tests for query execute — ported from less-db-js/tests/query/execute.test.ts

use less_db::query::execute::{
    count_matching, execute_query, find_first, paginate_records, sort_records,
};
use less_db::query::types::{
    normalize_computed_filter, normalize_sort, Query, SortDirection, SortEntry, SortInput,
};
use serde_json::{json, Value};

fn users() -> Vec<Value> {
    vec![
        json!({"id": "1", "name": "Alice", "age": 30, "score": 85, "active": true, "createdAt": "2024-01-15"}),
        json!({"id": "2", "name": "Bob",   "age": 25, "score": 90, "active": true, "createdAt": "2024-02-20"}),
        json!({"id": "3", "name": "Charlie","age": 35, "score": 75, "active": false,"createdAt": "2024-01-10"}),
        json!({"id": "4", "name": "Diana", "age": 28, "score": 90, "active": true, "createdAt": "2024-03-01"}),
        json!({"id": "5", "name": "Eve",   "age": 30, "score": 80, "active": false,"createdAt": "2024-02-15"}),
    ]
}

fn sort_entry(field: &str, direction: SortDirection) -> SortEntry {
    SortEntry {
        field: field.to_string(),
        direction,
    }
}

// ============================================================================
// sort_records — single field
// ============================================================================

#[test]
fn sort_by_string_asc() {
    let result = sort_records(users(), &[sort_entry("name", SortDirection::Asc)]);
    let names: Vec<&str> = result.iter().map(|u| u["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Alice", "Bob", "Charlie", "Diana", "Eve"]);
}

#[test]
fn sort_by_string_desc() {
    let result = sort_records(users(), &[sort_entry("name", SortDirection::Desc)]);
    let names: Vec<&str> = result.iter().map(|u| u["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Eve", "Diana", "Charlie", "Bob", "Alice"]);
}

#[test]
fn sort_by_number_asc() {
    let result = sort_records(users(), &[sort_entry("age", SortDirection::Asc)]);
    let ages: Vec<i64> = result.iter().map(|u| u["age"].as_i64().unwrap()).collect();
    assert_eq!(ages, [25, 28, 30, 30, 35]);
}

#[test]
fn sort_by_number_desc() {
    let result = sort_records(users(), &[sort_entry("age", SortDirection::Desc)]);
    let ages: Vec<i64> = result.iter().map(|u| u["age"].as_i64().unwrap()).collect();
    assert_eq!(ages, [35, 30, 30, 28, 25]);
}

#[test]
fn sort_by_date_asc() {
    // Dates stored as ISO strings — lexicographic sort works
    let result = sort_records(users(), &[sort_entry("createdAt", SortDirection::Asc)]);
    let names: Vec<&str> = result.iter().map(|u| u["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Charlie", "Alice", "Eve", "Bob", "Diana"]);
}

#[test]
fn sort_by_boolean_asc() {
    // false < true
    let result = sort_records(users(), &[sort_entry("active", SortDirection::Asc)]);
    let actives: Vec<bool> = result
        .iter()
        .map(|u| u["active"].as_bool().unwrap())
        .collect();
    assert!(actives[0..2].iter().all(|&b| !b));
    assert!(actives[2..].iter().all(|&b| b));
}

// ============================================================================
// sort_records — multi-field
// ============================================================================

#[test]
fn sort_primary_then_secondary() {
    let sort = vec![
        sort_entry("age", SortDirection::Asc),
        sort_entry("name", SortDirection::Asc),
    ];
    let result = sort_records(users(), &sort);
    let names: Vec<&str> = result.iter().map(|u| u["name"].as_str().unwrap()).collect();
    // Age 25: Bob, Age 28: Diana, Age 30: Alice then Eve (alpha), Age 35: Charlie
    assert_eq!(names, ["Bob", "Diana", "Alice", "Eve", "Charlie"]);
}

#[test]
fn sort_secondary_field_breaks_ties() {
    let sort = vec![
        sort_entry("score", SortDirection::Desc),
        sort_entry("name", SortDirection::Asc),
    ];
    let result = sort_records(users(), &sort);
    let names: Vec<&str> = result.iter().map(|u| u["name"].as_str().unwrap()).collect();
    // Score 90: Bob, Diana (alpha); Score 85: Alice; Score 80: Eve; Score 75: Charlie
    assert_eq!(names, ["Bob", "Diana", "Alice", "Eve", "Charlie"]);
}

#[test]
fn sort_mixed_directions() {
    let sort = vec![
        sort_entry("active", SortDirection::Desc), // true first
        sort_entry("age", SortDirection::Asc),     // youngest first within group
    ];
    let result = sort_records(users(), &sort);
    let names: Vec<&str> = result.iter().map(|u| u["name"].as_str().unwrap()).collect();
    // Active(true): Bob(25), Diana(28), Alice(30); Inactive(false): Eve(30), Charlie(35)
    assert_eq!(names, ["Bob", "Diana", "Alice", "Eve", "Charlie"]);
}

// ============================================================================
// sort_records — edge cases
// ============================================================================

#[test]
fn sort_empty_sort_spec_returns_copy() {
    let original = users();
    let result = sort_records(original.clone(), &[]);
    assert_eq!(result, original);
}

#[test]
fn sort_empty_array() {
    let result = sort_records(vec![], &[sort_entry("name", SortDirection::Asc)]);
    assert!(result.is_empty());
}

#[test]
fn sort_single_element() {
    let u = vec![users()[0].clone()];
    let result = sort_records(u.clone(), &[sort_entry("name", SortDirection::Asc)]);
    assert_eq!(result, u);
}

// ============================================================================
// paginate_records
// ============================================================================

fn items() -> Vec<Value> {
    (1..=10).map(|i| json!(i)).collect()
}

#[test]
fn paginate_limit_only() {
    let result = paginate_records(items(), None, Some(3));
    assert_eq!(result, vec![json!(1), json!(2), json!(3)]);
}

#[test]
fn paginate_limit_exceeds_length() {
    let result = paginate_records(items(), None, Some(100));
    assert_eq!(result.len(), 10);
}

#[test]
fn paginate_limit_zero() {
    let result = paginate_records(items(), None, Some(0));
    assert!(result.is_empty());
}

#[test]
fn paginate_offset_only() {
    let result = paginate_records(items(), Some(3), None);
    assert_eq!(result, (4..=10).map(|i| json!(i)).collect::<Vec<_>>());
}

#[test]
fn paginate_offset_exceeds_length() {
    let result = paginate_records(items(), Some(100), None);
    assert!(result.is_empty());
}

#[test]
fn paginate_offset_zero() {
    let result = paginate_records(items(), Some(0), None);
    assert_eq!(result.len(), 10);
}

#[test]
fn paginate_offset_and_limit() {
    let result = paginate_records(items(), Some(2), Some(3));
    assert_eq!(result, vec![json!(3), json!(4), json!(5)]);
}

#[test]
fn paginate_offset_near_end() {
    let result = paginate_records(items(), Some(8), Some(5));
    assert_eq!(result, vec![json!(9), json!(10)]);
}

#[test]
fn paginate_no_params() {
    let result = paginate_records(items(), None, None);
    assert_eq!(result.len(), 10);
}

#[test]
fn paginate_empty_array() {
    let result = paginate_records(vec![], Some(0), Some(10));
    assert!(result.is_empty());
}

// ============================================================================
// execute_query
// ============================================================================

#[test]
fn execute_query_filter_only() {
    let query = Query {
        filter: Some(json!({"active": true})),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    assert_eq!(result.records.len(), 3);
    assert_eq!(result.total, 3);
    assert!(result
        .records
        .iter()
        .all(|u| u["active"].as_bool().unwrap()));
}

#[test]
fn execute_query_sort_only() {
    let query = Query {
        sort: Some(SortInput::Entries(vec![sort_entry(
            "age",
            SortDirection::Asc,
        )])),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    let ages: Vec<i64> = result
        .records
        .iter()
        .map(|u| u["age"].as_i64().unwrap())
        .collect();
    assert_eq!(ages, [25, 28, 30, 30, 35]);
    assert_eq!(result.total, 5);
}

#[test]
fn execute_query_limit_only() {
    let query = Query {
        limit: Some(2),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.total, 5); // Total before limit
}

#[test]
fn execute_query_filter_sort_limit() {
    let query = Query {
        filter: Some(json!({"active": true})),
        sort: Some(SortInput::Entries(vec![sort_entry(
            "age",
            SortDirection::Asc,
        )])),
        limit: Some(2),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.total, 3); // 3 active users
    let names: Vec<&str> = result
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Bob", "Diana"]);
}

#[test]
fn execute_query_filter_sort_offset_limit() {
    let query = Query {
        filter: Some(json!({"active": true})),
        sort: Some(SortInput::Entries(vec![sort_entry(
            "name",
            SortDirection::Asc,
        )])),
        offset: Some(1),
        limit: Some(1),
    };
    let result = execute_query(users(), &query).unwrap();
    // Active users sorted by name: Alice, Bob, Diana
    // Skip 1, take 1 = Bob
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0]["name"], "Bob");
    assert_eq!(result.total, 3);
}

#[test]
fn execute_query_no_matches() {
    let query = Query {
        filter: Some(json!({"age": {"$gt": 100}})),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    assert_eq!(result.records.len(), 0);
    assert_eq!(result.total, 0);
}

#[test]
fn execute_query_empty_returns_all() {
    let query = Query::default();
    let result = execute_query(users(), &query).unwrap();
    assert_eq!(result.records.len(), 5);
    assert_eq!(result.total, 5);
}

#[test]
fn execute_query_logical_operators() {
    let query = Query {
        filter: Some(json!({"$or": [{"age": {"$lt": 26}}, {"age": {"$gt": 34}}]})),
        sort: Some(SortInput::Entries(vec![sort_entry(
            "age",
            SortDirection::Asc,
        )])),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    let names: Vec<&str> = result
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Bob", "Charlie"]);
}

// ============================================================================
// find_first
// ============================================================================

#[test]
fn find_first_finds_first_matching() {
    let query = Query {
        filter: Some(json!({"active": true})),
        ..Default::default()
    };
    let result = find_first(users(), &query).unwrap();
    assert!(result.is_some());
    assert!(result.unwrap()["active"].as_bool().unwrap());
}

#[test]
fn find_first_respects_sort_order() {
    let query = Query {
        filter: Some(json!({"active": true})),
        sort: Some(SortInput::Entries(vec![sort_entry(
            "age",
            SortDirection::Desc,
        )])),
        ..Default::default()
    };
    let result = find_first(users(), &query).unwrap();
    // Oldest active user is Alice (30) — Bob=25, Diana=28, Alice=30
    assert_eq!(result.unwrap()["name"], "Alice");
}

#[test]
fn find_first_returns_none_when_no_match() {
    let query = Query {
        filter: Some(json!({"age": {"$gt": 100}})),
        ..Default::default()
    };
    let result = find_first(users(), &query).unwrap();
    assert!(result.is_none());
}

// ============================================================================
// count_matching
// ============================================================================

#[test]
fn count_matching_with_filter() {
    let q_active = Query {
        filter: Some(json!({"active": true})),
        ..Default::default()
    };
    let q_inactive = Query {
        filter: Some(json!({"active": false})),
        ..Default::default()
    };
    assert_eq!(count_matching(&users(), &q_active).unwrap(), 3);
    assert_eq!(count_matching(&users(), &q_inactive).unwrap(), 2);
}

#[test]
fn count_matching_no_filter_counts_all() {
    let query = Query::default();
    assert_eq!(count_matching(&users(), &query).unwrap(), 5);
}

#[test]
fn count_matching_zero_when_no_match() {
    let query = Query {
        filter: Some(json!({"age": {"$gt": 100}})),
        ..Default::default()
    };
    assert_eq!(count_matching(&users(), &query).unwrap(), 0);
}

#[test]
fn count_matching_ignores_pagination() {
    let query = Query {
        filter: Some(json!({"active": true})),
        limit: Some(1),
        offset: Some(10),
        ..Default::default()
    };
    assert_eq!(count_matching(&users(), &query).unwrap(), 3);
}

// ============================================================================
// Integration: realistic queries
// ============================================================================

#[test]
fn integration_top_scorers_active() {
    let query = Query {
        filter: Some(json!({"active": true, "score": {"$gte": 85}})),
        sort: Some(SortInput::Entries(vec![sort_entry(
            "score",
            SortDirection::Desc,
        )])),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    let names: Vec<&str> = result
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Bob", "Diana", "Alice"]);
}

#[test]
fn integration_pagination_all_pages() {
    let page_size = 2;
    let make_query = |offset: usize| Query {
        sort: Some(SortInput::Entries(vec![sort_entry(
            "name",
            SortDirection::Asc,
        )])),
        limit: Some(page_size),
        offset: Some(offset),
        ..Default::default()
    };

    let page1 = execute_query(users(), &make_query(0)).unwrap();
    let page2 = execute_query(users(), &make_query(2)).unwrap();
    let page3 = execute_query(users(), &make_query(4)).unwrap();

    let p1_names: Vec<&str> = page1
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    let p2_names: Vec<&str> = page2
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    let p3_names: Vec<&str> = page3
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();

    assert_eq!(p1_names, ["Alice", "Bob"]);
    assert_eq!(p2_names, ["Charlie", "Diana"]);
    assert_eq!(p3_names, ["Eve"]);
    assert_eq!(page1.total, 5);
}

#[test]
fn integration_date_range_with_and() {
    // Dates as ISO strings: 2024-02-01 to 2024-03-01 (exclusive)
    let query = Query {
        filter: Some(json!({
            "$and": [
                {"createdAt": {"$gte": "2024-02-01"}},
                {"createdAt": {"$lt": "2024-03-01"}}
            ]
        })),
        sort: Some(SortInput::Entries(vec![sort_entry(
            "createdAt",
            SortDirection::Asc,
        )])),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    let names: Vec<&str> = result
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Eve", "Bob"]);
}

// ============================================================================
// Sort shorthand (SortInput::Field)
// ============================================================================

#[test]
fn sort_shorthand_string_ascending() {
    let query = Query {
        sort: Some(SortInput::Field("name".to_string())),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    let names: Vec<&str> = result
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Alice", "Bob", "Charlie", "Diana", "Eve"]);
}

#[test]
fn sort_shorthand_with_filter() {
    let query = Query {
        filter: Some(json!({"active": true})),
        sort: Some(SortInput::Field("age".to_string())),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    let names: Vec<&str> = result
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Bob", "Diana", "Alice"]);
}

#[test]
fn sort_shorthand_with_pagination() {
    let query = Query {
        sort: Some(SortInput::Field("name".to_string())),
        limit: Some(2),
        offset: Some(1),
        ..Default::default()
    };
    let result = execute_query(users(), &query).unwrap();
    let names: Vec<&str> = result
        .records
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Bob", "Charlie"]);
    assert_eq!(result.total, 5);
}

// ============================================================================
// normalize_sort
// ============================================================================

#[test]
fn normalize_sort_none() {
    assert!(normalize_sort(None).is_none());
}

#[test]
fn normalize_sort_field_to_asc() {
    let result = normalize_sort(Some(SortInput::Field("name".to_string()))).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].field, "name");
    assert_eq!(result[0].direction, SortDirection::Asc);
}

#[test]
fn normalize_sort_entries_unchanged() {
    let entries = vec![
        SortEntry {
            field: "name".to_string(),
            direction: SortDirection::Desc,
        },
        SortEntry {
            field: "age".to_string(),
            direction: SortDirection::Asc,
        },
    ];
    let result = normalize_sort(Some(SortInput::Entries(entries.clone()))).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].field, "name");
    assert_eq!(result[0].direction, SortDirection::Desc);
}

// ============================================================================
// normalize_computed_filter
// ============================================================================

#[test]
fn normalize_computed_filter_none() {
    assert!(normalize_computed_filter(None, &[]).is_none());
}

#[test]
fn normalize_computed_filter_no_computed_names() {
    let filter = json!({"name": "Alice"});
    let result = normalize_computed_filter(Some(filter.clone()), &[]).unwrap();
    assert_eq!(result, filter);
}

#[test]
fn normalize_computed_filter_no_matching_keys() {
    let filter = json!({"name": "Alice"});
    let result = normalize_computed_filter(Some(filter.clone()), &["emailLower"]).unwrap();
    assert_eq!(result, filter);
}

#[test]
fn normalize_computed_filter_moves_computed_key() {
    let filter = json!({"name": "Alice", "emailLower": "alice@example.com"});
    let result = normalize_computed_filter(Some(filter), &["emailLower"]).unwrap();
    let obj = result.as_object().unwrap();
    assert_eq!(obj.get("name"), Some(&json!("Alice")));
    assert!(obj.get("emailLower").is_none());
    let computed = obj.get("$computed").and_then(|v| v.as_object()).unwrap();
    assert_eq!(
        computed.get("emailLower"),
        Some(&json!("alice@example.com"))
    );
}

#[test]
fn normalize_computed_filter_merges_existing_computed() {
    let filter = json!({
        "emailLower": "alice@example.com",
        "$computed": {"other": "val"}
    });
    let result = normalize_computed_filter(Some(filter), &["emailLower"]).unwrap();
    let obj = result.as_object().unwrap();
    let computed = obj.get("$computed").and_then(|v| v.as_object()).unwrap();
    assert_eq!(
        computed.get("emailLower"),
        Some(&json!("alice@example.com"))
    );
    assert_eq!(computed.get("other"), Some(&json!("val")));
}

#[test]
fn normalize_computed_filter_multiple_computed_keys() {
    let filter = json!({"emailLower": "a@b.com", "nameLower": "alice", "status": "active"});
    let result = normalize_computed_filter(Some(filter), &["emailLower", "nameLower"]).unwrap();
    let obj = result.as_object().unwrap();
    assert_eq!(obj.get("status"), Some(&json!("active")));
    let computed = obj.get("$computed").and_then(|v| v.as_object()).unwrap();
    assert_eq!(computed.get("emailLower"), Some(&json!("a@b.com")));
    assert_eq!(computed.get("nameLower"), Some(&json!("alice")));
}

// ============================================================================
// executeQuery with $nin filter (from operator tests)
// ============================================================================

#[test]
fn execute_query_with_nin() {
    let records = vec![
        json!({"name": "Alice", "score": 90}),
        json!({"name": "Bob",   "score": 80}),
        json!({"name": "Charlie", "score": 70}),
    ];
    let query = Query {
        filter: Some(json!({"score": {"$nin": [90, 70]}})),
        ..Default::default()
    };
    let result = execute_query(records, &query).unwrap();
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0]["name"], "Bob");
}
