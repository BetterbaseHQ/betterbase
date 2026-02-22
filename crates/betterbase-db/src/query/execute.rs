//! Query execution engine — scan-and-filter with sorting and pagination.

use serde_json::Value;

use crate::error::Result;

use super::operators::{compare_values, filter_records, get_field_value};
use super::types::{normalize_sort, ExecuteQueryResult, Query, SortDirection, SortEntry};

// ============================================================================
// Sorting
// ============================================================================

/// Sort records by multiple fields with cascading priority.
/// Returns a sorted copy; does not mutate the input.
pub fn sort_records(mut records: Vec<Value>, sort: &[SortEntry]) -> Vec<Value> {
    if sort.is_empty() {
        return records;
    }

    records.sort_by(|a, b| {
        for entry in sort {
            let va = get_field_value(a, &entry.field).unwrap_or(&Value::Null);
            let vb = get_field_value(b, &entry.field).unwrap_or(&Value::Null);
            let cmp = compare_values(va, vb);
            if cmp != std::cmp::Ordering::Equal {
                return if entry.direction == SortDirection::Desc {
                    cmp.reverse()
                } else {
                    cmp
                };
            }
        }
        std::cmp::Ordering::Equal
    });

    records
}

// ============================================================================
// Pagination
// ============================================================================

/// Apply offset then limit to a list of records.
pub fn paginate_records(
    records: Vec<Value>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Vec<Value> {
    let start = offset.unwrap_or(0);
    let sliced = if start >= records.len() {
        vec![]
    } else {
        records.into_iter().skip(start).collect::<Vec<_>>()
    };

    match limit {
        Some(n) => sliced.into_iter().take(n).collect(),
        None => sliced,
    }
}

// ============================================================================
// Query Execution
// ============================================================================

/// Execute a query against a list of records (in-memory scan-and-filter).
///
/// 1. Apply filter (if present).
/// 2. Capture total count (after filter, before pagination).
/// 3. Sort (using normalized sort input).
/// 4. Paginate (offset then limit).
pub fn execute_query(records: Vec<Value>, query: &Query) -> Result<ExecuteQueryResult> {
    // 1. Filter
    let filtered = if let Some(filter) = &query.filter {
        filter_records(&records, filter)?
    } else {
        records
    };

    // 2. Capture total
    let total = filtered.len();

    // 3. Sort
    let sort_entries = normalize_sort(query.sort.clone());
    let sorted = if let Some(entries) = sort_entries {
        sort_records(filtered, &entries)
    } else {
        filtered
    };

    // 4. Paginate
    let paginated = paginate_records(sorted, query.offset, query.limit);

    Ok(ExecuteQueryResult {
        records: paginated,
        total,
        errors: vec![],
    })
}

/// Find the first record matching a query, or `None` if no records match.
pub fn find_first(records: Vec<Value>, query: &Query) -> Result<Option<Value>> {
    let limited = Query {
        filter: query.filter.clone(),
        sort: query.sort.clone(),
        limit: Some(1),
        offset: query.offset,
    };
    let result = execute_query(records, &limited)?;
    Ok(result.records.into_iter().next())
}

/// Count records matching the query filter (ignores sort and pagination).
pub fn count_matching(records: &[Value], query: &Query) -> Result<usize> {
    if let Some(filter) = &query.filter {
        let matched = filter_records(records, filter)?;
        Ok(matched.len())
    } else {
        Ok(records.len())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn paginate_records_basic() {
        let records = vec![json!(1), json!(2), json!(3), json!(4), json!(5)];
        let result = paginate_records(records.clone(), Some(1), Some(2));
        assert_eq!(result, vec![json!(2), json!(3)]);
    }

    #[test]
    fn paginate_records_no_offset_no_limit() {
        let records = vec![json!(1), json!(2)];
        let result = paginate_records(records.clone(), None, None);
        assert_eq!(result, records);
    }
}
