//! Index query planner — selects the best index for a query.
//! Analyzes filter conditions and available indexes to minimize scan cost.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::index::types::{
    ComputedIndex, FieldIndex, IndexDefinition, IndexScan, IndexScanType, IndexSortOrder,
    IndexableValue, RangeBound,
};
use crate::query::operators::is_operator;
use crate::query::types::{SortDirection, SortEntry};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of $in values before falling back to a full scan.
const MAX_IN_VALUES: usize = 20;

// ============================================================================
// QueryPlan
// ============================================================================

/// The output of the query planner: how to execute a query.
#[derive(Debug, Clone)]
pub struct QueryPlan {
    /// Index scan to execute (None = full table scan).
    pub scan: Option<IndexScan>,
    /// Conditions not covered by the index (applied after index scan).
    pub post_filter: Option<Value>,
    /// Whether the index provides the required sort order.
    pub index_provides_sort: bool,
    /// Sort to apply after the index scan (None if index provides sort).
    pub post_sort: Option<Vec<SortEntry>>,
    /// Estimated relative cost (1 = best, 6 = full scan).
    pub estimated_cost: f64,
}

// ============================================================================
// Internal condition types
// ============================================================================

pub struct ComputedCondition {
    pub index_name: String,
    pub equality: Option<IndexableValue>,
    pub range: Option<(Option<RangeBound>, Option<RangeBound>)>,
    pub in_values: Option<Vec<IndexableValue>>,
}

pub struct ExtractedConditions {
    pub equalities: HashMap<String, IndexableValue>,
    pub ranges: HashMap<String, (Option<RangeBound>, Option<RangeBound>)>,
    pub ins: HashMap<String, Vec<IndexableValue>>,
    pub computed: HashMap<String, ComputedCondition>,
    pub residual: Option<Value>,
}

// ============================================================================
// Value conversion
// ============================================================================

/// Returns true if the value can be stored in an index (string, non-NaN number, bool).
pub fn is_indexable_value(v: &Value) -> bool {
    match v {
        Value::String(_) => true,
        Value::Number(n) => n.as_f64().map(|f| !f.is_nan()).unwrap_or(false),
        Value::Bool(_) => true,
        _ => false,
    }
}

/// Convert a JSON value to an IndexableValue. Returns None for non-indexable values.
pub fn value_to_indexable(v: &Value) -> Option<IndexableValue> {
    match v {
        Value::String(s) => Some(IndexableValue::String(s.clone())),
        Value::Number(n) => Some(IndexableValue::Number(n.as_f64()?)),
        Value::Bool(b) => Some(IndexableValue::Bool(*b)),
        _ => None,
    }
}

// ============================================================================
// Condition extraction
// ============================================================================

/// Extract indexable conditions from a filter.
///
/// Separates equalities, ranges, `$in` conditions, computed conditions, and
/// residual (non-indexable) conditions that must be applied as a post-filter.
pub fn extract_conditions(filter: Option<&Value>) -> ExtractedConditions {
    let mut result = ExtractedConditions {
        equalities: HashMap::new(),
        ranges: HashMap::new(),
        ins: HashMap::new(),
        computed: HashMap::new(),
        residual: None,
    };

    let filter = match filter {
        Some(f) => f,
        None => return result,
    };

    let obj = match filter.as_object() {
        Some(o) => o,
        None => return result,
    };

    let mut residual_parts: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut has_residual = false;

    for (key, value) in obj {
        // Logical operators → residual
        if key == "$and" || key == "$or" || key == "$not" {
            residual_parts.insert(key.clone(), value.clone());
            has_residual = true;
            continue;
        }

        // $computed filter
        if key == "$computed" {
            if let Some(computed_filter) = value.as_object() {
                for (index_name, condition) in computed_filter {
                    if let Some(cond) = extract_computed_condition(index_name, condition) {
                        result.computed.insert(index_name.clone(), cond);
                    }
                }
            }
            continue;
        }

        // Null/undefined direct value → residual (not indexable, must be preserved)
        if value.is_null() {
            residual_parts.insert(key.clone(), value.clone());
            has_residual = true;
            continue;
        }

        // Direct non-operator value = equality
        if !is_operator(value) {
            if is_indexable_value(value) {
                if let Some(iv) = value_to_indexable(value) {
                    result.equalities.insert(key.clone(), iv);
                } else {
                    residual_parts.insert(key.clone(), value.clone());
                    has_residual = true;
                }
            } else {
                // Non-indexable direct value (array, object) → residual
                residual_parts.insert(key.clone(), value.clone());
                has_residual = true;
            }
            continue;
        }

        // Operator object
        let ops = value.as_object().unwrap();

        // $eq with an indexable value is extracted; non-indexable values (arrays,
        // objects) fall through to the residual path at the end of the loop.
        if let Some(eq_val) = ops.get("$eq") {
            if is_indexable_value(eq_val) {
                if let Some(iv) = value_to_indexable(eq_val) {
                    result.equalities.insert(key.clone(), iv);
                    continue;
                }
            }
        }

        // $in
        if let Some(in_val) = ops.get("$in") {
            if let Some(arr) = in_val.as_array() {
                let values: Vec<IndexableValue> =
                    arr.iter().filter_map(value_to_indexable).collect();
                if values.len() == arr.len() && values.len() <= MAX_IN_VALUES && !values.is_empty()
                {
                    result.ins.insert(key.clone(), values);
                    continue;
                }
            }
        }

        // Range operators
        let has_range = ops.contains_key("$gt")
            || ops.contains_key("$gte")
            || ops.contains_key("$lt")
            || ops.contains_key("$lte");

        if has_range {
            let lower = if let Some(v) = ops.get("$gt").filter(|v| is_indexable_value(v)) {
                value_to_indexable(v).map(|iv| RangeBound {
                    value: iv,
                    inclusive: false,
                })
            } else if let Some(v) = ops.get("$gte").filter(|v| is_indexable_value(v)) {
                value_to_indexable(v).map(|iv| RangeBound {
                    value: iv,
                    inclusive: true,
                })
            } else {
                None
            };

            let upper = if let Some(v) = ops.get("$lt").filter(|v| is_indexable_value(v)) {
                value_to_indexable(v).map(|iv| RangeBound {
                    value: iv,
                    inclusive: false,
                })
            } else if let Some(v) = ops.get("$lte").filter(|v| is_indexable_value(v)) {
                value_to_indexable(v).map(|iv| RangeBound {
                    value: iv,
                    inclusive: true,
                })
            } else {
                None
            };

            if lower.is_some() || upper.is_some() {
                result.ranges.insert(key.clone(), (lower, upper));
                continue;
            }
        }

        // Other operators ($ne, $nin, $contains, etc.) → residual
        residual_parts.insert(key.clone(), value.clone());
        has_residual = true;
    }

    if has_residual {
        result.residual = Some(Value::Object(residual_parts));
    }

    result
}

fn extract_computed_condition(index_name: &str, condition: &Value) -> Option<ComputedCondition> {
    // null = equality with null
    if condition.is_null() {
        return Some(ComputedCondition {
            index_name: index_name.to_string(),
            equality: Some(IndexableValue::Null),
            range: None,
            in_values: None,
        });
    }

    // Direct indexable value = equality
    if !is_operator(condition) {
        if is_indexable_value(condition) {
            return Some(ComputedCondition {
                index_name: index_name.to_string(),
                equality: value_to_indexable(condition),
                range: None,
                in_values: None,
            });
        }
        return None;
    }

    let ops = condition.as_object().unwrap();

    // $eq
    if let Some(eq_val) = ops.get("$eq") {
        if is_indexable_value(eq_val) {
            return Some(ComputedCondition {
                index_name: index_name.to_string(),
                equality: value_to_indexable(eq_val),
                range: None,
                in_values: None,
            });
        }
    }

    // $in
    if let Some(in_val) = ops.get("$in") {
        if let Some(arr) = in_val.as_array() {
            let values: Vec<IndexableValue> = arr.iter().filter_map(value_to_indexable).collect();
            if !values.is_empty() {
                return Some(ComputedCondition {
                    index_name: index_name.to_string(),
                    equality: None,
                    range: None,
                    in_values: Some(values),
                });
            }
        }
    }

    // Range operators
    let lower = if let Some(v) = ops.get("$gt").filter(|v| is_indexable_value(v)) {
        value_to_indexable(v).map(|iv| RangeBound {
            value: iv,
            inclusive: false,
        })
    } else if let Some(v) = ops.get("$gte").filter(|v| is_indexable_value(v)) {
        value_to_indexable(v).map(|iv| RangeBound {
            value: iv,
            inclusive: true,
        })
    } else {
        None
    };

    let upper = if let Some(v) = ops.get("$lt").filter(|v| is_indexable_value(v)) {
        value_to_indexable(v).map(|iv| RangeBound {
            value: iv,
            inclusive: false,
        })
    } else if let Some(v) = ops.get("$lte").filter(|v| is_indexable_value(v)) {
        value_to_indexable(v).map(|iv| RangeBound {
            value: iv,
            inclusive: true,
        })
    } else {
        None
    };

    if lower.is_some() || upper.is_some() {
        return Some(ComputedCondition {
            index_name: index_name.to_string(),
            equality: None,
            range: Some((lower, upper)),
            in_values: None,
        });
    }

    None
}

// ============================================================================
// Index Scoring
// ============================================================================

struct IndexScore {
    scan: IndexScan,
    score: f64,
    covered_conditions: HashSet<String>,
    provides_sort: bool,
}

fn score_index(
    index: &IndexDefinition,
    conditions: &ExtractedConditions,
    sort: Option<&[SortEntry]>,
) -> Option<IndexScore> {
    match index {
        IndexDefinition::Field(fi) => score_field_index(fi, conditions, sort),
        IndexDefinition::Computed(ci) => score_computed_index(ci, conditions),
    }
}

fn score_field_index(
    index: &FieldIndex,
    conditions: &ExtractedConditions,
    sort: Option<&[SortEntry]>,
) -> Option<IndexScore> {
    let mut covered_conditions: HashSet<String> = HashSet::new();
    let mut equality_values: Vec<IndexableValue> = Vec::new();
    let mut range_bounds: Option<(Option<RangeBound>, Option<RangeBound>)> = None;
    let mut in_values: Option<Vec<IndexableValue>> = None;

    // Walk index fields in order
    for index_field in &index.fields {
        let field_name = &index_field.field;

        // Check equality first
        if let Some(eq_val) = conditions.equalities.get(field_name) {
            equality_values.push(eq_val.clone());
            covered_conditions.insert(field_name.clone());
            continue;
        }

        // Check $in (treated as multi-point equality for small sets)
        if let Some(values) = conditions.ins.get(field_name) {
            if values.len() <= MAX_IN_VALUES {
                in_values = Some(values.clone());
                covered_conditions.insert(field_name.clone());
                // After $in, can't use more index fields
                break;
            }
        }

        // Check range
        if let Some(bounds) = conditions.ranges.get(field_name) {
            range_bounds = Some(bounds.clone());
            covered_conditions.insert(field_name.clone());
            // After range, can't use more index fields
            break;
        }

        // Field not in conditions — stop traversal
        break;
    }

    // Check if index provides sort order
    let provides_sort = check_sort_match(index, conditions, sort);

    // If no conditions covered and no sort match, index is not useful
    if covered_conditions.is_empty() && !provides_sort {
        return None;
    }

    // Sort-only scan: no filter conditions, but sort matches.
    // Full traversal of the index in the requested direction — no bounds needed.
    if covered_conditions.is_empty() && provides_sort {
        let direction = sort_to_index_order(sort.and_then(|s| s.first()));
        let scan = IndexScan {
            scan_type: IndexScanType::Full,
            index: IndexDefinition::Field(index.clone()),
            equality_values: None,
            range_lower: None,
            range_upper: None,
            in_values: None,
            direction,
        };
        return Some(IndexScore {
            scan,
            score: 5.5,
            covered_conditions,
            provides_sort: true,
        });
    }

    // Determine scan type
    let scan_type = if in_values.is_some() || range_bounds.is_some() {
        IndexScanType::Range
    } else if equality_values.len() == index.fields.len() {
        IndexScanType::Exact
    } else {
        IndexScanType::Prefix
    };

    // Score (lower = better)
    let score = if index.unique && scan_type == IndexScanType::Exact {
        1.0
    } else if covered_conditions.len() >= 2 && provides_sort {
        2.0
    } else if covered_conditions.len() >= 2 {
        3.0
    } else if scan_type == IndexScanType::Exact || scan_type == IndexScanType::Prefix {
        4.0
    } else {
        5.0
    };

    let direction = sort_to_index_order(sort.and_then(|s| s.first()));
    let (range_lower, range_upper) = range_bounds.unwrap_or((None, None));

    let scan = IndexScan {
        scan_type,
        index: IndexDefinition::Field(index.clone()),
        equality_values: if equality_values.is_empty() {
            None
        } else {
            Some(equality_values)
        },
        range_lower,
        range_upper,
        in_values,
        direction,
    };

    Some(IndexScore {
        scan,
        score,
        covered_conditions,
        provides_sort,
    })
}

fn score_computed_index(
    index: &ComputedIndex,
    conditions: &ExtractedConditions,
) -> Option<IndexScore> {
    let computed_cond = conditions.computed.get(&index.name)?;
    let covered_conditions: HashSet<String> =
        std::iter::once(format!("$computed.{}", index.name)).collect();

    let (scan_type, score, equality_values, range_lower, range_upper, in_values) =
        if computed_cond.equality.is_some() {
            let eq_vals = computed_cond.equality.clone().map(|v| vec![v]);
            let s = if index.unique { 1.0 } else { 4.0 };
            (IndexScanType::Exact, s, eq_vals, None, None, None)
        } else if let Some(ref iv) = computed_cond.in_values {
            if iv.len() <= MAX_IN_VALUES {
                (
                    IndexScanType::Range,
                    4.0,
                    None,
                    None,
                    None,
                    Some(iv.clone()),
                )
            } else {
                return None;
            }
        } else if let Some(ref range) = computed_cond.range {
            (
                IndexScanType::Range,
                5.0,
                None,
                range.0.clone(),
                range.1.clone(),
                None,
            )
        } else {
            return None;
        };

    let scan = IndexScan {
        scan_type,
        index: IndexDefinition::Computed(index.clone()),
        equality_values,
        range_lower,
        range_upper,
        in_values,
        direction: IndexSortOrder::Asc,
    };

    Some(IndexScore {
        scan,
        score,
        covered_conditions,
        provides_sort: false,
    })
}

fn sort_to_index_order(first_sort: Option<&SortEntry>) -> IndexSortOrder {
    match first_sort {
        Some(e) if e.direction == SortDirection::Desc => IndexSortOrder::Desc,
        _ => IndexSortOrder::Asc,
    }
}

/// Check if the index provides the required sort order.
fn check_sort_match(
    index: &FieldIndex,
    conditions: &ExtractedConditions,
    sort: Option<&[SortEntry]>,
) -> bool {
    let sort = match sort {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };

    // Count equality prefix (these fields are fixed and don't affect sort)
    let equality_prefix_len = index
        .fields
        .iter()
        .take_while(|f| conditions.equalities.contains_key(&f.field))
        .count();

    let remaining_index_fields = &index.fields[equality_prefix_len..];

    if remaining_index_fields.len() < sort.len() {
        return false;
    }

    for (sort_entry, index_field) in sort.iter().zip(remaining_index_fields.iter()) {
        if index_field.field != sort_entry.field {
            return false;
        }
        let sort_dir = match sort_entry.direction {
            SortDirection::Asc => IndexSortOrder::Asc,
            SortDirection::Desc => IndexSortOrder::Desc,
        };
        if index_field.order != sort_dir {
            return false;
        }
    }

    true
}

// ============================================================================
// Query Planning
// ============================================================================

/// Plan query execution by selecting the best index.
///
/// Scores all available indexes and picks the lowest-cost option.
/// Builds the residual filter for conditions not covered by the chosen index.
pub fn plan_query(
    filter: Option<&Value>,
    sort: Option<&[SortEntry]>,
    indexes: &[IndexDefinition],
) -> QueryPlan {
    let conditions = extract_conditions(filter);

    // Score all indexes
    let mut scores: Vec<IndexScore> = indexes
        .iter()
        .filter_map(|idx| score_index(idx, &conditions, sort))
        .collect();

    // Select best (lowest score)
    scores.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let best = match scores.into_iter().next() {
        None => {
            // Full table scan
            return QueryPlan {
                scan: None,
                post_filter: filter.cloned(),
                index_provides_sort: false,
                post_sort: sort.map(|s| s.to_vec()),
                estimated_cost: 6.0,
            };
        }
        Some(s) => s,
    };

    let post_filter = build_residual_filter(filter, &best.covered_conditions, &conditions);
    let post_sort = if best.provides_sort {
        None
    } else {
        sort.map(|s| s.to_vec())
    };

    QueryPlan {
        scan: Some(best.scan),
        post_filter,
        index_provides_sort: best.provides_sort,
        post_sort,
        estimated_cost: best.score,
    }
}

/// Build the residual filter — conditions not covered by the chosen index.
fn build_residual_filter(
    original_filter: Option<&Value>,
    covered_conditions: &HashSet<String>,
    conditions: &ExtractedConditions,
) -> Option<Value> {
    let filter = original_filter?;
    let obj = filter.as_object()?;

    let mut residual: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut has_residual = false;

    for (key, value) in obj {
        // Always include logical operators
        if key == "$and" || key == "$or" || key == "$not" {
            residual.insert(key.clone(), value.clone());
            has_residual = true;
            continue;
        }

        // Handle $computed: only include uncovered computed conditions
        if key == "$computed" {
            if let Some(computed_obj) = value.as_object() {
                let mut uncovered: serde_json::Map<String, Value> = serde_json::Map::new();
                for (index_name, condition) in computed_obj {
                    let key_str = format!("$computed.{}", index_name);
                    if !covered_conditions.contains(&key_str) {
                        uncovered.insert(index_name.clone(), condition.clone());
                    }
                }
                if !uncovered.is_empty() {
                    residual.insert("$computed".to_string(), Value::Object(uncovered));
                    has_residual = true;
                }
            }
            continue;
        }

        // Regular field: include if not covered
        if !covered_conditions.contains(key) {
            residual.insert(key.clone(), value.clone());
            has_residual = true;
        }
    }

    // Add back any conditions from the original residual (from extractConditions)
    if let Some(ref res) = conditions.residual {
        if let Some(res_obj) = res.as_object() {
            for (key, value) in res_obj {
                if !residual.contains_key(key) {
                    residual.insert(key.clone(), value.clone());
                    has_residual = true;
                }
            }
        }
    }

    if has_residual {
        Some(Value::Object(residual))
    } else {
        None
    }
}

// ============================================================================
// Explain
// ============================================================================

/// Format a query plan as a human-readable string for debugging.
pub fn explain_plan(plan: &QueryPlan) -> String {
    let mut lines: Vec<String> = Vec::new();

    if let Some(scan) = &plan.scan {
        lines.push(format!("Index: {}", scan.index.name()));
        lines.push(format!(
            "Scan type: {}",
            match scan.scan_type {
                IndexScanType::Exact => "exact",
                IndexScanType::Prefix => "prefix",
                IndexScanType::Range => "range",
                IndexScanType::Full => "full",
            }
        ));

        if let Some(ref eq_vals) = scan.equality_values {
            if !eq_vals.is_empty() {
                let formatted: Vec<String> = eq_vals.iter().map(format_indexable_value).collect();
                lines.push(format!("Equality values: {}", formatted.join(", ")));
            }
        }

        if scan.range_lower.is_some() || scan.range_upper.is_some() {
            let lower = scan.range_lower.as_ref().map(|b| {
                format!(
                    "{} {}",
                    if b.inclusive { ">=" } else { ">" },
                    format_indexable_value(&b.value)
                )
            });
            let upper = scan.range_upper.as_ref().map(|b| {
                format!(
                    "{} {}",
                    if b.inclusive { "<=" } else { "<" },
                    format_indexable_value(&b.value)
                )
            });
            let parts: Vec<String> = [lower, upper].into_iter().flatten().collect();
            lines.push(format!("Range: {}", parts.join(" AND ")));
        }

        if let Some(ref iv) = scan.in_values {
            let formatted: Vec<String> = iv.iter().map(format_indexable_value).collect();
            lines.push(format!("IN values: {}", formatted.join(", ")));
        }

        lines.push(format!(
            "Direction: {}",
            match scan.direction {
                IndexSortOrder::Asc => "asc",
                IndexSortOrder::Desc => "desc",
            }
        ));
    } else {
        lines.push("Full table scan".to_string());
    }

    lines.push(format!(
        "Post-filter: {}",
        if plan.post_filter.is_some() {
            "yes"
        } else {
            "no"
        }
    ));
    lines.push(format!(
        "Index provides sort: {}",
        if plan.index_provides_sort {
            "yes"
        } else {
            "no"
        }
    ));
    lines.push(format!(
        "Post-sort: {}",
        if plan.post_sort.is_some() {
            "yes"
        } else {
            "no"
        }
    ));
    lines.push(format!("Estimated cost: {}/6", plan.estimated_cost));

    lines.join("\n")
}

fn format_indexable_value(v: &IndexableValue) -> String {
    match v {
        IndexableValue::Null => "null".to_string(),
        IndexableValue::String(s) => format!("\"{}\"", s),
        IndexableValue::Number(n) => {
            // Format without trailing .0 when it's a whole number
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        IndexableValue::Bool(b) => format!("{}", b),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::types::{IndexField, IndexSortOrder};
    use serde_json::json;
    use std::sync::Arc;

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

    fn computed_index_def(
        name: &str,
        compute: impl Fn(&Value) -> Option<IndexableValue> + Send + Sync + 'static,
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

    #[test]
    fn extract_equality_conditions() {
        let filter = json!({ "status": "active", "email": "test@example.com" });
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
    fn extract_range_conditions() {
        let filter = json!({ "age": { "$gte": 18, "$lt": 65 } });
        let conds = extract_conditions(Some(&filter));
        let range = conds.ranges.get("age").unwrap();
        assert!(range.0.as_ref().unwrap().inclusive);
        assert_eq!(
            range.0.as_ref().unwrap().value,
            IndexableValue::Number(18.0)
        );
        assert!(!range.1.as_ref().unwrap().inclusive);
        assert_eq!(
            range.1.as_ref().unwrap().value,
            IndexableValue::Number(65.0)
        );
    }

    #[test]
    fn extract_in_conditions() {
        let filter = json!({ "status": { "$in": ["active", "pending"] } });
        let conds = extract_conditions(Some(&filter));
        let in_vals = conds.ins.get("status").unwrap();
        assert_eq!(in_vals.len(), 2);
    }

    #[test]
    fn logical_operators_go_to_residual() {
        let filter = json!({ "status": "active", "$or": [{"name": "Alice"}, {"name": "Bob"}] });
        let conds = extract_conditions(Some(&filter));
        assert!(conds.equalities.contains_key("status"));
        let residual = conds.residual.as_ref().unwrap();
        assert!(residual.get("$or").is_some());
    }

    #[test]
    fn null_values_go_to_residual() {
        let filter = json!({ "status": null, "email": "test@example.com" });
        let conds = extract_conditions(Some(&filter));
        assert_eq!(
            conds.equalities.get("email"),
            Some(&IndexableValue::String("test@example.com".to_string()))
        );
        assert!(!conds.equalities.contains_key("status"));
        let residual = conds.residual.as_ref().unwrap();
        assert!(residual.get("status").map(|v| v.is_null()).unwrap_or(false));
    }

    #[test]
    fn plan_query_unique_exact_best_cost() {
        let indexes = vec![
            field_index("email_unique", &["email"], true, false),
            field_index("status", &["status"], false, false),
        ];
        let filter = json!({ "email": "test@example.com" });
        let plan = plan_query(Some(&filter), None, &indexes);
        assert_eq!(plan.scan.as_ref().unwrap().index.name(), "email_unique");
        assert_eq!(plan.estimated_cost, 1.0);
    }

    #[test]
    fn plan_query_full_scan_when_no_indexes() {
        let filter = json!({ "status": "active" });
        let plan = plan_query(Some(&filter), None, &[]);
        assert!(plan.scan.is_none());
        assert_eq!(plan.estimated_cost, 6.0);
    }

    #[test]
    fn plan_query_post_filter_for_uncovered_conditions() {
        let indexes = vec![field_index("status", &["status"], false, false)];
        let filter = json!({ "status": "active", "name": "Alice" });
        let plan = plan_query(Some(&filter), None, &indexes);
        assert_eq!(plan.scan.as_ref().unwrap().index.name(), "status");
        let post = plan.post_filter.as_ref().unwrap();
        assert_eq!(post.get("name"), Some(&json!("Alice")));
    }

    #[test]
    fn plan_query_null_value_in_post_filter() {
        let indexes = vec![field_index("idx_email", &["email"], false, false)];
        let filter = json!({ "status": null, "email": "test@example.com" });
        let plan = plan_query(Some(&filter), None, &indexes);
        assert_eq!(plan.scan.as_ref().unwrap().index.name(), "idx_email");
        let post = plan.post_filter.as_ref().unwrap();
        assert!(post.get("status").map(|v| v.is_null()).unwrap_or(false));
    }

    #[test]
    fn explain_plan_full_scan() {
        let plan = plan_query(Some(&json!({ "status": "active" })), None, &[]);
        let output = explain_plan(&plan);
        assert!(output.contains("Full table scan"));
        assert!(output.contains("Estimated cost: 6/6"));
    }

    #[test]
    fn explain_plan_index_scan() {
        let indexes = vec![field_index("status", &["status"], false, false)];
        let plan = plan_query(Some(&json!({ "status": "active" })), None, &indexes);
        let output = explain_plan(&plan);
        assert!(output.contains("Index: status"));
        assert!(output.contains("Scan type: exact"));
        assert!(output.contains(r#"Equality values: "active""#));
    }

    #[test]
    fn explain_plan_range_scan() {
        let indexes = vec![field_index("age", &["age"], false, false)];
        let plan = plan_query(
            Some(&json!({ "age": { "$gte": 18, "$lt": 65 } })),
            None,
            &indexes,
        );
        let output = explain_plan(&plan);
        assert!(output.contains("Scan type: range"));
        assert!(output.contains("Range: >= 18 AND < 65"));
    }

    #[test]
    fn computed_index_used_for_computed_filter() {
        let indexes = vec![computed_index_def(
            "email_lower",
            |doc| {
                doc.get("email")
                    .and_then(|v| v.as_str())
                    .map(|s| IndexableValue::String(s.to_lowercase()))
            },
            true,
            false,
        )];
        let filter = json!({ "$computed": { "email_lower": "test@example.com" } });
        let plan = plan_query(Some(&filter), None, &indexes);
        assert_eq!(plan.scan.as_ref().unwrap().index.name(), "email_lower");
        assert_eq!(plan.scan.as_ref().unwrap().scan_type, IndexScanType::Exact);
    }
}
