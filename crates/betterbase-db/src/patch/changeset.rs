use std::collections::BTreeSet;

/// A set of dot-notation paths representing changed fields.
/// Examples: "email", "preferences.theme", "addresses"
pub type Changeset = BTreeSet<String>;

/// Create a new empty changeset.
pub fn create_changeset() -> Changeset {
    BTreeSet::new()
}

/// Create a changeset from an iterable of paths.
pub fn changeset_from(paths: impl IntoIterator<Item = impl Into<String>>) -> Changeset {
    paths.into_iter().map(|s| s.into()).collect()
}

/// Merge two changesets (union).
pub fn merge_changesets(a: &Changeset, b: &Changeset) -> Changeset {
    a.union(b).cloned().collect()
}

/// Check if a field or any of its children changed.
/// Also returns true if this field is a child of a changed field.
///
/// Examples:
///   changes = {"user.profile.email", "user.name"}
///   has_field_change(&changes, "user") → true (child changed)
///   has_field_change(&changes, "user.profile") → true (child changed)
///   has_field_change(&changes, "addresses.0.street") with changes = {"addresses"} → true (parent changed)
pub fn has_field_change(changeset: &Changeset, field: &str) -> bool {
    // Exact match
    if changeset.contains(field) {
        return true;
    }
    let child_prefix = format!("{}.", field);
    let parent_prefix_check = |path: &str| field.starts_with(&format!("{}.", path));
    for path in changeset {
        // Any changed field is a child of `field`
        if path.starts_with(&child_prefix) {
            return true;
        }
        // `field` is a child of a changed path
        if parent_prefix_check(path) {
            return true;
        }
    }
    false
}

/// Check if a field was directly changed (exact match only).
pub fn has_direct_change(changeset: &Changeset, field: &str) -> bool {
    changeset.contains(field)
}

/// Get all changes under a specific prefix (exact match + children).
pub fn get_changes_under(changeset: &Changeset, prefix: &str) -> Changeset {
    let prefix_dot = format!("{}.", prefix);
    changeset
        .iter()
        .filter(|p| p.as_str() == prefix || p.starts_with(&prefix_dot))
        .cloned()
        .collect()
}

/// Convert changeset to a sorted vec (BTreeSet is already sorted).
pub fn changeset_to_vec(changeset: &Changeset) -> Vec<String> {
    changeset.iter().cloned().collect()
}

/// Check if changeset is empty.
pub fn is_empty_changeset(changeset: &Changeset) -> bool {
    changeset.is_empty()
}
