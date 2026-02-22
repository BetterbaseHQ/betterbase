use less_db::patch::changeset::{
    changeset_from, create_changeset, get_changes_under, has_direct_change, has_field_change,
    is_empty_changeset, merge_changesets,
};

// ============================================================================
// get_changes_under
// ============================================================================

#[test]
fn get_changes_under_returns_exact_match() {
    let cs = changeset_from(["user", "user.name", "user.profile.email", "address"]);
    let result = get_changes_under(&cs, "user");
    assert!(result.contains("user"));
    assert!(result.contains("user.name"));
    assert!(result.contains("user.profile.email"));
    assert!(!result.contains("address"));
}

#[test]
fn get_changes_under_returns_only_children() {
    let cs = changeset_from(["user.name", "user.profile.email", "address.street"]);
    let result = get_changes_under(&cs, "user");
    assert!(result.contains("user.name"));
    assert!(result.contains("user.profile.email"));
    assert!(!result.contains("address.street"));
}

#[test]
fn get_changes_under_empty_when_no_match() {
    let cs = changeset_from(["address.street", "phone"]);
    let result = get_changes_under(&cs, "user");
    assert!(result.is_empty());
}

#[test]
fn get_changes_under_no_partial_prefix_match() {
    // "username" should NOT match prefix "user"
    let cs = changeset_from(["username", "userprofile"]);
    let result = get_changes_under(&cs, "user");
    assert!(result.is_empty());
}

// ============================================================================
// is_empty_changeset
// ============================================================================

#[test]
fn is_empty_changeset_true_for_empty() {
    let cs = create_changeset();
    assert!(is_empty_changeset(&cs));
}

#[test]
fn is_empty_changeset_false_for_non_empty() {
    let cs = changeset_from(["email"]);
    assert!(!is_empty_changeset(&cs));
}

// ============================================================================
// has_field_change
// ============================================================================

#[test]
fn has_field_change_exact_match() {
    let cs = changeset_from(["email"]);
    assert!(has_field_change(&cs, "email"));
}

#[test]
fn has_field_change_child_changed() {
    let cs = changeset_from(["user.profile.email", "user.name"]);
    // Parent of changed field
    assert!(has_field_change(&cs, "user"));
    assert!(has_field_change(&cs, "user.profile"));
}

#[test]
fn has_field_change_field_is_child_of_changed() {
    // "addresses" changed — any descendant should also report changed
    let cs = changeset_from(["addresses"]);
    assert!(has_field_change(&cs, "addresses.0.street"));
}

#[test]
fn has_field_change_unrelated_returns_false() {
    let cs = changeset_from(["email", "phone"]);
    assert!(!has_field_change(&cs, "address"));
}

#[test]
fn has_field_change_no_partial_prefix_match() {
    // "username" should not trigger a change for "user"
    let cs = changeset_from(["username"]);
    assert!(!has_field_change(&cs, "user"));
}

// ============================================================================
// has_direct_change
// ============================================================================

#[test]
fn has_direct_change_exact_match_only() {
    let cs = changeset_from(["user.name"]);
    assert!(has_direct_change(&cs, "user.name"));
    // Parent is not a direct change
    assert!(!has_direct_change(&cs, "user"));
    // Child is not a direct change
    assert!(!has_direct_change(&cs, "user.name.first"));
}

// ============================================================================
// merge_changesets
// ============================================================================

#[test]
fn merge_changesets_unions_two() {
    let a = changeset_from(["email", "name"]);
    let b = changeset_from(["phone", "name"]);
    let merged = merge_changesets(&a, &b);
    assert!(merged.contains("email"));
    assert!(merged.contains("name"));
    assert!(merged.contains("phone"));
    assert_eq!(merged.len(), 3);
}

#[test]
fn merge_changesets_with_empty() {
    let a = changeset_from(["email"]);
    let b = create_changeset();
    let merged = merge_changesets(&a, &b);
    assert_eq!(merged.len(), 1);
    assert!(merged.contains("email"));
}

#[test]
fn merge_changesets_both_empty() {
    let a = create_changeset();
    let b = create_changeset();
    let merged = merge_changesets(&a, &b);
    assert!(merged.is_empty());
}
