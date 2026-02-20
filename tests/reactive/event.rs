//! Tests for ChangeEvent accessors.

use less_db::reactive::event::ChangeEvent;

// ============================================================================
// collection() accessor
// ============================================================================

#[test]
fn put_event_collection() {
    let event = ChangeEvent::Put {
        collection: "users".to_string(),
        id: "u1".to_string(),
    };
    assert_eq!(event.collection(), "users");
}

#[test]
fn delete_event_collection() {
    let event = ChangeEvent::Delete {
        collection: "users".to_string(),
        id: "u1".to_string(),
    };
    assert_eq!(event.collection(), "users");
}

#[test]
fn bulk_event_collection() {
    let event = ChangeEvent::Bulk {
        collection: "items".to_string(),
        ids: vec!["a".to_string(), "b".to_string()],
    };
    assert_eq!(event.collection(), "items");
}

#[test]
fn remote_event_collection() {
    let event = ChangeEvent::Remote {
        collection: "docs".to_string(),
        ids: vec!["d1".to_string()],
    };
    assert_eq!(event.collection(), "docs");
}

// ============================================================================
// ids() accessor
// ============================================================================

#[test]
fn put_event_ids() {
    let event = ChangeEvent::Put {
        collection: "users".to_string(),
        id: "u1".to_string(),
    };
    assert_eq!(event.ids(), vec!["u1"]);
}

#[test]
fn delete_event_ids() {
    let event = ChangeEvent::Delete {
        collection: "users".to_string(),
        id: "u1".to_string(),
    };
    assert_eq!(event.ids(), vec!["u1"]);
}

#[test]
fn bulk_event_ids() {
    let event = ChangeEvent::Bulk {
        collection: "items".to_string(),
        ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
    };
    assert_eq!(event.ids(), vec!["a", "b", "c"]);
}

#[test]
fn remote_event_ids() {
    let event = ChangeEvent::Remote {
        collection: "docs".to_string(),
        ids: vec!["d1".to_string(), "d2".to_string()],
    };
    assert_eq!(event.ids(), vec!["d1", "d2"]);
}

// ============================================================================
// Equality and Clone
// ============================================================================

#[test]
fn events_are_eq() {
    let a = ChangeEvent::Put {
        collection: "x".to_string(),
        id: "1".to_string(),
    };
    let b = ChangeEvent::Put {
        collection: "x".to_string(),
        id: "1".to_string(),
    };
    assert_eq!(a, b);
}

#[test]
fn events_are_clone() {
    let event = ChangeEvent::Bulk {
        collection: "x".to_string(),
        ids: vec!["a".to_string()],
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
}
