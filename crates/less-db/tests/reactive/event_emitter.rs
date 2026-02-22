//! Tests for `EventEmitter<T>`.

use less_db::reactive::EventEmitter;
use std::sync::{Arc, Mutex};

/// Helper: create a shared call-log that listeners append to.
fn make_log() -> Arc<Mutex<Vec<String>>> {
    Arc::new(Mutex::new(Vec::new()))
}

// ============================================================================
// Basic subscription
// ============================================================================

#[test]
fn on_adds_listener_and_emit_calls_it() {
    let emitter: EventEmitter<i32> = EventEmitter::new();
    let log = make_log();
    let log_clone = Arc::clone(&log);

    emitter.on(move |event| {
        log_clone.lock().unwrap().push(format!("{event}"));
    });

    emitter.emit(&42);

    assert_eq!(*log.lock().unwrap(), vec!["42"]);
}

#[test]
fn emit_calls_multiple_listeners_in_registration_order() {
    let emitter: EventEmitter<i32> = EventEmitter::new();
    let log = make_log();

    {
        let log = Arc::clone(&log);
        emitter.on(move |e| log.lock().unwrap().push(format!("a:{e}")));
    }
    {
        let log = Arc::clone(&log);
        emitter.on(move |e| log.lock().unwrap().push(format!("b:{e}")));
    }
    {
        let log = Arc::clone(&log);
        emitter.on(move |e| log.lock().unwrap().push(format!("c:{e}")));
    }

    emitter.emit(&1);

    assert_eq!(*log.lock().unwrap(), vec!["a:1", "b:1", "c:1"]);
}

// ============================================================================
// Unsubscription
// ============================================================================

#[test]
fn off_removes_listener_by_id() {
    let emitter: EventEmitter<i32> = EventEmitter::new();
    let log = make_log();
    let log_clone = Arc::clone(&log);

    let id = emitter.on(move |e| log_clone.lock().unwrap().push(format!("{e}")));
    emitter.off(id);
    emitter.emit(&99);

    assert!(
        log.lock().unwrap().is_empty(),
        "listener should not fire after off()"
    );
}

#[test]
fn double_off_is_safe() {
    let emitter: EventEmitter<i32> = EventEmitter::new();
    let log = make_log();
    let log_clone = Arc::clone(&log);

    let id = emitter.on(move |e| log_clone.lock().unwrap().push(format!("{e}")));
    emitter.off(id);
    // Second removal of the same ID should not panic
    emitter.off(id);
    emitter.emit(&1);

    assert!(log.lock().unwrap().is_empty());
}

// ============================================================================
// Size
// ============================================================================

#[test]
fn size_reflects_listener_count() {
    let emitter: EventEmitter<i32> = EventEmitter::new();
    assert_eq!(emitter.size(), 0);

    let id1 = emitter.on(|_| {});
    assert_eq!(emitter.size(), 1);

    let _id2 = emitter.on(|_| {});
    assert_eq!(emitter.size(), 2);

    emitter.off(id1);
    assert_eq!(emitter.size(), 1);
}

// ============================================================================
// Snapshot semantics during emit
// ============================================================================

#[test]
fn listener_added_during_emit_is_not_called_in_current_emission() {
    let emitter: Arc<EventEmitter<i32>> = Arc::new(EventEmitter::new());
    let log = make_log();

    // First listener: during its call, it adds a second listener.
    {
        let emitter_clone = Arc::clone(&emitter);
        let log_clone = Arc::clone(&log);

        emitter.on(move |_e| {
            log_clone.lock().unwrap().push("first".to_string());
            // Add a second listener mid-emission — works because on() takes &self
            // with interior mutability, and emit() releases its lock before callbacks.
            let log2 = Arc::clone(&log_clone);
            emitter_clone.on(move |_| log2.lock().unwrap().push("second".to_string()));
        });
    }

    emitter.emit(&1);

    // Only "first" should appear — "second" was added during emission
    // so it should not be called in this round.
    let log_guard = log.lock().unwrap();
    assert!(
        log_guard.contains(&"first".to_string()),
        "first listener should fire"
    );
    assert!(
        !log_guard.contains(&"second".to_string()),
        "second listener added during emit should NOT fire in same emission"
    );
}

#[test]
fn listener_removed_during_emit_is_still_called_snapshot_semantics() {
    let emitter: Arc<EventEmitter<i32>> = Arc::new(EventEmitter::new());
    let log = make_log();

    // The second listener removes the first listener mid-emission via off().
    // Snapshot semantics guarantee the first listener was already called because
    // the snapshot was taken before any callbacks ran.
    let first_called = Arc::new(Mutex::new(false));
    let first_called_clone = Arc::clone(&first_called);

    let id1 = emitter.on(move |_| {
        *first_called_clone.lock().unwrap() = true;
    });

    // Second listener removes the first during emission.
    let emitter_clone = Arc::clone(&emitter);
    let log_clone = Arc::clone(&log);
    emitter.on(move |_| {
        log_clone.lock().unwrap().push("second".to_string());
        emitter_clone.off(id1);
    });

    emitter.emit(&1);

    // Both should have fired (snapshot was taken before second called off).
    assert!(
        *first_called.lock().unwrap(),
        "first listener should have been called"
    );
    assert!(log.lock().unwrap().contains(&"second".to_string()));

    // But the first listener is now removed — second emit should only fire "second".
    *first_called.lock().unwrap() = false;
    emitter.emit(&2);
    assert!(
        !*first_called.lock().unwrap(),
        "first listener should NOT fire after removal"
    );
}

// ============================================================================
// Error isolation — emit does NOT catch panics (matches JS behavior)
// ============================================================================

#[test]
fn throwing_listener_propagates_and_prevents_subsequent_calls() {
    let emitter: EventEmitter<i32> = EventEmitter::new();
    let log = make_log();
    let log_clone = Arc::clone(&log);

    emitter.on(|_| panic!("first panics"));
    emitter.on(move |_| {
        log_clone.lock().unwrap().push("second".to_string());
    });

    // The panic from the first listener should propagate out of emit().
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        emitter.emit(&1);
    }));

    assert!(
        result.is_err(),
        "emit should propagate panics from listeners"
    );
    // The second listener should NOT have been called because the panic
    // interrupted iteration.
    assert!(
        log.lock().unwrap().is_empty(),
        "second listener should not be called after first panics"
    );
}

// ============================================================================
// emit with no listeners
// ============================================================================

#[test]
fn emit_with_no_listeners_is_a_no_op() {
    let emitter: EventEmitter<i32> = EventEmitter::new();
    // Should not panic
    emitter.emit(&42);
}
