//! EventEmitter<T> — a simple typed pub/sub primitive.
//!
//! Listeners are stored as `Arc<dyn Fn(&T)>` so snapshots are cheap.
//! Snapshot-on-emit semantics mean:
//!   - A listener removed *during* emission is still called in that round.
//!   - A listener added *during* emission is NOT called until the next emit.
//!
//! Panics inside a listener propagate to the caller — no error isolation at
//! this level (the ReactiveAdapter handles isolation above).
//!
//! All methods take `&self` (interior mutability via `parking_lot::Mutex`),
//! which allows listeners to call `on()`/`off()` during `emit()` without
//! deadlocking — matching JS's naturally reentrant semantics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

/// A listener ID returned by [`EventEmitter::on`] that can be passed to
/// [`EventEmitter::off`] to remove the listener.
pub type ListenerId = u64;

/// Closure type for event listeners.
pub type ListenerFn<T> = dyn Fn(&T) + Send + Sync;

/// Typed synchronous event emitter.
///
/// `T` is the event payload type. All methods take `&self` — internal state
/// is protected by a `parking_lot::Mutex` that is never held during callbacks.
pub struct EventEmitter<T> {
    listeners: Mutex<Vec<(ListenerId, Arc<ListenerFn<T>>)>>,
    next_id: AtomicU64,
}

impl<T> EventEmitter<T> {
    /// Create a new, empty emitter.
    pub fn new() -> Self {
        Self {
            listeners: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Register `callback` and return its [`ListenerId`].
    ///
    /// The callback is called with a shared reference to each emitted event.
    pub fn on(&self, callback: impl Fn(&T) + Send + Sync + 'static) -> ListenerId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.listeners.lock().push((id, Arc::new(callback)));
        id
    }

    /// Remove the listener identified by `id`.
    ///
    /// Does nothing if `id` is not present (safe to call multiple times).
    pub fn off(&self, id: ListenerId) {
        self.listeners.lock().retain(|(lid, _)| *lid != id);
    }

    /// Emit `event` to all currently registered listeners.
    ///
    /// A snapshot of the listener list is taken before iteration so that
    /// additions or removals during a callback do not affect the current
    /// emission round. The lock is released before calling any callbacks.
    pub fn emit(&self, event: &T) {
        // Snapshot Arc references under the lock (cheap: just ref-count bumps).
        let snapshot: Vec<Arc<ListenerFn<T>>> = {
            let guard = self.listeners.lock();
            guard.iter().map(|(_, cb)| Arc::clone(cb)).collect()
        };
        // Lock is released — callbacks can safely call on()/off().
        for cb in snapshot {
            cb(event);
        }
    }

    /// Number of currently registered listeners.
    pub fn size(&self) -> usize {
        self.listeners.lock().len()
    }
}

impl<T> Default for EventEmitter<T> {
    fn default() -> Self {
        Self::new()
    }
}
