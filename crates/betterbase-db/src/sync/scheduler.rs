//! SyncScheduler — throttle/coalesce layer over `SyncManager`.
//!
//! Mirrors JS `SyncScheduler`. Provides request coalescing and cooldown
//! periods to prevent sync storms while ensuring all dirty data is pushed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::collection::builder::CollectionDef;

use super::manager::SyncManager;
use super::types::SyncResult;

// ============================================================================
// SyncScheduler
// ============================================================================

pub struct SyncScheduler {
    sync_manager: Arc<SyncManager>,
    throttle_ms: u64,
    slots: Arc<Mutex<HashMap<String, Arc<Mutex<ScheduleSlot>>>>>,
    disposed: Arc<AtomicBool>,
}

/// Internal per-key scheduling state.
struct ScheduleSlot {
    running: bool,
    cooldown_active: bool,
    /// Queued waiters — they all share the next cycle's result.
    queued_senders: Vec<oneshot::Sender<Result<SyncResult, String>>>,
}

impl ScheduleSlot {
    fn new() -> Self {
        Self {
            running: false,
            cooldown_active: false,
            queued_senders: Vec::new(),
        }
    }
}

/// What the caller should do after checking the slot state.
enum ScheduleAction {
    /// Slot is idle — caller should run sync now.
    Run,
    /// Slot is busy — caller should await on this receiver.
    Wait(oneshot::Receiver<Result<SyncResult, String>>),
}

impl SyncScheduler {
    /// Create a new scheduler wrapping the given `SyncManager`.
    ///
    /// `throttle_ms` sets the cooldown between sync cycles (default: 1000).
    pub fn new(sync_manager: Arc<SyncManager>, throttle_ms: Option<u64>) -> Self {
        Self {
            sync_manager,
            throttle_ms: throttle_ms.unwrap_or(1000),
            slots: Arc::new(Mutex::new(HashMap::new())),
            disposed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Schedule a full sync for the given collection.
    pub async fn schedule_sync(&self, def: Arc<CollectionDef>) -> Result<SyncResult, String> {
        self.check_disposed()?;
        let key = def.name.clone();
        let sm = self.sync_manager.clone();
        self.schedule(key, move || {
            let def = def.clone();
            let sm = sm.clone();
            async move { sm.sync(&def).await }
        })
        .await
    }

    /// Schedule a push-only sync for the given collection.
    pub async fn schedule_push(&self, def: Arc<CollectionDef>) -> Result<SyncResult, String> {
        self.check_disposed()?;
        let key = format!("push:{}", def.name);
        let sm = self.sync_manager.clone();
        self.schedule(key, move || {
            let def = def.clone();
            let sm = sm.clone();
            async move { sm.push(&def).await }
        })
        .await
    }

    /// Schedule a sync-all across all collections.
    ///
    /// Returns a merged `SyncResult` (throttle/coalesce operates on flat results).
    ///
    /// Uses a separate throttle slot from per-collection `schedule_sync` calls.
    /// Concurrent `schedule_sync("x")` and `schedule_sync_all()` will both run
    /// (SyncManager's per-collection locks prevent data races).
    pub async fn schedule_sync_all(&self) -> Result<SyncResult, String> {
        self.check_disposed()?;
        let sm = self.sync_manager.clone();
        self.schedule("__sync_all__".to_string(), move || {
            let sm = sm.clone();
            async move {
                let map = sm.sync_all().await;
                let mut merged = SyncResult::default();
                for r in map.values() {
                    merged.pushed += r.pushed;
                    merged.pulled += r.pulled;
                    merged.merged += r.merged;
                    merged.errors.extend(r.errors.clone());
                }
                merged
            }
        })
        .await
    }

    /// Bypass throttle and run sync immediately.
    pub async fn flush(&self, def: &CollectionDef) -> SyncResult {
        self.sync_manager.sync(def).await
    }

    /// Bypass throttle and run sync_all immediately.
    pub async fn flush_all(&self) -> HashMap<String, SyncResult> {
        self.sync_manager.sync_all().await
    }

    /// Dispose the scheduler — cancel pending timers, reject queued waiters.
    pub fn dispose(&self) {
        self.disposed.store(true, Ordering::SeqCst);

        let mut slots = self.slots.lock();
        for (_, slot_arc) in slots.drain() {
            let mut slot = slot_arc.lock();
            for sender in slot.queued_senders.drain(..) {
                let _ = sender.send(Err("SyncScheduler is disposed".to_string()));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn check_disposed(&self) -> Result<(), String> {
        if self.disposed.load(Ordering::SeqCst) {
            Err("SyncScheduler is disposed".to_string())
        } else {
            Ok(())
        }
    }

    /// Get or create the slot for a key, then check if we should run or wait.
    ///
    /// This is a sync helper that returns immediately — no MutexGuard is held
    /// after it returns, ensuring the async caller can safely `.await`.
    fn check_slot(&self, key: &str) -> (Arc<Mutex<ScheduleSlot>>, ScheduleAction) {
        let slot_arc = {
            let mut slots = self.slots.lock();
            slots
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(ScheduleSlot::new())))
                .clone()
        };

        let action = {
            let mut slot = slot_arc.lock();
            if slot.running || slot.cooldown_active {
                let (tx, rx) = oneshot::channel();
                slot.queued_senders.push(tx);
                ScheduleAction::Wait(rx)
            } else {
                slot.running = true;
                ScheduleAction::Run
            }
        };

        (slot_arc, action)
    }

    async fn schedule<F, Fut>(&self, key: String, make_future: F) -> Result<SyncResult, String>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = SyncResult> + Send + 'static,
    {
        let (slot_arc, action) = self.check_slot(&key);

        match action {
            ScheduleAction::Wait(rx) => {
                return rx.await.map_err(|_| "channel closed".to_string())?;
            }
            ScheduleAction::Run => {
                // Fall through to run the sync
            }
        }

        // Run the sync (no mutex guard held here)
        let result = make_future().await;

        // Mark as not running and collect queued senders
        let queued = {
            let mut slot = slot_arc.lock();
            slot.running = false;
            slot.queued_senders.drain(..).collect::<Vec<_>>()
        };

        // Start cooldown timer and handle queued follow-up
        {
            let mut slot = slot_arc.lock();
            slot.cooldown_active = true;
        }

        let slot_clone = slot_arc.clone();
        let throttle_ms = self.throttle_ms;
        let disposed = self.disposed.clone();

        let mf: Arc<
            dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = SyncResult> + Send>>
                + Send
                + Sync,
        > = Arc::new(move || Box::pin(make_future()));

        tokio::spawn(async move {
            // Carry forward senders from the initial cycle
            let mut prev_senders = queued;

            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(throttle_ms)).await;

                // Collect senders that arrived during cooldown
                let cooldown_senders = {
                    let mut slot = slot_clone.lock();
                    slot.cooldown_active = false;
                    slot.queued_senders.drain(..).collect::<Vec<_>>()
                };

                // Merge with senders from before cooldown
                let mut all_senders = std::mem::take(&mut prev_senders);
                all_senders.extend(cooldown_senders);

                if all_senders.is_empty() {
                    break;
                }

                if disposed.load(Ordering::SeqCst) {
                    for sender in all_senders {
                        let _ = sender.send(Err("SyncScheduler is disposed".to_string()));
                    }
                    break;
                }

                // Run the follow-up sync
                {
                    let mut slot = slot_clone.lock();
                    slot.running = true;
                }

                let follow_result = mf().await;

                // Drain any senders that arrived during the follow-up sync
                let during_run_senders = {
                    let mut slot = slot_clone.lock();
                    slot.running = false;
                    slot.cooldown_active = true;
                    slot.queued_senders.drain(..).collect::<Vec<_>>()
                };

                for sender in all_senders {
                    let _ = sender.send(Ok(follow_result.clone()));
                }

                // If new waiters arrived during the follow-up, loop for another cooldown cycle
                if during_run_senders.is_empty() {
                    // No waiters during run — clear cooldown and exit (matches JS behavior)
                    let mut slot = slot_clone.lock();
                    slot.cooldown_active = false;
                    break;
                } else {
                    prev_senders = during_run_senders;
                }
                // Loop continues — another cooldown sleep begins
            }
        });

        Ok(result)
    }
}
