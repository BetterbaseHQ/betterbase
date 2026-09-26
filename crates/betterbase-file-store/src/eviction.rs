//! LRU byte-budget eviction — pure selection over a metadata snapshot.
//!
//! The invariant enforced here is the one platforms must not drift on:
//! queued entries are never selected (their local bytes may be the only
//! copy of unacknowledged data). Selection is coldest-first by
//! `last_accessed_at`; the caller performs the deletions and URL cleanup.

use crate::meta::FileMeta;

/// Selection inputs and accounting.
pub struct EvictionBudget<'a> {
    /// Live snapshot of every meta entry.
    pub entries: &'a [FileMeta],
    /// Ceiling the cache must come back under.
    pub max_bytes: u64,
}

impl EvictionBudget<'_> {
    fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|m| m.size).sum()
    }
}

/// Pick eviction victims: the coldest plain-cache entries (by
/// `last_accessed_at`, ties broken by `cached_at` then key for
/// determinism) until the total is at or under budget. Queued entries
/// are never selected — see [`FileMeta::is_eviction_protected`].
/// Returns `None` when the budget is already satisfied.
pub fn select_eviction_victims<'a>(budget: &EvictionBudget<'a>) -> Option<Vec<&'a FileMeta>> {
    if budget.total_bytes() <= budget.max_bytes {
        return None;
    }

    let mut candidates: Vec<&FileMeta> = budget
        .entries
        .iter()
        .filter(|m| !m.is_eviction_protected())
        .collect();
    // Coldest first; deterministic tie-break so selection is testable
    // and replayable across platforms.
    candidates.sort_by(|a, b| {
        a.last_accessed_at
            .cmp(&b.last_accessed_at)
            .then(a.cached_at.cmp(&b.cached_at))
            .then(a.key.cmp(&b.key))
    });

    let excess = budget.total_bytes() - budget.max_bytes;
    let mut freed = 0u64;
    let mut victims = Vec::new();
    for meta in candidates {
        if freed >= excess {
            break;
        }
        freed += meta.size;
        victims.push(meta);
    }
    Some(victims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{cache_key, UploadStatus};

    fn entry(space: &str, file: &str, size: u64, accessed: u64, queued: bool) -> FileMeta {
        FileMeta {
            key: cache_key(space, file),
            space_id: space.into(),
            file_id: file.into(),
            cached_at: accessed, // tie-break input
            last_accessed_at: accessed,
            size,
            record_id: queued.then(|| "r".to_string()),
            upload_status: queued.then_some(UploadStatus::Pending),
            upload_error: None,
            queued_at: None,
            attempts: None,
            last_attempt_at: None,
        }
    }

    #[test]
    fn under_budget_selects_nothing() {
        let entries = vec![entry("s", "a", 10, 1, false)];
        assert!(select_eviction_victims(&EvictionBudget {
            entries: &entries,
            max_bytes: 100
        })
        .is_none());
    }

    #[test]
    fn selects_coldest_first_until_under_budget() {
        let entries = vec![
            entry("s", "hot", 40, 100, false),
            entry("s", "cold", 30, 10, false),
            entry("s", "mid", 30, 50, false),
        ];
        let victims = select_eviction_victims(&EvictionBudget {
            entries: &entries,
            max_bytes: 60,
        })
        .unwrap();
        let keys: Vec<&str> = victims.iter().map(|m| m.file_id.as_str()).collect();
        // cold(30) + mid(30) = 60 freed of the 40 excess — mid is taken
        // because victims are selected until EXCESS is covered, matching
        // the byte-accounting of the original implementation.
        assert_eq!(keys, vec!["cold", "mid"]);
    }

    #[test]
    fn queued_entries_are_inviolable() {
        let entries = vec![
            entry("s", "queued-pending", 1000, 1, true),
            entry("s", "queued-error", 1000, 2, true),
            entry("s", "queued-uploading", 1000, 3, true),
        ];
        // Over budget with ONLY queued entries: nothing can be selected —
        // the cache stays over budget rather than losing unacked bytes.
        let victims = select_eviction_victims(&EvictionBudget {
            entries: &entries,
            max_bytes: 1,
        })
        .unwrap();
        assert!(victims.is_empty());
    }

    #[test]
    fn mixed_selection_skips_queued() {
        let entries = vec![
            entry("s", "queued", 100, 1, true), // coldest but protected
            entry("s", "plain-cold", 50, 2, false),
            entry("s", "plain-hot", 50, 99, false),
        ];
        // Total 200; budget 150 → 50 excess → the protected entry is
        // never taken even though it is the coldest.
        let victims = select_eviction_victims(&EvictionBudget {
            entries: &entries,
            max_bytes: 150,
        })
        .unwrap();
        let keys: Vec<&str> = victims.iter().map(|m| m.file_id.as_str()).collect();
        assert_eq!(keys, vec!["plain-cold"]);
    }

    #[test]
    fn tie_break_is_deterministic() {
        let entries = vec![entry("s", "b", 10, 5, false), entry("s", "a", 10, 5, false)];
        let victims = select_eviction_victims(&EvictionBudget {
            entries: &entries,
            max_bytes: 5,
        })
        .unwrap();
        assert_eq!(victims[0].file_id, "a"); // key order, not insertion order
    }
}
