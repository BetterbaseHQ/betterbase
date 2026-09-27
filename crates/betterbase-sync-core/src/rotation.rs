//! Canonical epoch-key-rotation state machine (audit G3).
//!
//! Space-key rotation is a stateful, branching protocol with four entry
//! points — scheduled (time-based) rotation, member-removal rotation,
//! completion of another device's interrupted advance, and adoption of a
//! finished server epoch. The ordering, conflict recovery, and the D-005
//! follow-up bound are owned here; the host (the browser `SpaceManager`)
//! performs the I/O steps and reports results.
//!
//! Design (mirrors [`crate::pull`]):
//! - [`RotationState::start`] seeds the machine from the host's local view
//!   and emits the first [`RotationAction`].
//! - [`RotationState::step`] consumes one host result and emits the next
//!   action (terminal action = [`RotationAction::Done`]).
//! - The host loops until `Done`, or reports a failed action via
//!   [`RotationEvent::ActionFailed`] (the machine decides whether the run
//!   survives — see below).
//!
//! Key material never enters the machine: it emits *key-source* actions
//! (fresh random vs. derive-from-epoch) and the host generates/derives/
//! resolves the actual bytes. This keeps the machine pure and the
//! conformance vectors key-free.
//!
//! ## Kinds
//!
//! - **Scheduled** — admin rotation on the 30-day cadence. Shared spaces
//!   rotate to a *fresh* random key (AUD-024) distributed as wrapped
//!   shares before the rewrap; personal spaces forward-derive.
//! - **Removal** — a member was revoked: revoke their UCANs, advance with
//!   `set_min_epoch` (skip the grace period), fresh key, shares to the
//!   remaining members, then re-encrypt the membership log with the
//!   removal entries folded in and notify the member's mailbox.
//! - **Interrupted** — the server reports `rewrapEpoch` set: another
//!   device advanced the epoch but did not finish the rewrap. This device
//!   resolves the target key (distributed share, else derivation — a
//!   derived completion is always followed by a fresh re-rotation,
//!   D-005), rewraps, and completes.
//! - **Adopt** — the server epoch is ahead of local with no rewrap
//!   pending: take the key (share, else derivation) and commit locally.
//!   No rewrap — the server's DEKs are already at the new epoch.
//!
//! ## Conflict recovery (`advanceEpoch` loses its CAS race)
//!
//! The server responds with its own epoch state:
//! - `rewrapEpoch` set (and ahead of local) → complete that interrupted
//!   advance first. After the completion finishes: **Removal** retries its
//!   advance on top with a fresh key (bounded to a single retry — a
//!   persistently conflicting server must not spin the machinery);
//!   **Scheduled** stops — the completion already moved the space forward.
//! - `rewrapEpoch` clear → adopt the server epoch (share or derived).
//!   **Removal** cannot proceed without a fresh key on top — it errors.
//!
//! ## Host failures
//!
//! The host reports a failed action with [`RotationEvent::ActionFailed`].
//! Containment is the machine's decision: a failure inside a D-005
//! follow-up frame is discarded and the run continues (the committed
//! completion stands — mirroring the pre-port `runFreshFollowup`
//! catch-and-log behavior), while any other failure aborts the run
//! (in-flight frames cleared, committed progress and D-005 bookkeeping
//! kept).
//!
//! ## D-005 (a derived completion is never final)
//!
//! A completed interrupted advance whose key was *derived* left the epoch
//! derivable from pre-rotation keys — a removed member could still catch
//! up. A shared space that completes a derived epoch therefore runs a
//! follow-up *fresh* rotation (AUD-024). The loop is bounded: a derived
//! completion landing *while a follow-up is in flight* defers exactly one
//! pass ([`RotationAction::Defer`]); a derived completion landing *during
//! that deferred pass* gives up loudly ([`RotationAction::GiveUp`]).
//! The bookkeeping flags persist across runs: if a run ends (crash or
//! abort) with a deferral still pending, the next run that empties the
//! stack consumes the deferred pass — the promised extra rotation is never
//! silently dropped. A completed run clears the flags (the pre-port guard
//! was in-memory and per-run; the machine makes it airtight).
//!
//! The wire behavior is pinned by conformance vectors
//! (`test-vectors/rotation.json`), which run against this machine in
//! Rust, against the 1:1 JS mirror in node tests, and against the real
//! wasm in the browser suite.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// How a rotation run was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RotationKind {
    /// Admin rotation on the time-based cadence.
    Scheduled,
    /// A member was removed (fresh key, min-epoch bump, log re-encryption).
    Removal,
    /// The server reports a pending `rewrapEpoch` — complete the rewrap.
    Interrupted,
    /// The server epoch is ahead of local and the rewrap is done — adopt.
    Adopt,
}

/// Where the run's target-epoch key comes from. Key bytes never enter the
/// machine — the host generates/derives/resolves them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum KeyMode {
    /// Fresh random secret (AUD-024 — never derivable from old keys).
    Fresh,
    /// Forward derivation from the local key at `from_epoch` (legacy chain).
    Derive {
        #[serde(rename = "fromEpoch")]
        from_epoch: u32,
    },
}

/// One I/O step the host must perform for the pending action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RotationAction {
    /// Revoke the removed member's UCANs (removal runs only).
    RevokeUcans,
    /// Generate or derive the target-epoch key and hold it run-locally.
    GenerateKey { epoch: u32, mode: KeyMode },
    /// Try to resolve a distributed key share for the epoch.
    ResolveShare { epoch: u32 },
    /// Advance the server epoch (CAS). `set_min_epoch` skips the grace
    /// period (removal runs only).
    AdvanceEpoch {
        epoch: u32,
        #[serde(rename = "setMinEpoch")]
        set_min_epoch: bool,
    },
    /// Read the membership log under the current (pre-rotation) key so its
    /// payloads can be re-encrypted after the key swap (shared, non-removal
    /// runs only).
    ReadLog,
    /// Distribute the new key as wrapped shares to the active members
    /// (shared spaces only).
    DistributeShares { epoch: u32 },
    /// Re-wrap all DEKs from `from_epoch` to `to_epoch`. `fresh_key`
    /// means the target key is not forward-derivable from the source (fresh
    /// random or resolved share): the key cache holds exactly the two
    /// endpoints and no intermediate epoch is materialized.
    RewrapDeks {
        #[serde(rename = "fromEpoch")]
        from_epoch: u32,
        #[serde(rename = "toEpoch")]
        to_epoch: u32,
        #[serde(rename = "freshKey")]
        fresh_key: bool,
    },
    /// Signal the server that the rewrap is complete.
    SignalComplete { epoch: u32 },
    /// Commit the new epoch locally (swap key material, persist the record).
    CommitLocal { epoch: u32 },
    /// Re-encrypt the membership log under the new key (shared spaces).
    ReencryptLog { epoch: u32 },
    /// Append the removal entries to the re-encrypted log (removal runs
    /// only).
    AppendRemovalEntries { epoch: u32 },
    /// Send the revocation notice to the removed member's mailbox (removal
    /// runs only; a no-op when the member had no known contact).
    SendRevocationNotice { epoch: u32 },
    /// D-005: a derived completion landed while the deferred re-rotation
    /// pass was running — give up loudly (the host logs an error and the
    /// admin must rotate again).
    GiveUp,
    /// D-005: a derived completion landed while a follow-up rotation was in
    /// flight — defer exactly one pass (the host logs a warning).
    Defer,
    /// The run is finished — the host stops consuming actions.
    Done,
}

/// The host's result for the pending action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RotationEvent {
    /// The pending action completed successfully (every action except
    /// `advanceEpoch`, which reports [`RotationEvent::AdvanceConflict`] on
    /// a lost CAS race).
    StepDone,
    /// `advanceEpoch` lost its CAS race. `server_epoch` is the server's
    /// actual epoch; `rewrap_epoch` set means another device is mid-rewrap.
    AdvanceConflict {
        #[serde(rename = "serverEpoch")]
        server_epoch: u32,
        #[serde(rename = "rewrapEpoch")]
        rewrap_epoch: Option<u32>,
    },
    /// Result of a `resolveShare`: `has_share` is true when a wrapped
    /// distributed key share was resolved.
    ShareResult {
        #[serde(rename = "hasShare")]
        has_share: bool,
    },
    /// The host failed to execute the pending action (transport error, db
    /// failure, ...). The machine decides containment: a failure inside a
    /// D-005 follow-up frame is discarded and the run continues; any other
    /// failure aborts the run.
    ActionFailed,
}

/// Input to [`RotationState::start`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationSpec {
    pub kind: RotationKind,
    /// The device's local epoch for the space — authoritative (the host
    /// passes its own view; the machine re-syncs to it on every start).
    pub current_epoch: u32,
    /// Shared space (UCAN-based, member key shares) vs. personal.
    pub shared: bool,
    /// Required for `kind = interrupted`: the server's `rewrapEpoch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrap_epoch: Option<u32>,
    /// Required for `kind = adopt`: the server epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_epoch: Option<u32>,
}

impl std::fmt::Display for RotationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RotationKind::Scheduled => "Scheduled",
            RotationKind::Removal => "Removal",
            RotationKind::Interrupted => "Interrupted",
            RotationKind::Adopt => "Adopt",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RotationError {
    #[error("rotation run already in flight")]
    Busy,
    #[error("no rotation run in flight")]
    NotStarted,
    #[error("invalid rotation spec for {kind}: {reason}")]
    InvalidSpec {
        kind: RotationKind,
        reason: &'static str,
    },
    #[error("unexpected event {got} for action {action}")]
    UnexpectedEvent {
        got: &'static str,
        action: &'static str,
    },
    #[error(
        "advance conflict without a pending rewrap — cannot proceed (server at epoch {server_epoch})"
    )]
    AdvanceFailed { server_epoch: u32 },
    #[error("revocation advance failed after retry (server at epoch {server_epoch})")]
    RemovalAdvanceFailed { server_epoch: u32 },
    #[error("rotation action {action} failed")]
    ActionFailed { action: &'static str },
    #[error("epoch overflow: cannot advance beyond u32::MAX")]
    EpochOverflow,
}

/// One in-flight rotation frame (innermost = top of the stack).
///
/// Opaque to the host; serialized with the state so it round-trips through
/// the wasm boundary verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Frame {
    kind: RotationKind,
    /// Target epoch of this run.
    target_epoch: u32,
    /// Resolved key source (`None` until `generateKey`; stays `None` for a
    /// share-resolved completion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_mode: Option<KeyMode>,
    /// Completion runs: whether the target key came from a distributed
    /// share. `Some(false)` = derived — the D-005 trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    share: Option<bool>,
    /// D-005: this scheduled frame is a fresh follow-up rotation.
    #[serde(default)]
    is_followup: bool,
    /// Removal runs: failed `advanceEpoch` attempts so far (the retry is
    /// bounded to one — a persistently conflicting server must not spin the
    /// machinery; pre-port behavior retried exactly once and propagated).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    advance_attempts: u32,
    /// The phase the frame moves to once the pending `readLog` completes
    /// (all other phases: the frame's current phase).
    #[serde(default)]
    after_read_log: Option<Phase>,
    phase: Phase,
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Phase {
    RevokeUcans,
    GenerateKey,
    Advance,
    ResolveShare,
    ReadLog,
    DistributeShares,
    Rewrap,
    Complete,
    Commit,
    AppendRemoval,
    SendNotice,
    ReencryptLog,
}

/// The canonical rotation state machine (one instance per space, persisted
/// across runs via its D-005 flags).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationState {
    /// The device's local epoch for this space (advances on `commitLocal`).
    pub current_epoch: u32,
    pub shared: bool,
    /// D-005 follow-up guard (persists across runs — it is what bounds the
    /// loop):
    /// - `followup_active`: a fresh follow-up rotation is in flight.
    /// - `followup_pending`: a derived completion landed while one was in
    ///   flight — run exactly one deferred pass when it finishes.
    /// - `followup_deferred`: the deferred pass is running — a further
    ///   derived completion gives up instead of chaining another pass.
    #[serde(default)]
    pub followup_active: bool,
    #[serde(default)]
    pub followup_pending: bool,
    #[serde(default)]
    pub followup_deferred: bool,
    /// The next action for the host; `null` when idle.
    #[serde(default)]
    pub action: Option<RotationAction>,
    /// In-flight frames (innermost last). Opaque to the host.
    #[serde(default)]
    stack: Vec<Frame>,
}

impl RotationState {
    /// A fresh machine for a space (no run in flight).
    pub fn new(current_epoch: u32, shared: bool) -> Self {
        Self {
            current_epoch,
            shared,
            followup_active: false,
            followup_pending: false,
            followup_deferred: false,
            action: None,
            stack: Vec::new(),
        }
    }

    /// No run in flight.
    pub fn is_idle(&self) -> bool {
        self.stack.is_empty()
    }

    /// Start a run. The host's `spec.current_epoch`/`spec.shared` are
    /// authoritative — the machine re-syncs to them on every start. Fails
    /// with [`RotationError::Busy`] if a run is already in flight.
    pub fn start(&mut self, spec: &RotationSpec) -> Result<(), RotationError> {
        if !self.stack.is_empty() {
            return Err(RotationError::Busy);
        }
        self.current_epoch = spec.current_epoch;
        self.shared = spec.shared;
        let current = spec.current_epoch;

        match spec.kind {
            RotationKind::Scheduled => {
                let mode = if spec.shared {
                    KeyMode::Fresh
                } else {
                    KeyMode::Derive {
                        from_epoch: current,
                    }
                };
                let target = next_epoch(current)?;
                let mut frame = Frame {
                    kind: spec.kind,
                    target_epoch: target,
                    key_mode: Some(mode),
                    share: None,
                    is_followup: false,
                    advance_attempts: 0,
                    after_read_log: None,
                    phase: Phase::GenerateKey,
                };
                if spec.shared {
                    // Read the membership log under the pre-rotation key
                    // before the swap (its payloads are re-encrypted after
                    // commit).
                    frame.after_read_log = Some(Phase::GenerateKey);
                    frame.phase = Phase::ReadLog;
                    self.action = Some(RotationAction::ReadLog);
                } else {
                    self.action = Some(RotationAction::GenerateKey {
                        epoch: target,
                        mode,
                    });
                }
                self.stack.push(frame);
            }
            RotationKind::Removal => {
                let target = next_epoch(current)?;
                self.stack.push(Frame {
                    kind: spec.kind,
                    target_epoch: target,
                    key_mode: Some(KeyMode::Fresh),
                    share: None,
                    is_followup: false,
                    advance_attempts: 0,
                    after_read_log: None,
                    phase: Phase::RevokeUcans,
                });
                self.action = Some(RotationAction::RevokeUcans);
            }
            RotationKind::Interrupted => {
                let rewrap = spec.rewrap_epoch.ok_or(RotationError::InvalidSpec {
                    kind: spec.kind,
                    reason: "missing rewrapEpoch",
                })?;
                if rewrap <= current {
                    // Already at or past the rewrap epoch — nothing to do.
                    self.action = Some(RotationAction::Done);
                } else {
                    let mut frame = Frame {
                        kind: spec.kind,
                        target_epoch: rewrap,
                        key_mode: None,
                        share: None,
                        is_followup: false,
                        advance_attempts: 0,
                        after_read_log: None,
                        phase: Phase::ResolveShare,
                    };
                    if spec.shared {
                        // Collect the log under the old key first (needed to
                        // re-encrypt it after the completion commits).
                        frame.after_read_log = Some(Phase::ResolveShare);
                        frame.phase = Phase::ReadLog;
                        self.action = Some(RotationAction::ReadLog);
                    } else {
                        self.action = Some(RotationAction::ResolveShare { epoch: rewrap });
                    }
                    self.stack.push(frame);
                }
            }
            RotationKind::Adopt => {
                let server = spec.server_epoch.ok_or(RotationError::InvalidSpec {
                    kind: spec.kind,
                    reason: "missing serverEpoch",
                })?;
                if server <= current {
                    self.action = Some(RotationAction::Done);
                } else {
                    self.stack.push(Frame {
                        kind: spec.kind,
                        target_epoch: server,
                        key_mode: None,
                        share: None,
                        is_followup: false,
                        advance_attempts: 0,
                        after_read_log: None,
                        phase: Phase::ResolveShare,
                    });
                    self.action = Some(RotationAction::ResolveShare { epoch: server });
                }
            }
        }
        Ok(())
    }

    /// Consume the host's result for the pending action, advancing the
    /// machine. Returns an error on protocol violations (host bug) or
    /// unrecoverable conditions (a removal whose advance conflicts with no
    /// rewrap to complete) — the host should [`RotationState::abort`] and
    /// stop the run.
    pub fn step(&mut self, event: &RotationEvent) -> Result<(), RotationError> {
        let action = self.action.clone().ok_or(RotationError::NotStarted)?;
        if matches!(action, RotationAction::Done) {
            return Err(RotationError::UnexpectedEvent {
                got: event_name(event),
                action: "done",
            });
        }
        match (&action, event) {
            (
                RotationAction::AdvanceEpoch { .. },
                RotationEvent::AdvanceConflict {
                    server_epoch,
                    rewrap_epoch,
                },
            ) => self.advance_conflict(*server_epoch, *rewrap_epoch),
            (RotationAction::ResolveShare { .. }, RotationEvent::ShareResult { has_share }) => {
                self.share_result(*has_share)
            }
            (action, RotationEvent::ActionFailed) => self.action_failed(action),
            (action, RotationEvent::StepDone) => self.step_done(action),
            (action, other) => Err(RotationError::UnexpectedEvent {
                got: event_name(other),
                action: action_name(action),
            }),
        }
    }

    /// Host failure for the pending action. Containment is decided by the
    /// machine: a failed D-005 follow-up frame is discarded (the committed
    /// completion stands) and the run continues with the parent; any other
    /// failure aborts the run.
    fn action_failed(&mut self, action: &RotationAction) -> Result<(), RotationError> {
        let is_followup = self.top_mut().is_followup;
        if !is_followup {
            self.abort();
            return Err(RotationError::ActionFailed {
                action: action_name(action),
            });
        }
        self.finish_frame()
    }

    /// Abort a run (host failure). Clears the in-flight frames and the
    /// `followup_active` flag; `current_epoch` (committed progress) and the
    /// `pending`/`deferred` flags are kept — worst case the next completion
    /// runs one extra bounded pass, never a loop.
    pub fn abort(&mut self) {
        self.stack.clear();
        self.followup_active = false;
        self.action = None;
    }

    fn step_done(&mut self, action: &RotationAction) -> Result<(), RotationError> {
        match action {
            RotationAction::RevokeUcans => {
                let epoch = self.top_mut().target_epoch;
                self.top_mut().phase = Phase::GenerateKey;
                self.action = Some(RotationAction::GenerateKey {
                    epoch,
                    mode: KeyMode::Fresh,
                });
            }
            RotationAction::GenerateKey { epoch: _, mode } => {
                self.top_mut().key_mode = Some(*mode);
                let (kind, epoch) = {
                    let frame = self.top_mut();
                    (frame.kind, frame.target_epoch)
                };
                match kind {
                    // Completion runs: the key is ready — rewrap (interrupted)
                    // or commit (adopt).
                    RotationKind::Interrupted => self.begin_rewrap()?,
                    RotationKind::Adopt => {
                        self.top_mut().phase = Phase::Commit;
                        self.action = Some(RotationAction::CommitLocal { epoch });
                    }
                    // Rotation runs (scheduled / follow-up / removal):
                    // advance the server epoch.
                    _ => {
                        self.top_mut().phase = Phase::Advance;
                        self.action = Some(RotationAction::AdvanceEpoch {
                            epoch,
                            set_min_epoch: kind == RotationKind::Removal,
                        });
                    }
                }
            }
            RotationAction::ResolveShare { .. } => {
                unreachable!("resolveShare is driven by a shareResult event")
            }
            RotationAction::AdvanceEpoch { epoch, .. } => {
                self.advance_ok(*epoch)?;
            }
            RotationAction::ReadLog => {
                let (next_phase, epoch, key_mode) = {
                    let frame = self.top_mut();
                    let next_phase = frame
                        .after_read_log
                        .expect("readLog emitted with after_read_log set");
                    frame.phase = next_phase;
                    (next_phase, frame.target_epoch, frame.key_mode)
                };
                match next_phase {
                    Phase::GenerateKey => {
                        let mode = key_mode.expect("rotation key mode set at start");
                        self.action = Some(RotationAction::GenerateKey { epoch, mode });
                    }
                    Phase::ResolveShare => {
                        self.action = Some(RotationAction::ResolveShare { epoch });
                    }
                    Phase::DistributeShares => {
                        self.action = Some(RotationAction::DistributeShares { epoch });
                    }
                    _ => unreachable!("readLog next phase"),
                }
            }
            RotationAction::DistributeShares { .. } => {
                self.begin_rewrap()?;
            }
            RotationAction::RewrapDeks { .. } => {
                let epoch = self.top_mut().target_epoch;
                self.top_mut().phase = Phase::Complete;
                self.action = Some(RotationAction::SignalComplete { epoch });
            }
            RotationAction::SignalComplete { .. } => {
                let (kind, epoch) = {
                    let frame = self.top_mut();
                    (frame.kind, frame.target_epoch)
                };
                if kind == RotationKind::Removal {
                    self.top_mut().phase = Phase::AppendRemoval;
                    self.action = Some(RotationAction::AppendRemovalEntries { epoch });
                } else {
                    self.top_mut().phase = Phase::Commit;
                    self.action = Some(RotationAction::CommitLocal { epoch });
                }
            }
            RotationAction::AppendRemovalEntries { .. } => {
                let epoch = self.top_mut().target_epoch;
                self.top_mut().phase = Phase::SendNotice;
                self.action = Some(RotationAction::SendRevocationNotice { epoch });
            }
            RotationAction::SendRevocationNotice { .. } => {
                let epoch = self.top_mut().target_epoch;
                self.top_mut().phase = Phase::Commit;
                self.action = Some(RotationAction::CommitLocal { epoch });
            }
            RotationAction::CommitLocal { epoch } => {
                self.current_epoch = *epoch;
                let shared = self.shared;
                let (kind, epoch) = {
                    let frame = self.top_mut();
                    (frame.kind, frame.target_epoch)
                };
                match kind {
                    RotationKind::Removal | RotationKind::Adopt => {
                        self.finish_frame()?;
                    }
                    _ => {
                        if shared {
                            self.top_mut().phase = Phase::ReencryptLog;
                            self.action = Some(RotationAction::ReencryptLog { epoch });
                        } else {
                            self.finish_frame()?;
                        }
                    }
                }
            }
            RotationAction::ReencryptLog { .. } => {
                let derived_completion = {
                    let frame = self.top_mut();
                    frame.kind == RotationKind::Interrupted && frame.share == Some(false)
                };
                if derived_completion && self.shared {
                    // D-005: a derived completion must be followed by a
                    // fresh re-rotation.
                    self.followup_check()?;
                } else {
                    self.finish_frame()?;
                }
            }
            RotationAction::GiveUp | RotationAction::Defer => {
                self.finish_frame()?;
            }
            RotationAction::Done => unreachable!("checked in step()"),
        }
        Ok(())
    }

    /// Shared spaces: read the log (unless a removal — its log state came
    /// from the pre-run fold), then distribute shares. Personal: straight
    /// to the rewrap.
    fn advance_ok(&mut self, epoch: u32) -> Result<(), RotationError> {
        if !self.shared {
            return self.begin_rewrap();
        }
        let is_removal = self.top_mut().kind == RotationKind::Removal;
        if is_removal {
            self.action = Some(RotationAction::DistributeShares { epoch });
        } else {
            self.top_mut().phase = Phase::ReadLog;
            self.top_mut().after_read_log = Some(Phase::DistributeShares);
            self.action = Some(RotationAction::ReadLog);
        }
        Ok(())
    }

    fn begin_rewrap(&mut self) -> Result<(), RotationError> {
        // The target key is resolvable from the current key:
        // - fresh random (shared rotation, removal, follow-up) → endpoints only
        // - resolved share (interrupted) → endpoints only
        // - derived (personal rotation, derived completion) → whole chain
        let fresh_key = !matches!(self.top_mut().key_mode, Some(KeyMode::Derive { .. }));
        let to = self.top_mut().target_epoch;
        self.top_mut().phase = Phase::Rewrap;
        self.action = Some(RotationAction::RewrapDeks {
            from_epoch: self.current_epoch,
            to_epoch: to,
            fresh_key,
        });
        Ok(())
    }

    fn share_result(&mut self, has_share: bool) -> Result<(), RotationError> {
        let current = self.current_epoch;
        self.top_mut().share = Some(has_share);
        if has_share {
            let (kind, epoch) = {
                let frame = self.top_mut();
                (frame.kind, frame.target_epoch)
            };
            if kind == RotationKind::Adopt {
                self.top_mut().phase = Phase::Commit;
                self.action = Some(RotationAction::CommitLocal { epoch });
            } else {
                self.begin_rewrap()?;
            }
        } else {
            // No share: legacy epoch — derive the target key forward from
            // the current one.
            let mode = KeyMode::Derive {
                from_epoch: current,
            };
            let epoch = self.top_mut().target_epoch;
            self.top_mut().key_mode = Some(mode);
            self.top_mut().phase = Phase::GenerateKey;
            self.action = Some(RotationAction::GenerateKey { epoch, mode });
        }
        Ok(())
    }

    fn advance_conflict(
        &mut self,
        server_epoch: u32,
        rewrap_epoch: Option<u32>,
    ) -> Result<(), RotationError> {
        let current = self.current_epoch;
        let kind = self.top_mut().kind;
        match kind {
            RotationKind::Removal => {
                // Bound the retry: a persistently conflicting server must
                // not spin the machinery (pre-port retried exactly once).
                self.top_mut().advance_attempts += 1;
                if self.top_mut().advance_attempts >= 2 {
                    self.stack.clear();
                    self.followup_active = false;
                    self.action = None;
                    return Err(RotationError::RemovalAdvanceFailed { server_epoch });
                }
                match rewrap_epoch {
                    Some(r) if r > current => {
                        // Another device is mid-rewrap: complete it, then
                        // retry the revocation advance on top of it.
                        self.push_completion(RotationKind::Interrupted, r);
                    }
                    Some(_) => {
                        // The server is already at/past the rewrap epoch — the
                        // completion would be a no-op; retry the revocation
                        // advance on top of the current epoch.
                        self.retry_removal_advance()?;
                    }
                    None => {
                        // No rewrap to complete, no fresh key on top — the
                        // removal cannot proceed.
                        self.stack.clear();
                        self.followup_active = false;
                        self.action = None;
                        return Err(RotationError::AdvanceFailed { server_epoch });
                    }
                }
            }
            RotationKind::Scheduled => match rewrap_epoch {
                Some(r) if r > current => {
                    // Help finish it; the run stops once the completion
                    // lands (the space has already moved forward).
                    self.push_completion(RotationKind::Interrupted, r);
                }
                Some(_) => {
                    // No-op completion — stop (mirrors the pre-port
                    // behavior: no retry, no adopt).
                    self.finish_frame()?;
                }
                None => {
                    // Another device completed everything — adopt its epoch.
                    if server_epoch > current {
                        self.push_completion(RotationKind::Adopt, server_epoch);
                    } else {
                        self.finish_frame()?;
                    }
                }
            },
            // Completions (interrupted/adopt) never advance.
            _ => unreachable!("advance conflict on a completion frame"),
        }
        Ok(())
    }

    fn push_completion(&mut self, kind: RotationKind, target: u32) {
        let mut frame = Frame {
            kind,
            target_epoch: target,
            key_mode: None,
            share: None,
            is_followup: false,
            advance_attempts: 0,
            after_read_log: None,
            phase: Phase::ResolveShare,
        };
        if kind == RotationKind::Interrupted && self.shared {
            frame.after_read_log = Some(Phase::ResolveShare);
            frame.phase = Phase::ReadLog;
            self.action = Some(RotationAction::ReadLog);
        } else {
            self.action = Some(RotationAction::ResolveShare { epoch: target });
        }
        self.stack.push(frame);
    }

    /// Removal only: retry the revocation advance on top of the current
    /// (possibly just-committed) epoch with a fresh key.
    fn retry_removal_advance(&mut self) -> Result<(), RotationError> {
        let target = next_epoch(self.current_epoch)?;
        let frame = self.top_mut();
        frame.target_epoch = target;
        frame.key_mode = Some(KeyMode::Fresh);
        frame.phase = Phase::GenerateKey;
        self.action = Some(RotationAction::GenerateKey {
            epoch: target,
            mode: KeyMode::Fresh,
        });
        Ok(())
    }

    /// D-005 decision after a derived completion (see the module docs).
    fn followup_check(&mut self) -> Result<(), RotationError> {
        if self.followup_deferred {
            // A deferred pass is running and its completion also landed on a
            // derived epoch: give up loudly — the bound is one extra pass.
            self.followup_pending = false;
            self.action = Some(RotationAction::GiveUp);
        } else if self.followup_active {
            // A follow-up is in flight: defer exactly one pass.
            self.followup_pending = true;
            self.action = Some(RotationAction::Defer);
        } else {
            // Clean start: run the fresh follow-up rotation.
            self.followup_active = true;
            self.start_followup()?;
        }
        Ok(())
    }

    /// Spawn a D-005 fresh follow-up rotation (AUD-024 — random, never
    /// derivable) on top of the just-committed epoch.
    fn start_followup(&mut self) -> Result<(), RotationError> {
        let target = next_epoch(self.current_epoch)?;
        let mut frame = Frame {
            kind: RotationKind::Scheduled,
            target_epoch: target,
            key_mode: Some(KeyMode::Fresh),
            share: None,
            is_followup: true,
            advance_attempts: 0,
            after_read_log: None,
            phase: Phase::GenerateKey,
        };
        if self.shared {
            frame.after_read_log = Some(Phase::GenerateKey);
            frame.phase = Phase::ReadLog;
            self.action = Some(RotationAction::ReadLog);
        } else {
            self.action = Some(RotationAction::GenerateKey {
                epoch: target,
                mode: KeyMode::Fresh,
            });
        }
        self.stack.push(frame);
        Ok(())
    }

    /// Finish the top frame, honoring the D-005 deferred-pass bookkeeping
    /// for follow-up frames, then continue with the parent (a removal
    /// retries its advance; anything else unwinds to `Done`).
    fn finish_frame(&mut self) -> Result<(), RotationError> {
        let frame = self.stack.pop().expect("finish_frame: empty stack");
        if frame.is_followup {
            self.followup_active = false;
            if self.followup_pending {
                // Consume the deferral: run the fresh re-rotation exactly
                // once more (the deferred pass).
                self.followup_pending = false;
                self.followup_deferred = true;
                return self.start_followup();
            }
        }
        let parent_is_removal =
            matches!(self.stack.last(), Some(f) if f.kind == RotationKind::Removal);
        if self.stack.is_empty() {
            // A deferral was recorded but no follow-up frame survived to
            // consume it (crash/abort residue in the host's flags): run the
            // promised deferred pass now instead of dropping it. Bounded by
            // `followup_deferred` — it cannot chain another deferral.
            if self.followup_pending && !self.followup_deferred {
                self.followup_pending = false;
                self.followup_deferred = true;
                return self.start_followup();
            }
            // The run completed: D-005 bookkeeping is per-run (the pre-port
            // follow-up guard was in-memory). Flags survive only when a run
            // is interrupted (crash) — there they bound the next run; a
            // completed run starts the next cycle clean.
            self.followup_active = false;
            self.followup_pending = false;
            self.followup_deferred = false;
            self.action = Some(RotationAction::Done);
            return Ok(());
        }
        if parent_is_removal {
            return self.retry_removal_advance();
        }
        self.finish_frame()
    }

    fn top_mut(&mut self) -> &mut Frame {
        self.stack.last_mut().expect("step: no frame in flight")
    }
}

fn next_epoch(current: u32) -> Result<u32, RotationError> {
    current.checked_add(1).ok_or(RotationError::EpochOverflow)
}

fn action_name(action: &RotationAction) -> &'static str {
    match action {
        RotationAction::RevokeUcans => "revokeUcans",
        RotationAction::GenerateKey { .. } => "generateKey",
        RotationAction::ResolveShare { .. } => "resolveShare",
        RotationAction::AdvanceEpoch { .. } => "advanceEpoch",
        RotationAction::ReadLog => "readLog",
        RotationAction::DistributeShares { .. } => "distributeShares",
        RotationAction::RewrapDeks { .. } => "rewrapDeks",
        RotationAction::SignalComplete { .. } => "signalComplete",
        RotationAction::CommitLocal { .. } => "commitLocal",
        RotationAction::ReencryptLog { .. } => "reencryptLog",
        RotationAction::AppendRemovalEntries { .. } => "appendRemovalEntries",
        RotationAction::SendRevocationNotice { .. } => "sendRevocationNotice",
        RotationAction::GiveUp => "giveUp",
        RotationAction::Defer => "defer",
        RotationAction::Done => "done",
    }
}

fn event_name(event: &RotationEvent) -> &'static str {
    match event {
        RotationEvent::StepDone => "stepDone",
        RotationEvent::AdvanceConflict { .. } => "advanceConflict",
        RotationEvent::ShareResult { .. } => "shareResult",
        RotationEvent::ActionFailed => "actionFailed",
    }
}

/// Whether a space's epoch key is due for scheduled rotation.
///
/// Mirrors the client policy exactly:
/// - Only admins rotate (the server rejects non-admin advances anyway).
/// - A missing/invalid/zero `advanced_at` reads as "not due" — never as
///   epoch zero: `now - null` ≈ 1.8e12 ms would rotate every fresh device
///   instantly.
/// - The interval is inclusive (`now - advanced_at >= interval`).
///
/// `now_ms` and `advanced_at_ms` are wall-clock milliseconds. The host must
/// pass `None` for missing or non-finite values (an `i64` cannot carry a
/// `NaN` sentinel through the wasm boundary).
pub fn should_rotate(
    now_ms: i64,
    advanced_at_ms: Option<i64>,
    is_admin: bool,
    interval_ms: i64,
) -> bool {
    if !is_admin {
        return false;
    }
    let Some(advanced_at) = advanced_at_ms.filter(|&v| v > 0) else {
        return false;
    };
    now_ms - advanced_at >= interval_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../test-vectors/rotation.json");

    #[derive(Deserialize)]
    struct VectorFile {
        cases: Vec<VectorCase>,
    }

    #[derive(Deserialize)]
    struct InitialFlags {
        #[serde(default, rename = "followupActive")]
        followup_active: bool,
        #[serde(default, rename = "followupPending")]
        followup_pending: bool,
        #[serde(default, rename = "followupDeferred")]
        followup_deferred: bool,
    }

    #[derive(Deserialize)]
    struct VectorCase {
        name: String,
        start: RotationSpec,
        /// D-005 bookkeeping carried into the run (crash/abort residue).
        #[serde(default, rename = "initialFlags")]
        initial_flags: Option<InitialFlags>,
        #[serde(default)]
        actions: Vec<RotationAction>,
        /// One event per non-terminal action; the final `done` action
        /// consumes none.
        #[serde(default)]
        events: Vec<RotationEvent>,
        #[serde(default, rename = "finalState")]
        final_state: Option<serde_json::Value>,
        #[serde(default)]
        error: Option<String>,
        #[serde(default, rename = "startError")]
        start_error: Option<String>,
    }

    fn expected_final(state: &RotationState) -> serde_json::Value {
        // Full wire shape — the vectors pin the entire machine state
        // (including D-005 flags and the done marker), not just a subset.
        serde_json::to_value(state).expect("state serializes")
    }

    #[test]
    fn conformance_vectors() {
        let file: VectorFile = serde_json::from_str(VECTORS).expect("vector file parses");
        assert!(!file.cases.is_empty(), "vector file must not be empty");
        for case in &file.cases {
            let mut state = RotationState::new(case.start.current_epoch, case.start.shared);
            if let Some(flags) = &case.initial_flags {
                state.followup_active = flags.followup_active;
                state.followup_pending = flags.followup_pending;
                state.followup_deferred = flags.followup_deferred;
            }
            match state.start(&case.start) {
                Ok(()) => {}
                Err(e) => {
                    assert_eq!(
                        case.start_error.as_deref(),
                        Some(e.to_string().as_str()),
                        "vector '{}': start error drift (got {})",
                        case.name,
                        e
                    );
                    continue;
                }
            }
            assert!(
                case.start_error.is_none(),
                "vector '{}': unexpected start success",
                case.name
            );
            let mut errored: Option<String> = None;
            for (i, expected_action) in case.actions.iter().enumerate() {
                assert_eq!(
                    state.action.as_ref(),
                    Some(expected_action),
                    "vector '{}': action {} drift (expected {:?}, got {:?}) — mirror/wasm drift",
                    case.name,
                    i,
                    expected_action,
                    state.action
                );
                let Some(event) = case.events.get(i) else {
                    break; // terminal action — no further events
                };
                match state.step(event) {
                    Ok(()) => {}
                    Err(e) => {
                        errored = Some(e.to_string());
                        break;
                    }
                }
            }
            if let Some(expected_error) = &case.error {
                assert_eq!(
                    errored.as_deref(),
                    Some(expected_error.as_str()),
                    "vector '{}': error string drift",
                    case.name
                );
                if let Some(expected) = &case.final_state {
                    assert_eq!(
                        expected_final(&state),
                        *expected,
                        "vector '{}': error-case final state drift",
                        case.name
                    );
                }
                continue;
            }
            assert!(
                errored.is_none(),
                "vector '{}': unexpected error: {errored:?}",
                case.name
            );
            assert_eq!(
                state.action,
                Some(RotationAction::Done),
                "vector '{}': final action must be done",
                case.name
            );
            assert!(
                state.is_idle(),
                "vector '{}': must be idle at end",
                case.name
            );
            if let Some(expected) = &case.final_state {
                assert_eq!(
                    expected_final(&state),
                    *expected,
                    "vector '{}': final state drift",
                    case.name
                );
            }
        }
    }

    // --- wire-format pins (the JSON vectors rely on these exact names) ---

    #[test]
    fn action_wire_format() {
        assert_eq!(
            serde_json::to_string(&RotationAction::RevokeUcans).unwrap(),
            r#"{"type":"revokeUcans"}"#
        );
        assert_eq!(
            serde_json::to_string(&RotationAction::GenerateKey {
                epoch: 4,
                mode: KeyMode::Derive { from_epoch: 3 }
            })
            .unwrap(),
            r#"{"type":"generateKey","epoch":4,"mode":{"type":"derive","fromEpoch":3}}"#
        );
        assert_eq!(
            serde_json::to_string(&RotationAction::AdvanceEpoch {
                epoch: 6,
                set_min_epoch: true
            })
            .unwrap(),
            r#"{"type":"advanceEpoch","epoch":6,"setMinEpoch":true}"#
        );
        assert_eq!(
            serde_json::to_string(&RotationAction::RewrapDeks {
                from_epoch: 5,
                to_epoch: 6,
                fresh_key: true
            })
            .unwrap(),
            r#"{"type":"rewrapDeks","fromEpoch":5,"toEpoch":6,"freshKey":true}"#
        );
        assert_eq!(
            serde_json::to_string(&RotationEvent::AdvanceConflict {
                server_epoch: 6,
                rewrap_epoch: None
            })
            .unwrap(),
            r#"{"type":"advanceConflict","serverEpoch":6,"rewrapEpoch":null}"#
        );
        assert_eq!(
            serde_json::to_string(&RotationEvent::ShareResult { has_share: true }).unwrap(),
            r#"{"type":"shareResult","hasShare":true}"#
        );
        assert_eq!(
            serde_json::to_string(&RotationEvent::ActionFailed).unwrap(),
            r#"{"type":"actionFailed"}"#
        );
    }

    #[test]
    fn state_round_trips_through_json() {
        let mut state = RotationState::new(5, true);
        state
            .start(&RotationSpec {
                kind: RotationKind::Scheduled,
                current_epoch: 5,
                shared: true,
                rewrap_epoch: None,
                server_epoch: None,
            })
            .unwrap();
        let raw = serde_json::to_string(&state).unwrap();
        let back: RotationState = serde_json::from_str(&raw).unwrap();
        assert_eq!(state, back);
    }

    // --- should_rotate pins ---

    #[test]
    fn should_rotate_policy() {
        const INTERVAL: i64 = 60_000;
        const NOW: i64 = 100_000;
        // Non-admin never rotates.
        assert!(!should_rotate(NOW, Some(NOW - INTERVAL), false, INTERVAL));
        // Missing/zero/negative advancedAt never rotates (never treated as
        // epoch zero).
        assert!(!should_rotate(NOW, None, true, INTERVAL));
        assert!(!should_rotate(NOW, Some(0), true, INTERVAL));
        assert!(!should_rotate(NOW, Some(-5), true, INTERVAL));
        // Exact interval is due (inclusive).
        assert!(should_rotate(NOW, Some(NOW - INTERVAL), true, INTERVAL));
        // One ms short is not.
        assert!(!should_rotate(
            NOW,
            Some(NOW - INTERVAL + 1),
            true,
            INTERVAL
        ));
        // Future advancedAt (clock skew) is not due.
        assert!(!should_rotate(NOW, Some(NOW + 100), true, INTERVAL));
    }

    // --- machine edge cases ---

    fn spec(kind: RotationKind, epoch: u32, shared: bool) -> RotationSpec {
        RotationSpec {
            kind,
            current_epoch: epoch,
            shared,
            rewrap_epoch: None,
            server_epoch: None,
        }
    }

    #[test]
    fn step_while_idle_errors() {
        let mut state = RotationState::new(1, true);
        let err = state.step(&RotationEvent::StepDone).unwrap_err();
        assert_eq!(err, RotationError::NotStarted);
    }

    #[test]
    fn start_while_busy_errors() {
        let mut state = RotationState::new(1, true);
        state
            .start(&spec(RotationKind::Scheduled, 1, true))
            .unwrap();
        let err = state
            .start(&spec(RotationKind::Scheduled, 1, true))
            .unwrap_err();
        assert_eq!(err, RotationError::Busy);
    }

    #[test]
    fn missing_kind_fields_error() {
        let mut state = RotationState::new(1, true);
        assert_eq!(
            state
                .start(&spec(RotationKind::Interrupted, 1, true))
                .unwrap_err(),
            RotationError::InvalidSpec {
                kind: RotationKind::Interrupted,
                reason: "missing rewrapEpoch",
            }
        );
        assert_eq!(
            state
                .start(&spec(RotationKind::Adopt, 1, true))
                .unwrap_err(),
            RotationError::InvalidSpec {
                kind: RotationKind::Adopt,
                reason: "missing serverEpoch",
            }
        );
    }

    #[test]
    fn wrong_event_type_errors() {
        let mut state = RotationState::new(1, false);
        state
            .start(&spec(RotationKind::Scheduled, 1, false))
            .unwrap();
        let err = state
            .step(&RotationEvent::ShareResult { has_share: true })
            .unwrap_err();
        assert_eq!(
            err,
            RotationError::UnexpectedEvent {
                got: "shareResult",
                action: "generateKey",
            }
        );
    }

    #[test]
    fn step_after_done_errors() {
        let mut state = RotationState::new(3, true);
        let mut s = spec(RotationKind::Interrupted, 3, true);
        s.rewrap_epoch = Some(3); // no-op completion
        state.start(&s).unwrap();
        assert_eq!(state.action, Some(RotationAction::Done));
        let err = state.step(&RotationEvent::StepDone).unwrap_err();
        assert_eq!(
            err,
            RotationError::UnexpectedEvent {
                got: "stepDone",
                action: "done",
            }
        );
    }

    #[test]
    fn abort_clears_run_but_keeps_progress() {
        let mut state = RotationState::new(5, true);
        let mut s = spec(RotationKind::Interrupted, 5, true);
        s.rewrap_epoch = Some(6);
        state.start(&s).unwrap();
        state.step(&RotationEvent::StepDone).unwrap(); // readLog
        state
            .step(&RotationEvent::ShareResult { has_share: false })
            .unwrap();
        state.abort();
        assert!(state.is_idle());
        assert_eq!(state.current_epoch, 5);
        assert!(!state.followup_active);
        // A fresh start re-syncs and proceeds.
        state
            .start(&spec(RotationKind::Scheduled, 5, true))
            .unwrap();
        assert!(matches!(state.action, Some(RotationAction::ReadLog)));
    }

    #[test]
    fn epoch_overflow_is_bounded() {
        let mut state = RotationState::new(u32::MAX, false);
        let err = state
            .start(&spec(RotationKind::Scheduled, u32::MAX, false))
            .unwrap_err();
        assert_eq!(err, RotationError::EpochOverflow);
    }
}
