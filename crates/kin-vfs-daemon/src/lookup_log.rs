// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-lookup diagnostics for the VFS daemon.
//!
//! A production incident turned on a question the daemon could not answer: it
//! reported "not in graph" for a path the graph demonstrably held, and nothing
//! in `kin-vfs-daemon.log` named the path, the outcome, or the endpoint the
//! provider was dialing at the time. The whole failure had to be reconstructed
//! from a proof harness's redirect files.
//!
//! So every path-bearing request is recorded here, with the path, the operation,
//! how it was answered, and which backend answered it.
//!
//! Volume is the reason this is not simply `info!` on every lookup. An editor or
//! a build walks thousands of paths, and a log nobody can read is not a
//! diagnostic. The rule instead is: **every lookup at `debug`, and the first
//! lookup of each distinct outcome class at a visible level**. That bounds the
//! default-level output to at most one line per class per daemon lifetime (four
//! classes, so four lines), while `KIN_VFS_LOG=debug` still yields the full
//! per-lookup trace.
//!
//! The first *served* lookup is announced too, not only the failures. A log that
//! speaks only on failure cannot distinguish "the provider answered everything"
//! from "nothing ever asked", and that ambiguity is what made the incident
//! expensive.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use kin_vfs_core::protocol::{ErrorCode, VfsResponse};

/// How one lookup was answered, in the vocabulary an operator needs.
///
/// Deliberately coarser than [`ErrorCode`]: the question at incident time is
/// "did graph truth answer this, and if not, was the graph unavailable or did it
/// genuinely not hold the path" — not which errno the shim will synthesize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LookupOutcome {
    /// Graph truth answered.
    Served,
    /// The provider reached authority and authority does not hold this path.
    /// The interesting case: benign for a path that really is absent, and the
    /// exact shape of the incident when the path is one the graph owns.
    NotInGraph,
    /// The path exists but this operation is wrong for it (a directory read as a
    /// file, a gitlink boundary, a permission refusal). Not an authority
    /// failure, and not a miss.
    Boundary,
    /// Authority could not be consulted: transport failure, or the backend
    /// itself erroring. Distinguished from [`Self::NotInGraph`] because these
    /// two are what an operator must never have to guess between.
    AuthorityUnavailable,
}

impl LookupOutcome {
    /// Classify a response the daemon is about to send.
    pub(crate) fn of(response: &VfsResponse) -> Self {
        match response {
            VfsResponse::Error { code, .. } => match code {
                ErrorCode::NotFound => Self::NotInGraph,
                ErrorCode::IsDirectory
                | ErrorCode::NotDirectory
                | ErrorCode::PermissionDenied
                | ErrorCode::InvalidInput
                | ErrorCode::UnsupportedBoundary => Self::Boundary,
                ErrorCode::IoError | ErrorCode::Internal => Self::AuthorityUnavailable,
            },
            _ => Self::Served,
        }
    }

    /// Stable identifier for the log field. Not `Debug`, so renaming the variant
    /// cannot silently rename an operator-facing value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::NotInGraph => "not-in-graph",
            Self::Boundary => "boundary",
            Self::AuthorityUnavailable => "authority-unavailable",
        }
    }

    /// Bit this class occupies in the announcement latch.
    fn bit(self) -> u8 {
        match self {
            Self::Served => 1,
            Self::NotInGraph => 1 << 1,
            Self::Boundary => 1 << 2,
            Self::AuthorityUnavailable => 1 << 3,
        }
    }
}

/// Records which outcome classes have already been announced at a visible level.
///
/// One per daemon, so a second daemon in the same process (tests, a supervisor)
/// gets its own announcements rather than inheriting a latch another one
/// consumed.
#[derive(Debug, Default)]
pub(crate) struct LookupLog {
    announced: AtomicU8,
    recorded: AtomicU64,
}

impl LookupLog {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// How many lookups this daemon has recorded.
    ///
    /// The tracing output is the product; this counter is how a test asserts the
    /// dispatcher actually reaches [`Self::record`], since a log line that is
    /// never emitted looks exactly like a quiet run. Only the accessor is
    /// test-gated: the increment itself stays unconditional so the path a test
    /// measures is byte for byte the path production runs.
    #[cfg(test)]
    pub(crate) fn recorded(&self) -> u64 {
        self.recorded.load(Ordering::Relaxed)
    }

    /// Claim the first announcement for `outcome`, returning `true` to exactly
    /// one caller per class. Racing callers settle on one winner: the loser sees
    /// its bit already set in the value it swapped out.
    fn claim_announcement(&self, outcome: LookupOutcome) -> bool {
        let bit = outcome.bit();
        self.announced.fetch_or(bit, Ordering::Relaxed) & bit == 0
    }

    /// Record one path-bearing lookup.
    ///
    /// `op` names the request kind, `path` is the byte-exact path as the caller
    /// spelled it, and `endpoint` yields whatever backend the provider is
    /// currently dialing (absent for providers that have none).
    ///
    /// `endpoint` is a closure, not a value, because resolving it costs a lock
    /// and an allocation and this runs once per intercepted syscall. A build
    /// that stats a hundred thousand paths must not pay for a string nothing
    /// formats. It is called only when a line will actually be emitted.
    pub(crate) fn record(
        &self,
        op: &'static str,
        path: &str,
        outcome: LookupOutcome,
        endpoint: impl FnOnce() -> Option<String>,
    ) {
        self.recorded.fetch_add(1, Ordering::Relaxed);

        // Claim before the early return, and only skip when nothing would be
        // written: consuming a class's one announcement without emitting it
        // would silence the very line it exists to produce.
        let announcing = self.claim_announcement(outcome);
        // Level only, matching what `KIN_VFS_LOG` documents. A filter that
        // selected events by field rather than by level could enable the line
        // below while this check reads false; that is not a filter this daemon
        // offers, and paying a lock per syscall to cover it would cost more
        // than it buys.
        let tracing_debug = tracing::enabled!(tracing::Level::DEBUG);
        if !announcing && !tracing_debug {
            return;
        }

        let resolved = endpoint();
        let endpoint = resolved.as_deref().unwrap_or("none");
        if tracing_debug {
            tracing::debug!(op, path, outcome = outcome.as_str(), endpoint, "VFS lookup");
        }

        if !announcing {
            return;
        }
        // First of its class. Say it once at a level the default filter shows,
        // and say that the rest are at debug so nobody reads the silence as
        // "it only happened once".
        match outcome {
            LookupOutcome::Served => tracing::info!(
                op,
                path,
                endpoint,
                "first VFS lookup served from graph truth; further lookups log at debug"
            ),
            LookupOutcome::NotInGraph => tracing::warn!(
                op,
                path,
                endpoint,
                "VFS lookup answered not-in-graph; if this path is one the graph owns, the \
                 provider is not reaching the authority that holds it. Further misses log at \
                 debug"
            ),
            LookupOutcome::Boundary => tracing::warn!(
                op,
                path,
                endpoint,
                "VFS lookup refused at a path boundary; further boundary refusals log at debug"
            ),
            LookupOutcome::AuthorityUnavailable => tracing::warn!(
                op,
                path,
                endpoint,
                "VFS lookup could not reach graph authority; reads fail closed rather than \
                 falling back to disk. Further authority failures log at debug"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use kin_vfs_core::VirtualStat;
    use tracing::Level;

    use super::*;

    fn error(code: ErrorCode) -> VfsResponse {
        VfsResponse::Error {
            code,
            message: String::new(),
        }
    }

    #[test]
    fn a_miss_is_never_classified_as_an_authority_failure() {
        // These two are the pair the incident could not distinguish. Everything
        // else in this module exists to keep them apart in the log.
        assert_eq!(
            LookupOutcome::of(&error(ErrorCode::NotFound)),
            LookupOutcome::NotInGraph
        );
        assert_eq!(
            LookupOutcome::of(&error(ErrorCode::IoError)),
            LookupOutcome::AuthorityUnavailable
        );
        assert_eq!(
            LookupOutcome::of(&error(ErrorCode::Internal)),
            LookupOutcome::AuthorityUnavailable
        );
    }

    #[test]
    fn boundary_refusals_are_their_own_class() {
        for code in [
            ErrorCode::IsDirectory,
            ErrorCode::NotDirectory,
            ErrorCode::PermissionDenied,
            ErrorCode::InvalidInput,
            ErrorCode::UnsupportedBoundary,
        ] {
            let label = format!("{code:?}");
            assert_eq!(
                LookupOutcome::of(&error(code)),
                LookupOutcome::Boundary,
                "{label} should classify as a boundary refusal"
            );
        }
    }

    #[test]
    fn every_non_error_response_counts_as_served() {
        assert_eq!(
            LookupOutcome::of(&VfsResponse::Content {
                data: Vec::new(),
                total_size: 0,
            }),
            LookupOutcome::Served
        );
        assert_eq!(
            LookupOutcome::of(&VfsResponse::Stat(VirtualStat::directory(0))),
            LookupOutcome::Served
        );
        assert_eq!(
            LookupOutcome::of(&VfsResponse::DirEntries(Vec::new())),
            LookupOutcome::Served
        );
        assert_eq!(
            LookupOutcome::of(&VfsResponse::Accessible(false)),
            LookupOutcome::Served
        );
    }

    #[test]
    fn each_class_is_announced_once_and_classes_do_not_shadow_each_other() {
        let log = LookupLog::new();

        assert!(log.claim_announcement(LookupOutcome::NotInGraph));
        assert!(!log.claim_announcement(LookupOutcome::NotInGraph));

        // A class already announced must not consume another class's line: an
        // authority failure after a flood of misses is exactly the transition
        // an operator needs to see.
        assert!(log.claim_announcement(LookupOutcome::AuthorityUnavailable));
        assert!(log.claim_announcement(LookupOutcome::Served));
        assert!(log.claim_announcement(LookupOutcome::Boundary));
        for outcome in [
            LookupOutcome::Served,
            LookupOutcome::NotInGraph,
            LookupOutcome::Boundary,
            LookupOutcome::AuthorityUnavailable,
        ] {
            assert!(
                !log.claim_announcement(outcome),
                "{} announced twice",
                outcome.as_str()
            );
        }
    }

    #[test]
    fn recording_counts_every_lookup_including_repeats_of_one_class() {
        // Kept here rather than only in the dispatcher test because that one is
        // `cfg(all(test, unix))`: this is the platform-independent half, and
        // without it the accessor is unused on Windows.
        let log = LookupLog::new();
        assert_eq!(log.recorded(), 0);

        log.record("stat", "a.rs", LookupOutcome::Served, || {
            Some("http://x".to_string())
        });
        log.record("read", "b.rs", LookupOutcome::NotInGraph, || None);
        // The announcement latch bounds the visible lines, never the count. A
        // counter that stopped at the first of each class would report a busy
        // daemon as idle.
        log.record("read", "c.rs", LookupOutcome::NotInGraph, || None);
        assert_eq!(log.recorded(), 3);
    }

    #[test]
    fn the_endpoint_is_resolved_only_when_a_line_is_written() {
        // `record` runs once per intercepted syscall, and resolving an endpoint
        // costs an RwLock read plus a String clone. A build that stats a
        // hundred thousand paths must not pay that for lines no filter will
        // emit, so the caller hands over a closure rather than a value.
        //
        // Subscribers are installed per scope rather than globally so the level
        // under test is this test's own, not whatever another test in this
        // binary happened to leave behind.
        let log = LookupLog::new();
        let resolutions = Cell::new(0u32);
        let endpoint = || {
            resolutions.set(resolutions.get() + 1);
            Some("http://x".to_string())
        };

        let quiet = tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .with_writer(std::io::sink)
            .finish();
        tracing::subscriber::with_default(quiet, || {
            log.record("stat", "a.rs", LookupOutcome::Served, endpoint);
            assert_eq!(
                resolutions.get(),
                1,
                "the first of a class announces, so it must resolve its endpoint"
            );

            log.record("stat", "b.rs", LookupOutcome::Served, endpoint);
            log.record("stat", "c.rs", LookupOutcome::Served, endpoint);
            assert_eq!(
                resolutions.get(),
                1,
                "a lookup whose class is already announced writes nothing at this \
                 level and must not resolve its endpoint"
            );
        });

        let verbose = tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_writer(std::io::sink)
            .finish();
        tracing::subscriber::with_default(verbose, || {
            // Served is already announced, so the debug line is the only writer
            // left and the resolution below is attributable to it alone.
            log.record("stat", "d.rs", LookupOutcome::Served, endpoint);
            assert_eq!(
                resolutions.get(),
                2,
                "at debug every lookup writes its line, so every lookup resolves"
            );
        });
    }

    #[test]
    fn a_second_daemon_gets_its_own_announcements() {
        // Per-daemon state, not process-global: a latch shared across servers
        // would leave the second one silent about its own first miss.
        let first = LookupLog::new();
        let second = LookupLog::new();
        assert!(first.claim_announcement(LookupOutcome::NotInGraph));
        assert!(second.claim_announcement(LookupOutcome::NotInGraph));
    }

    #[test]
    fn outcome_labels_are_stable_and_distinct() {
        let labels: Vec<&str> = [
            LookupOutcome::Served,
            LookupOutcome::NotInGraph,
            LookupOutcome::Boundary,
            LookupOutcome::AuthorityUnavailable,
        ]
        .iter()
        .map(|outcome| outcome.as_str())
        .collect();
        assert_eq!(
            labels,
            vec![
                "served",
                "not-in-graph",
                "boundary",
                "authority-unavailable"
            ]
        );
    }
}
