// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-process memory of path facts the shim has already asked the daemon for.
//!
//! Resolving `a/b/c/d.rs` used to cost one daemon round trip per component,
//! because the shim walked the path proving each prefix was a directory. The
//! prefixes repeat across every file in a tree, so a tool that stats a whole
//! repository paid depth × files for facts it had already been told.
//!
//! What is remembered, and what is deliberately not:
//!
//! - This cache holds **path-prefix assertions only**. It is consulted while
//!   resolving the intermediate components of a path, never to produce the
//!   attribute a caller receives. Every intercepted stat still makes exactly
//!   one daemon call for the exact path the caller named, so no caller can
//!   observe a remembered answer, and the process re-reads the authority
//!   generation on every call it makes.
//! - Every entry is stamped with the repository-authority generation the daemon
//!   reported when it produced that fact, and is consulted only while that
//!   stamp equals the generation of the most recent answer this process
//!   received. A higher generation clears everything before the next path
//!   resolves. The window a remembered fact can survive a publication is zero
//!   calls, not a duration: there is no clock here and no TTL.
//! - Generation `0` is the protocol's "no snapshot answered" sentinel. It is
//!   never stored and never observed, so an answer from a daemon with no
//!   installed authority cannot be mistaken for a fact about the graph.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};

use lru::LruCache;
use parking_lot::Mutex;

use kin_vfs_core::VfsPath;

/// Entries retained per process. Sized for the prefix set of a large
/// repository: a tree of a few hundred thousand files has far fewer distinct
/// directories than files, and only directories are ever consulted.
pub(crate) const DEFAULT_CAPACITY: usize = 8192;

/// A fact about one path, holding exactly what path resolution reads and
/// nothing more. Size and mtime are deliberately absent: they belong to the
/// answer a caller receives, which this cache never serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathFact {
    /// The graph holds this path.
    Present { is_dir: bool, is_symlink: bool },
    /// The graph definitively does not hold this path. Absence is the hot
    /// result for tools that probe for configuration files that are not there,
    /// so it is remembered on the same terms as presence.
    Absent,
}

/// Generation-stamped memory of path facts, bounded and evicting.
pub(crate) struct StatCache {
    /// The newest generation any answer has reported to this process.
    observed: AtomicU64,
    /// `None` disables the cache outright, which is what makes the round-trip
    /// claim falsifiable: the same workload against a disabled cache must show
    /// the per-component cost return.
    entries: Option<Mutex<LruCache<VfsPath, Stamped>>>,
}

#[derive(Debug, Clone, Copy)]
struct Stamped {
    generation: u64,
    fact: PathFact,
}

impl StatCache {
    /// Build a cache holding at most `capacity` entries. Zero disables it.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            observed: AtomicU64::new(0),
            entries: NonZeroUsize::new(capacity).map(|cap| Mutex::new(LruCache::new(cap))),
        }
    }

    /// Record the generation an answer carried and return the generation now
    /// observed.
    ///
    /// A higher generation is the publication boundary: everything remembered
    /// belongs to a superseded snapshot and is dropped before the caller can
    /// consult it. A lower one is an answer from a snapshot this process has
    /// already moved past, so it is neither observed nor stored; a daemon whose
    /// generation regressed therefore degrades this to a cache that never hits
    /// rather than one that serves the wrong era.
    pub(crate) fn observe(&self, generation: u64) -> u64 {
        if generation == 0 {
            return self.observed.load(Ordering::Acquire);
        }
        let mut current = self.observed.load(Ordering::Acquire);
        while generation > current {
            match self.observed.compare_exchange_weak(
                current,
                generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.clear();
                    return generation;
                }
                Err(seen) => current = seen,
            }
        }
        current
    }

    /// The generation entries must carry to be consulted.
    pub(crate) fn observed(&self) -> u64 {
        self.observed.load(Ordering::Acquire)
    }

    /// Remember one fact, if it belongs to the generation now observed.
    pub(crate) fn remember(&self, path: &VfsPath, generation: u64, fact: PathFact) {
        if generation == 0 || generation != self.observed() {
            return;
        }
        let Some(entries) = &self.entries else {
            return;
        };
        entries
            .lock()
            .put(path.clone(), Stamped { generation, fact });
    }

    /// Recall one fact, if it was recorded under the generation now observed.
    ///
    /// An entry from a superseded generation is dropped on sight rather than
    /// left to age out, so a stale key cannot be reached again even if the
    /// generation were somehow to return to its value.
    pub(crate) fn recall(&self, path: &VfsPath) -> Option<PathFact> {
        let entries = self.entries.as_ref()?;
        let observed = self.observed();
        let mut guard = entries.lock();
        match guard.get(path) {
            Some(entry) if entry.generation == observed => Some(entry.fact),
            Some(_) => {
                guard.pop(path);
                None
            }
            None => None,
        }
    }

    fn clear(&self) {
        if let Some(entries) = &self.entries {
            entries.lock().clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vpath(path: &str) -> VfsPath {
        VfsPath::from_utf8(path).expect("valid test path")
    }

    const DIR: PathFact = PathFact::Present {
        is_dir: true,
        is_symlink: false,
    };

    #[test]
    fn a_fact_survives_only_its_own_generation() {
        let cache = StatCache::new(16);
        assert_eq!(cache.observe(7), 7);
        cache.remember(&vpath("src"), 7, DIR);
        assert_eq!(cache.recall(&vpath("src")), Some(DIR));

        // The publication boundary: one answer carrying a newer generation
        // discards everything remembered under the old one.
        assert_eq!(cache.observe(8), 8);
        assert_eq!(cache.recall(&vpath("src")), None);
    }

    #[test]
    fn an_answer_from_a_superseded_snapshot_is_not_remembered() {
        let cache = StatCache::new(16);
        cache.observe(9);
        cache.remember(&vpath("src"), 8, DIR);
        assert_eq!(
            cache.recall(&vpath("src")),
            None,
            "an older snapshot's answer must not be stored under the current generation"
        );
        assert_eq!(
            cache.observed(),
            9,
            "a lower generation must not be observed"
        );
    }

    #[test]
    fn the_no_snapshot_sentinel_is_never_remembered_or_observed() {
        let cache = StatCache::new(16);
        cache.observe(5);
        assert_eq!(cache.observe(0), 5, "zero carries no information");
        cache.remember(&vpath("src"), 0, DIR);
        assert_eq!(cache.recall(&vpath("src")), None);
    }

    #[test]
    fn absence_is_remembered_on_the_same_terms_as_presence() {
        let cache = StatCache::new(16);
        cache.observe(3);
        cache.remember(&vpath("node_modules"), 3, PathFact::Absent);
        assert_eq!(
            cache.recall(&vpath("node_modules")),
            Some(PathFact::Absent),
            "a definitive absence is a graph fact and must be rememberable"
        );
        cache.observe(4);
        assert_eq!(cache.recall(&vpath("node_modules")), None);
    }

    #[test]
    fn capacity_bounds_the_cache_and_zero_disables_it() {
        let cache = StatCache::new(2);
        cache.observe(1);
        for name in ["a", "b", "c"] {
            cache.remember(&vpath(name), 1, DIR);
        }
        assert_eq!(cache.recall(&vpath("a")), None, "the oldest entry evicts");
        assert_eq!(cache.recall(&vpath("c")), Some(DIR));

        let disabled = StatCache::new(0);
        disabled.observe(1);
        disabled.remember(&vpath("a"), 1, DIR);
        assert_eq!(disabled.recall(&vpath("a")), None);
    }
}
