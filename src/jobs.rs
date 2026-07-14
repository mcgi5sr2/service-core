//! Bounded, TTL-swept in-memory store for async job APIs.
//!
//! A handler returns a job id immediately; a background worker runs the job and
//! records the outcome here. Growth is bounded two ways: [`JobStore::try_create_under`]
//! refuses new jobs past a cap (atomic check+insert — no count-then-create TOCTOU),
//! and [`JobStore::evict_terminal_older_than`] sweeps aged terminal jobs. In-flight
//! jobs are never evicted, and [`JobStore::set`] no-ops on a missing id so a late
//! worker can't resurrect a zombie entry.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// The lifecycle of a single job. `Done`/`Failed` carry the terminal payload.
#[derive(Clone)]
pub enum JobStatus {
    Pending,
    Running,
    Done(String),
    Failed(String),
}

impl JobStatus {
    fn is_terminal(&self) -> bool {
        matches!(self, JobStatus::Done(_) | JobStatus::Failed(_))
    }
}

struct Job {
    status: JobStatus,
    updated: Instant,
}

/// Cloneable handle (an `Arc` bump) shared by handlers and workers.
#[derive(Clone, Default)]
pub struct JobStore {
    jobs: Arc<RwLock<HashMap<String, Job>>>,
}

impl JobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically create a job in `Pending` iff the store holds fewer than `limit`
    /// jobs; returns the new id, or `None` at/over capacity. Check and insert happen
    /// under one write lock, so a concurrent burst can't exceed the bound.
    pub fn try_create_under(&self, limit: usize) -> Option<String> {
        let mut jobs = self.jobs.write().unwrap();
        if jobs.len() >= limit {
            return None;
        }
        let id = uuid::Uuid::new_v4().to_string();
        jobs.insert(id.clone(), Job { status: JobStatus::Pending, updated: Instant::now() });
        Some(id)
    }

    /// Update an existing job. No-ops if the job is gone (already evicted).
    pub fn set(&self, id: &str, status: JobStatus) {
        if let Some(job) = self.jobs.write().unwrap().get_mut(id) {
            job.status = status;
            job.updated = Instant::now();
        }
    }

    /// Read the current status, cloned out so the guard is never handed back.
    pub fn get(&self, id: &str) -> Option<JobStatus> {
        self.jobs.read().unwrap().get(id).map(|j| j.status.clone())
    }

    /// Number of jobs currently tracked.
    pub fn count(&self) -> usize {
        self.jobs.read().unwrap().len()
    }

    /// Drop terminal jobs whose result has aged past `ttl`; in-flight jobs are kept.
    /// Returns how many were evicted.
    pub fn evict_terminal_older_than(&self, ttl: Duration) -> usize {
        let now = Instant::now();
        let mut jobs = self.jobs.write().unwrap();
        let before = jobs.len();
        jobs.retain(|_, job| !(job.status.is_terminal() && now.duration_since(job.updated) > ttl));
        before - jobs.len()
    }
}
