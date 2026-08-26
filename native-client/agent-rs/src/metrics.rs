use serde::Serialize;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const STALE_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeLatencyState {
    Warming,
    Fresh,
    Degraded,
    Stale,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeLatencySnapshot {
    pub latest_rtt_ms: Option<u64>,
    pub ewma_rtt_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub sample_count: u64,
    pub active_relays: u64,
    pub consecutive_failures: u64,
    pub state: EdgeLatencyState,
    pub updated_at_unix_ms: Option<u64>,
}

#[derive(Debug, Default)]
struct TrackerState {
    latest_rtt_ms: Option<u64>,
    ewma_rtt_ms: Option<u64>,
    jitter_ms: Option<u64>,
    sample_count: u64,
    active_relays: u64,
    consecutive_failures: u64,
    updated_at: Option<SystemTime>,
    probe_owner: Option<u64>,
    next_relay_id: u64,
    next_nonce: u64,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<TrackerState>,
}

#[derive(Debug, Clone, Default)]
pub struct EdgeLatencyTracker {
    shared: Arc<Shared>,
}

impl EdgeLatencyTracker {
    #[must_use]
    pub fn relay_started(&self) -> RelayProbeLease {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.next_relay_id = state.next_relay_id.wrapping_add(1).max(1);
        state.active_relays = state.active_relays.saturating_add(1);
        let relay_id = state.next_relay_id;
        drop(state);
        RelayProbeLease {
            shared: self.shared.clone(),
            relay_id,
        }
    }

    pub fn record_success(&self, duration: Duration, at: SystemTime) {
        let sample = duration_to_millis(duration);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = state.latest_rtt_ms;
        state.latest_rtt_ms = Some(sample);
        state.ewma_rtt_ms = Some(
            state
                .ewma_rtt_ms
                .map_or(sample, |current| ewma(current, sample)),
        );
        let deviation = previous.map_or(0, |value| value.abs_diff(sample));
        state.jitter_ms = Some(ewma(state.jitter_ms.unwrap_or(0), deviation));
        state.sample_count = state.sample_count.saturating_add(1);
        state.consecutive_failures = 0;
        state.updated_at = Some(at);
    }

    pub fn record_failure(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    }

    #[must_use]
    pub fn snapshot(&self) -> EdgeLatencySnapshot {
        self.snapshot_at(SystemTime::now())
    }

    #[must_use]
    pub fn snapshot_at(&self, now: SystemTime) -> EdgeLatencySnapshot {
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state_name = if state.active_relays == 0 {
            EdgeLatencyState::Unavailable
        } else if state.sample_count == 0 && state.consecutive_failures == 0 {
            EdgeLatencyState::Warming
        } else if state
            .updated_at
            .is_some_and(|updated| now.duration_since(updated).unwrap_or_default() > STALE_AFTER)
        {
            EdgeLatencyState::Stale
        } else if state.consecutive_failures > 0 {
            EdgeLatencyState::Degraded
        } else {
            EdgeLatencyState::Fresh
        };
        EdgeLatencySnapshot {
            latest_rtt_ms: state.latest_rtt_ms,
            ewma_rtt_ms: state.ewma_rtt_ms,
            jitter_ms: state.jitter_ms,
            sample_count: state.sample_count,
            active_relays: state.active_relays,
            consecutive_failures: state.consecutive_failures,
            state: state_name,
            updated_at_unix_ms: state.updated_at.map(unix_millis),
        }
    }
}

#[derive(Debug)]
pub struct RelayProbeLease {
    shared: Arc<Shared>,
    relay_id: u64,
}

impl RelayProbeLease {
    #[must_use]
    pub fn try_claim_probe(&self) -> bool {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.probe_owner.is_none() {
            state.probe_owner = Some(self.relay_id);
        }
        state.probe_owner == Some(self.relay_id)
    }

    #[must_use]
    pub fn owns_probe(&self) -> bool {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .probe_owner
            == Some(self.relay_id)
    }

    #[must_use]
    pub fn next_nonce(&self) -> u64 {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.next_nonce = state.next_nonce.wrapping_add(1).max(1);
        state.next_nonce
    }
}

impl Drop for RelayProbeLease {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_relays = state.active_relays.saturating_sub(1);
        if state.probe_owner == Some(self.relay_id) {
            state.probe_owner = None;
        }
        drop(state);
    }
}

const fn ewma(current: u64, sample: u64) -> u64 {
    current.saturating_mul(3).saturating_add(sample) / 4
}

fn duration_to_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn unix_millis(time: SystemTime) -> u64 {
    u64::try_from(
        time.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}
