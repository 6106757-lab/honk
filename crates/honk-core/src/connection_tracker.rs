//! Per-connection state tracker for HTTP APIs and interrupting groups.
//!
//! Uses [`DashMap`] for concurrent-safe access from multiple tokio tasks
//! (accept loop, relay workers, and HTTP API handlers).

use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use std::net::{IpAddr, SocketAddr};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseOutcome {
    Closed,
    Gone,
    NotClosable,
    Failed,
}

/// Tally of one bulk close; `failed` means some retirement could not be confirmed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CloseSummary {
    pub(crate) closed: usize,
    pub(crate) skipped: usize,
    pub(crate) failed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClosePhase {
    Active,
    Closing,
    Closed,
    Failed,
}

pub(crate) struct CloseSignal(watch::Sender<ClosePhase>);

impl CloseSignal {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(watch::channel(ClosePhase::Active).0))
    }

    /// True once the owning transport has finished (cleanly or with a failure).
    /// Used by the tracker sweeper to reclaim rows whose removal path failed.
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(*self.0.borrow(), ClosePhase::Closed | ClosePhase::Failed)
    }

    fn claim(&self) -> bool {
        self.0.send_if_modified(|phase| {
            if *phase != ClosePhase::Active {
                return false;
            }
            *phase = ClosePhase::Closing;
            true
        })
    }

    pub(crate) async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        let _ = receiver
            .wait_for(|phase| *phase != ClosePhase::Active)
            .await;
    }

    pub(crate) fn finish(&self, success: bool) {
        self.0.send_if_modified(|phase| {
            if matches!(*phase, ClosePhase::Closed | ClosePhase::Failed) {
                return false;
            }
            *phase = if success {
                ClosePhase::Closed
            } else {
                ClosePhase::Failed
            };
            true
        });
    }

    async fn completed(&self) -> CloseOutcome {
        let mut receiver = self.0.subscribe();
        match receiver
            .wait_for(|phase| matches!(phase, ClosePhase::Closed | ClosePhase::Failed))
            .await
        {
            Ok(phase) if *phase == ClosePhase::Closed => CloseOutcome::Closed,
            _ => CloseOutcome::Failed,
        }
    }
}

/// A dropped owner is not an acknowledgement of transport/backend cleanup.
pub(crate) struct CloseCompletion(pub(crate) Arc<CloseSignal>);

impl Drop for CloseCompletion {
    fn drop(&mut self) {
        self.0.finish(false);
    }
}

pub(crate) enum CloseAction {
    Tcp,
    Udp {
        pool: std::sync::Weak<crate::control::udp_endpoint::UdpEndpointPool>,
        client: SocketAddr,
        destination: SocketAddr,
        token: u32,
        generation: u64,
    },
    /// A userspace listener relay with no kernel-side action to perform. One
    /// row owns one TCP relay or one whole UDP ASSOCIATE session, so claiming
    /// it simply wakes that single owner through `Notify`; the owner then
    /// tears everything down and acknowledges with `CloseSignal::finish(true)`.
    Inbound {
        cancel: Arc<tokio::sync::Notify>,
    },
}

pub(crate) struct ConnectionOwner {
    pub(crate) signal: Arc<CloseSignal>,
    pub(crate) action: CloseAction,
    pub(crate) groups: Vec<String>,
}

struct TrackedConnection {
    entry: ConnectionEntry,
    owner: Option<Arc<ConnectionOwner>>,
    /// First tick at which the owner's CloseSignal was observed terminal.
    /// Some(..) means the transport has ended and the row is only being kept
    /// for a short grace period before the sweeper reclaims it.
    terminal_since: Option<Instant>,
}

pub(crate) struct SelectedConnection {
    id: String,
    owner: Option<Arc<ConnectionOwner>>,
}

pub(crate) enum CloseRequest {
    Immediate(CloseOutcome),
    Pending(Arc<CloseSignal>),
}

impl CloseRequest {
    pub(crate) async fn wait(self) -> CloseOutcome {
        match self {
            Self::Immediate(outcome) => outcome,
            Self::Pending(signal) => signal.completed().await,
        }
    }
}

pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

pub(crate) fn captured_groups(
    chain: &[String],
    leaf: &str,
    config: &honk_config::Config,
    native_ids: Option<&std::collections::HashMap<String, String>>,
) -> Vec<String> {
    chain
        .iter()
        .take(
            chain
                .len()
                .saturating_sub(usize::from(chain.last().is_some_and(|name| name == leaf))),
        )
        .filter_map(|name| {
            if let Some(ids) = native_ids {
                ids.get(name).cloned()
            } else {
                config
                    .groups
                    .iter()
                    .rev()
                    .find(|group| group.name == *name)
                    .map(|group| group.id.to_string())
            }
        })
        .collect()
}

/// Snapshot of a connection's state, safe to serialize and expose via API.
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub proxy: String,
    /// Matched routing rule (dae expression; "Fallback" = fallback).
    pub rule: String,
    /// Value that drove the match (sniffed domain or destination IP).
    pub rule_payload: String,
    /// Selection path, leaf-first ([leaf, ..sub-groups.., topGroup]).
    pub chains: Vec<String>,
    pub upload: u64,
    pub download: u64,
    pub start_time: Instant,
    pub domain: Option<String>,
    pub network: String,
    /// Originating process name for locally-generated flows (cgroup cookie
    /// attribution); None for LAN-forwarded traffic.
    pub process: Option<String>,
    /// /proc/<pid>/exe at registration time; None when the pid is unknown
    /// or the process already exited.
    pub process_path: Option<String>,
}

/// Live per-connection entry, updated concurrently from the relay task.
pub struct ConnectionEntry {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub proxy: String,
    #[cfg(feature = "native-api")]
    pub routed_outbound: Option<String>,
    #[cfg(feature = "native-api")]
    pub native_flow_id: Option<String>,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    /// Byte counters are shared with the relay task, which increments them
    /// as data flows so `/connections` shows live (not close-time) totals.
    pub upload: Arc<AtomicU64>,
    pub download: Arc<AtomicU64>,
    pub start_time: Instant,
    pub domain: Option<String>,
    pub network: String,
    /// Originating process name for locally-generated flows (cgroup cookie
    /// attribution); None for LAN-forwarded traffic.
    pub process: Option<String>,
    /// /proc/<pid>/exe resolved at registration; None when the pid is
    /// unknown or the process already exited.
    pub process_path: Option<String>,
}

impl ConnectionEntry {
    /// Create a read-only snapshot of the current entry state.
    pub fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id: self.id.clone(),
            source: self.source.clone(),
            destination: self.destination.clone(),
            proxy: self.proxy.clone(),
            rule: self.rule.clone(),
            rule_payload: self.rule_payload.clone(),
            chains: self.chains.clone(),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            start_time: self.start_time,
            domain: self.domain.clone(),
            network: self.network.clone(),
            process: self.process.clone(),
            process_path: self.process_path.clone(),
        }
    }
}

/// Concurrent-safe tracking of all active connections.
///
/// Thread-safe by construction via [`DashMap`] — no external locks needed.
pub struct ConnectionTracker {
    entries: DashMap<String, TrackedConnection>,
    consumers: AtomicU8,
    consumer_transition: parking_lot::Mutex<()>,
}

const API_CONSUMER: u8 = 1;
const INTERRUPT_CONSUMER: u8 = 2;
#[cfg(feature = "native-api")]
const NATIVE_CONSUMER: u8 = 4;

impl ConnectionTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            consumers: AtomicU8::new(0),
            consumer_transition: parking_lot::Mutex::new(()),
        }
    }

    /// Enable tracking for the Clash API.
    #[cfg(any(feature = "clash-api", test))]
    pub(crate) fn enable(&self) {
        let _transition = self.consumer_transition.lock();
        self.consumers.fetch_or(API_CONSUMER, Ordering::AcqRel);
    }

    /// Enable tracking for interrupting group selections.
    pub(crate) fn enable_for_interrupts(&self) {
        let _transition = self.consumer_transition.lock();
        self.consumers
            .fetch_or(INTERRUPT_CONSUMER, Ordering::AcqRel);
    }

    /// Stop API-only tracking after its server terminates.
    #[cfg(any(feature = "clash-api", test))]
    pub(crate) fn disable_api(&self) {
        let _transition = self.consumer_transition.lock();
        let previous = self.consumers.fetch_and(!API_CONSUMER, Ordering::AcqRel);
        if previous & !API_CONSUMER == 0 {
            self.entries.clear();
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.consumers.load(Ordering::Acquire) != 0
    }

    pub(crate) fn needs_rule_details(&self) -> bool {
        self.consumers.load(Ordering::Acquire) & (API_CONSUMER | INTERRUPT_CONSUMER) != 0
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn enable_native(&self) {
        let _transition = self.consumer_transition.lock();
        self.consumers.fetch_or(NATIVE_CONSUMER, Ordering::AcqRel);
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn disable_native(&self) {
        let _transition = self.consumer_transition.lock();
        let previous = self.consumers.fetch_and(!NATIVE_CONSUMER, Ordering::AcqRel);
        if previous & !NATIVE_CONSUMER == 0 {
            self.entries.clear();
        }
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn native_enabled(&self) -> bool {
        self.consumers.load(Ordering::Acquire) & NATIVE_CONSUMER != 0
    }

    /// The visitor must not re-enter the tracker or acquire control-plane locks.
    #[cfg(feature = "native-api")]
    pub(crate) fn visit(&self, mut visitor: impl FnMut(&ConnectionEntry)) {
        for entry in &self.entries {
            visitor(&entry.value().entry);
        }
    }

    /// Register a new connection and return its unique ID (UUID v4).
    pub fn register(&self, entry: ConnectionEntry) -> String {
        let id = entry.id.clone();
        self.entries.insert(
            id.clone(),
            TrackedConnection {
                entry,
                owner: None,
                terminal_since: None,
            },
        );
        id
    }

    pub(crate) fn register_owned(&self, entry: ConnectionEntry, owner: ConnectionOwner) -> String {
        let id = entry.id.clone();
        self.entries.insert(
            id.clone(),
            TrackedConnection {
                entry,
                owner: Some(Arc::new(owner)),
                terminal_since: None,
            },
        );
        id
    }

    pub(crate) fn snapshot_close(
        &self,
        network: Option<&str>,
        source: Option<IpAddr>,
        maximum: usize,
    ) -> Result<Vec<SelectedConnection>, ()> {
        let source = source.map(normalize_ip);
        let mut selected = Vec::new();
        for tracked in &self.entries {
            let entry = &tracked.entry;
            if network.is_some_and(|network| entry.network != network)
                || source.is_some_and(|source| {
                    entry
                        .source
                        .parse::<SocketAddr>()
                        .ok()
                        .is_none_or(|addr| normalize_ip(addr.ip()) != source)
                })
            {
                continue;
            }
            if selected.len() == maximum {
                return Err(());
            }
            selected.push(SelectedConnection {
                id: entry.id.clone(),
                owner: tracked.owner.clone(),
            });
        }
        Ok(selected)
    }

    /// Closes every connection `snapshot_close` selects and tallies the outcomes.
    pub(crate) async fn close_matching(
        &self,
        network: Option<&str>,
        source: Option<IpAddr>,
        maximum: usize,
    ) -> Result<CloseSummary, ()> {
        use futures::StreamExt;
        // All claims precede the first wait; caller cancellation cannot abandon a suffix.
        let mut pending: futures::stream::FuturesUnordered<_> = self
            .snapshot_close(network, source, maximum)?
            .into_iter()
            .map(|selected| self.start_close(selected).wait())
            .collect();
        let mut summary = CloseSummary::default();
        while let Some(outcome) = pending.next().await {
            match outcome {
                CloseOutcome::Closed => summary.closed += 1,
                CloseOutcome::NotClosable => summary.skipped += 1,
                CloseOutcome::Gone => {}
                CloseOutcome::Failed => summary.failed = true,
            }
        }
        Ok(summary)
    }

    pub(crate) fn snapshot_group(
        &self,
        group: &str,
        network: Option<&str>,
    ) -> Vec<SelectedConnection> {
        self.entries
            .iter()
            .filter_map(|tracked| {
                let owner = tracked.owner.as_ref()?;
                (network.is_none_or(|network| tracked.entry.network == network)
                    && owner.groups.iter().any(|id| id == group))
                .then(|| SelectedConnection {
                    id: tracked.entry.id.clone(),
                    owner: Some(Arc::clone(owner)),
                })
            })
            .collect()
    }

    #[cfg(any(test, feature = "native-api", feature = "clash-api"))]
    pub(crate) async fn close_id(&self, id: &str) -> CloseOutcome {
        let selected = self.entries.get(id).map(|tracked| SelectedConnection {
            id: id.to_owned(),
            owner: tracked.owner.clone(),
        });
        match selected {
            Some(selected) => self.close_selected(selected).await,
            None => CloseOutcome::Gone,
        }
    }

    #[cfg(any(test, feature = "native-api", feature = "clash-api"))]
    pub(crate) async fn close_selected(&self, selected: SelectedConnection) -> CloseOutcome {
        self.start_close(selected).wait().await
    }

    pub(crate) fn start_close(&self, selected: SelectedConnection) -> CloseRequest {
        let claimed = {
            let Some(tracked) = self.entries.get(&selected.id) else {
                return CloseRequest::Immediate(CloseOutcome::Gone);
            };
            match (&tracked.owner, &selected.owner) {
                (None, None) => return CloseRequest::Immediate(CloseOutcome::NotClosable),
                (Some(current), Some(selected)) if Arc::ptr_eq(current, selected) => {
                    if !current.signal.claim() {
                        return CloseRequest::Pending(Arc::clone(&current.signal));
                    }
                    true
                }
                _ => false,
            }
        };
        if !claimed {
            return CloseRequest::Immediate(CloseOutcome::Gone);
        }
        let owner = selected.owner.expect("claimed transport owner");
        match &owner.action {
            CloseAction::Udp {
                pool,
                client,
                destination,
                token,
                generation,
            } => {
                let Some(pool) = pool.upgrade() else {
                    owner.signal.finish(false);
                    // No removal will ever be produced for this close: the pool is
                    // gone, so neither settle() nor the endpoint can reclaim the
                    // row. Drop the observation immediately.
                    self.remove(&selected.id);
                    return CloseRequest::Pending(Arc::clone(&owner.signal));
                };
                if !pool.close_exact(*client, *destination, *token, *generation) {
                    owner.signal.finish(false);
                    // close_exact returned false: no EndpointRemoval is emitted,
                    // which used to leave the row in the unbounded map forever.
                    self.remove(&selected.id);
                }
            }
            // Claiming already moved the signal out of `Active`; the relay
            // wakes on this notification, drops its sockets and acknowledges.
            CloseAction::Inbound { cancel } => cancel.notify_one(),
            CloseAction::Tcp => {}
        }
        CloseRequest::Pending(Arc::clone(&owner.signal))
    }

    /// Add upload/download bytes to an existing connection.
    ///
    /// If the connection is no longer in the map, the update is silently
    /// dropped (the relay task may have raced with a close).
    pub fn update_bytes(&self, id: &str, upload_delta: u64, download_delta: u64) {
        if let Some(entry) = self.entries.get(id) {
            entry
                .entry
                .upload
                .fetch_add(upload_delta, Ordering::Relaxed);
            entry
                .entry
                .download
                .fetch_add(download_delta, Ordering::Relaxed);
        }
    }

    /// Attach process metadata after registration. A missing entry means the
    /// flow closed before the blocking `/proc` lookup completed.
    pub fn update_process_path(&self, id: &str, process_path: String) {
        if let Some(mut entry) = self.entries.get_mut(id) {
            entry.entry.process_path = Some(process_path);
        }
    }

    /// Remove a connection from the tracker.
    pub fn remove(&self, id: &str) {
        self.entries.remove(id);
    }

    /// Last-resort reclamation of observation rows whose owning transport has
    /// already finished. Called on every janitor tick.
    ///
    /// A terminal [`CloseSignal`] is authoritative: the relay/driver is gone,
    /// so a row still present here can only be a leaked observation (failed
    /// retirement, lost owner, kernel table reclaimed without a userspace
    /// removal). Keeping it briefly lets in-flight close requests observe the
    /// outcome; after `grace` it is dropped unconditionally.
    ///
    /// Rows whose transport is still active are never touched, so legitimate
    /// long-lived idle connections (Telegram, push, mtalk) are safe — this is
    /// deliberately not a start_time/idle TTL.
    pub(crate) fn sweep_terminal(&self, grace: Duration) -> usize {
        let now = Instant::now();
        let ids: Vec<String> = self.entries.iter().map(|row| row.key().clone()).collect();
        let mut expired = Vec::new();
        for id in &ids {
            let Some(mut tracked) = self.entries.get_mut(id) else {
                continue;
            };
            let terminal = tracked
                .owner
                .as_ref()
                .is_some_and(|owner| owner.signal.is_terminal());
            if terminal {
                let since = *tracked.terminal_since.get_or_insert(now);
                if now.duration_since(since) >= grace {
                    expired.push(id.clone());
                }
            } else {
                tracked.terminal_since = None;
            }
        }
        let count = expired.len();
        for id in expired {
            self.entries.remove(&id);
        }
        count
    }

    /// Snapshot of rows whose transport has finished. Taken once per API page
    /// so the connections handler can report a real state without re-entering
    /// the map while it is being visited.
    pub(crate) fn terminal_ids(&self) -> HashSet<String> {
        self.entries
            .iter()
            .filter(|row| row.value().terminal_since.is_some())
            .map(|row| row.key().clone())
            .collect()
    }

    /// Return a point-in-time snapshot of all active connections.
    pub fn snapshot(&self) -> Vec<ConnectionSnapshot> {
        self.entries
            .iter()
            .map(|ref_multi| ref_multi.value().entry.snapshot())
            .collect()
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(id: &str, network: &str) -> ConnectionEntry {
        ConnectionEntry {
            id: id.into(),
            source: "172.20.1.20:50000".into(),
            destination: "1.1.1.1:443".into(),
            proxy: "Final".into(),
            #[cfg(feature = "native-api")]
            routed_outbound: Some("Final".into()),
            #[cfg(feature = "native-api")]
            native_flow_id: None,
            rule: "Fallback".into(),
            rule_payload: String::new(),
            chains: vec!["Final".into()],
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
            domain: None,
            network: network.into(),
            process: None,
            process_path: None,
        }
    }

    /// Stand-in for a userspace listener relay: a close request notifies it,
    /// it drops both sockets and acknowledges transport teardown.
    fn inbound_owner(
        tracker: &ConnectionTracker,
        entry: ConnectionEntry,
    ) -> (String, Arc<tokio::sync::Notify>, Arc<CloseSignal>) {
        let cancel = Arc::new(tokio::sync::Notify::new());
        let signal = CloseSignal::new();
        let id = tracker.register_owned(
            entry,
            ConnectionOwner {
                signal: Arc::clone(&signal),
                action: CloseAction::Inbound {
                    cancel: Arc::clone(&cancel),
                },
                groups: Vec::new(),
            },
        );
        (id, cancel, signal)
    }

    #[tokio::test]
    async fn inbound_connection_is_closable_by_id() {
        let tracker = ConnectionTracker::new();
        let (id, cancel, signal) = inbound_owner(&tracker, test_entry("inbound-tcp", "tcp"));
        let relay = tokio::spawn(async move {
            cancel.notified().await;
            signal.finish(true);
        });
        assert_eq!(tracker.close_id(&id).await, CloseOutcome::Closed);
        relay.await.unwrap();
        tracker.remove(&id);
    }

    #[tokio::test]
    async fn bulk_close_counts_inbound_connections_as_closed() {
        let tracker = ConnectionTracker::new();
        let (tcp_id, tcp_cancel, tcp_signal) =
            inbound_owner(&tracker, test_entry("inbound-tcp", "tcp"));
        let (udp_id, udp_cancel, udp_signal) =
            inbound_owner(&tracker, test_entry("inbound-udp", "udp"));
        // A row without an owner (e.g. a legacy observation) must still be
        // reported as skipped, not silently counted as closed.
        tracker.register(test_entry("unowned", "tcp"));

        let relays = tokio::spawn(async move {
            let tcp = tokio::spawn(async move {
                tcp_cancel.notified().await;
                tcp_signal.finish(true);
            });
            let udp = tokio::spawn(async move {
                udp_cancel.notified().await;
                udp_signal.finish(true);
            });
            let _ = tcp.await;
            let _ = udp.await;
        });

        let summary = tracker.close_matching(None, None, 100).await.unwrap();
        assert_eq!(summary.closed, 2);
        assert_eq!(summary.skipped, 1);
        assert!(!summary.failed);
        relays.await.unwrap();
        tracker.remove(&tcp_id);
        tracker.remove(&udp_id);
    }

    #[test]
    fn interrupt_consumer_survives_api_shutdown() {
        let tracker = ConnectionTracker::new();
        tracker.enable();
        tracker.enable_for_interrupts();
        tracker.disable_api();
        assert!(tracker.is_enabled());
    }

    #[cfg(feature = "native-api")]
    #[test]
    fn native_consumer_preserves_other_observers() {
        let tracker = ConnectionTracker::new();
        tracker.enable_native();
        assert!(!tracker.needs_rule_details());
        tracker.enable();
        tracker.disable_native();
        assert!(tracker.is_enabled());
        assert!(tracker.needs_rule_details());
        tracker.enable_native();
        tracker.disable_api();
        assert!(tracker.native_enabled());
        assert!(!tracker.needs_rule_details());
        tracker.enable_for_interrupts();
        tracker.disable_native();
        assert!(tracker.needs_rule_details());
    }

    #[cfg(feature = "native-api")]
    #[test]
    fn native_enable_cannot_overtake_last_consumer_clear() {
        use super::*;
        fn entry(id: &str) -> ConnectionEntry {
            ConnectionEntry {
                id: id.into(),
                source: "127.0.0.1:1".into(),
                destination: "127.0.0.1:2".into(),
                proxy: "direct".into(),
                routed_outbound: Some("direct".into()),
                native_flow_id: None,
                rule: String::new(),
                rule_payload: String::new(),
                chains: Vec::new(),
                upload: Arc::new(AtomicU64::new(0)),
                download: Arc::new(AtomicU64::new(0)),
                start_time: Instant::now(),
                domain: None,
                network: "tcp".into(),
                process: None,
                process_path: None,
            }
        }
        let tracker = Arc::new(ConnectionTracker::new());
        tracker.enable();
        tracker.register(entry("old"));
        let old = tracker.entries.get("old").unwrap();
        let disabling = Arc::clone(&tracker);
        let disabled = std::thread::spawn(move || disabling.disable_api());
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        while tracker.is_enabled() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(tracker.consumer_transition.try_lock().is_none());
        let enabling = Arc::clone(&tracker);
        let enabled = std::thread::spawn(move || {
            enabling.enable_native();
            enabling.register(entry("new"));
        });
        drop(old);
        disabled.join().unwrap();
        enabled.join().unwrap();
        assert!(tracker.native_enabled());
        assert_eq!(
            tracker
                .snapshot()
                .iter()
                .map(|entry| entry.id.as_str())
                .collect::<Vec<_>>(),
            ["new"]
        );
    }
}
