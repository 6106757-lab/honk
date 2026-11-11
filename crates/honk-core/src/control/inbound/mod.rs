//! Named mixed (HTTP + SOCKS5) inbound listeners.
//!
//! Architecture: a listener only carries an **identity** (`name`). Outbound
//! selection is done by `inbound(name)` routing rules, so there is no second
//! routing table, no second node configuration and no bypass of the DNS
//! `qname()` / `follow` path.
//!
//! Lifecycle: bind every socket synchronously before spawning any supervisor
//! (atomic startup), then drive a three-state watch phase
//! (Running / StopAccepting / Abort) with a JoinSet and the process drain
//! tracker. Reload rebuilds the epoch, which rebinds the listener set; the
//! `patch` method below additionally supports name-wise incremental replace.

mod dial;
mod http;
mod mixed;
mod param;
mod socks;
#[cfg(test)]
mod tests;

use super::connection::ControlPlaneHandle;
use crate::stats::StatsManager;
use honk_config::ListenerConfig;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerPhase {
    Running,
    StopAccepting,
    Abort,
}

/// One quarter of the process TCP budget is shared by **all** inbound
/// listeners, not by each of them (the reference PR gave every listener its
/// own quarter, so N listeners could consume N/4 of the budget).
fn standalone_tcp_capacity(total: usize) -> usize {
    if total == 0 {
        1
    } else {
        (total / 4).max(1)
    }
}

pub(super) struct BoundInboundListener {
    config: ListenerConfig,
    listener: std::net::TcpListener,
}

impl BoundInboundListener {
    /// Validate the whole set first, then bind all sockets. Nothing is
    /// spawned until every bind succeeded, so a conflicting config cannot
    /// leave a half-started listener set behind.
    pub(super) fn bind_all(configs: &[ListenerConfig]) -> io::Result<Vec<Self>> {
        honk_config::validate_listeners(configs)
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
        configs.iter().map(Self::bind).collect()
    }

    fn bind(config: &ListenerConfig) -> io::Result<Self> {
        let listener = bind_tcp_listener(config.bind_addr())?;
        Ok(Self {
            config: config.clone(),
            listener,
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.config.name
    }

    fn spawn(
        self,
        handle: ControlPlaneHandle,
        connection_limit: Arc<Semaphore>,
        standalone_limit: Arc<Semaphore>,
        stats: Arc<StatsManager>,
        drain: Arc<super::drain::DrainTracker>,
    ) -> io::Result<InboundListener> {
        let Self { config, listener } = self;
        let local_addr = listener.local_addr()?;
        let listener = TcpListener::from_std(listener)?;
        let (phase, phase_rx) = watch::channel(ListenerPhase::Running);
        let mut supervisors = JoinSet::new();
        supervisors.spawn(run_accept_supervisor(
            config.clone(),
            listener,
            handle,
            connection_limit,
            standalone_limit,
            stats,
            drain,
            phase_rx,
        ));
        info!(
            listener = %config.name,
            %local_addr,
            auth = config.auth.is_some(),
            "入站混合监听已启动（出口由 inbound() 规则决定）"
        );
        Ok(InboundListener {
            name: config.name.clone(),
            config,
            phase,
            supervisors,
        })
    }
}

pub(super) struct InboundListener {
    name: String,
    config: ListenerConfig,
    phase: watch::Sender<ListenerPhase>,
    supervisors: JoinSet<anyhow::Result<()>>,
}

impl InboundListener {
    pub(super) fn stop_accepting(&self) {
        let _ = self.phase.send(ListenerPhase::StopAccepting);
    }

    pub(super) async fn abort_and_join(&mut self) -> anyhow::Result<()> {
        let _ = self.phase.send(ListenerPhase::Abort);
        let mut failure = None;
        while let Some(result) = self.supervisors.join_next().await {
            if let Err(error) = result
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
            {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for InboundListener {
    fn drop(&mut self) {
        let _ = self.phase.send(ListenerPhase::Abort);
        self.supervisors.abort_all();
    }
}

pub(super) struct InboundListenerSet {
    listeners: Vec<InboundListener>,
}

impl InboundListenerSet {
    pub(super) fn spawn_all(
        bound: Vec<BoundInboundListener>,
        handle: ControlPlaneHandle,
        connection_limit: Arc<Semaphore>,
        stats: Arc<StatsManager>,
        drain: Arc<super::drain::DrainTracker>,
    ) -> io::Result<Self> {
        let capacity = standalone_tcp_capacity(connection_limit.available_permits());
        let standalone_limit = Arc::new(Semaphore::new(capacity));
        let mut listeners = Vec::with_capacity(bound.len());
        for item in bound {
            listeners.push(item.spawn(
                handle.clone(),
                Arc::clone(&connection_limit),
                Arc::clone(&standalone_limit),
                Arc::clone(&stats),
                Arc::clone(&drain),
            )?);
        }
        Ok(Self { listeners })
    }

    /// Name-wise incremental replacement (mihomo `PatchInboundListeners`):
    /// unchanged listeners keep their sockets and accepted connections, only
    /// added/removed/changed names are touched.
    #[allow(dead_code)]
    pub(super) async fn patch(
        &mut self,
        bound: Vec<BoundInboundListener>,
        handle: ControlPlaneHandle,
        connection_limit: Arc<Semaphore>,
        stats: Arc<StatsManager>,
        drain: Arc<super::drain::DrainTracker>,
    ) -> io::Result<()> {
        let capacity = standalone_tcp_capacity(connection_limit.available_permits());
        let standalone_limit = Arc::new(Semaphore::new(capacity));
        let mut keep = vec![false; self.listeners.len()];
        let mut additions = Vec::new();
        for item in bound {
            if let Some((index, _)) = self
                .listeners
                .iter()
                .enumerate()
                .find(|(_, live)| live.name == item.name() && live.config == item.config)
            {
                keep[index] = true;
                continue;
            }
            additions.push(item);
        }
        let mut retained = Vec::new();
        for (index, live) in self.listeners.drain(..).enumerate() {
            let mut live = live;
            if keep[index] {
                retained.push(live);
            } else {
                let _ = live.abort_and_join().await;
            }
        }
        for item in additions {
            retained.push(item.spawn(
                handle.clone(),
                Arc::clone(&connection_limit),
                Arc::clone(&standalone_limit),
                Arc::clone(&stats),
                Arc::clone(&drain),
            )?);
        }
        self.listeners = retained;
        Ok(())
    }

    pub(super) fn stop_accepting(&self) {
        for listener in &self.listeners {
            listener.stop_accepting();
        }
    }

    pub(super) async fn abort_and_join(&mut self) -> anyhow::Result<()> {
        let mut failure = None;
        for listener in &mut self.listeners {
            if let Err(error) = listener.abort_and_join().await {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn bind_tcp_listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[allow(clippy::too_many_arguments)]
async fn run_accept_supervisor(
    config: ListenerConfig,
    listener: TcpListener,
    handle: ControlPlaneHandle,
    connection_limit: Arc<Semaphore>,
    standalone_limit: Arc<Semaphore>,
    stats: Arc<StatsManager>,
    drain: Arc<super::drain::DrainTracker>,
    mut phase: watch::Receiver<ListenerPhase>,
) -> anyhow::Result<()> {
    let mut children = JoinSet::new();
    let mut failure = None;
    let mut accept_failing = false;

    loop {
        tokio::select! {
            biased;
            changed = phase.changed() => {
                if changed.is_err() || *phase.borrow() != ListenerPhase::Running {
                    break;
                }
            }
            completed = children.join_next(), if !children.is_empty() => {
                retain_child_result(&mut failure, completed, false);
            }
            accepted = listener.accept() => {
                let (stream, client_addr) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // 3proxy's proxymain.c classifies accept failures and
                        // sleeps; a bare `continue` spins at 100% CPU on
                        // EMFILE/ENFILE. Log once per episode, back off by
                        // errno severity.
                        if !std::mem::replace(&mut accept_failing, true) {
                            warn!(?error, listener = %config.name, "入站监听 accept 失败");
                        }
                        let backoff = match error.raw_os_error() {
                            Some(23) | Some(24) => Duration::from_millis(200), // ENFILE / EMFILE
                            _ => Duration::from_millis(20),
                        };
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                };
                if std::mem::replace(&mut accept_failing, false) {
                    info!(listener = %config.name, "入站监听 accept 已恢复");
                }
                if *phase.borrow() != ListenerPhase::Running || drain.should_reject() {
                    continue;
                }
                let standalone_permit = match Arc::clone(&standalone_limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(listener = %config.name, %client_addr, "入站监听容量已满，丢弃连接");
                        continue;
                    }
                };
                let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        stats.record_tcp_capacity_rejection();
                        debug!(listener = %config.name, %client_addr, "全局容量已满，丢弃连接");
                        continue;
                    }
                };
                let guard = super::connection::ConnectionGuard::new(Arc::clone(&drain));
                let child_handle = handle.clone();
                let child_config = config.clone();
                children.spawn(async move {
                    let _permit = permit;
                    let _standalone_permit = standalone_permit;
                    let _guard = guard;
                    if let Err(error) = mixed::serve_mixed_connection(
                        stream,
                        client_addr,
                        &child_config,
                        &child_handle,
                    )
                    .await
                    {
                        debug!(%error, %client_addr, "入站连接结束");
                    }
                });
            }
        }
    }

    drop(listener);
    finish_children(&mut children, &mut phase, &mut failure).await;
    failure.map_or(Ok(()), Err)
}

async fn finish_children(
    children: &mut JoinSet<()>,
    phase: &mut watch::Receiver<ListenerPhase>,
    failure: &mut Option<anyhow::Error>,
) {
    let mut aborted = *phase.borrow() == ListenerPhase::Abort;
    if aborted {
        children.abort_all();
    }
    while !children.is_empty() {
        tokio::select! {
            changed = phase.changed(), if !aborted => {
                if changed.is_err() || *phase.borrow() == ListenerPhase::Abort {
                    aborted = true;
                    children.abort_all();
                }
            }
            completed = children.join_next() => retain_child_result(failure, completed, aborted),
        }
    }
}

fn retain_child_result(
    failure: &mut Option<anyhow::Error>,
    completed: Option<Result<(), tokio::task::JoinError>>,
    aborted: bool,
) {
    if let Some(Err(error)) = completed
        && (!aborted || !error.is_cancelled())
    {
        failure.get_or_insert_with(|| anyhow::Error::new(error).context("inbound connection"));
    }
}
