#[cfg(windows)]
use crate::windows_pipe_security::create_secure_named_pipe;
use crate::{
    api::CentralClient,
    config::AgentConfig,
    endpoint::edge_tunnel_url,
    ipc::{ControlCommand, ControlRequest, EdgeLatencyStatus, StatusResponse, authorize_secret},
    metrics::EdgeLatencyTracker,
    relay::connect_and_relay,
    socks::{negotiate, send_reply},
};
use anyhow::{Context, Result, bail};
use secrecy::SecretString;
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::JoinSet,
};
use tracing::{error, info, warn};
use url::Url;

const MAX_CONTROL_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct RuntimeOptions {
    pub heartbeat_interval: Duration,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentReady {
    pub socks_addr: SocketAddr,
    pub control_socket_path: std::path::PathBuf,
}

pub async fn run(
    config: AgentConfig,
    options: RuntimeOptions,
    ready: oneshot::Sender<AgentReady>,
) -> Result<()> {
    run_with_shutdown(config, options, ready, std::future::pending()).await
}

pub async fn run_with_shutdown<F>(
    config: AgentConfig,
    options: RuntimeOptions,
    ready: oneshot::Sender<AgentReady>,
    external_shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    let config = config.validate()?;
    let central = CentralClient::new(&config)?;
    let store = central
        .preflight()
        .await
        .context("native preflight failed")?;
    let immutable_endpoint = edge_tunnel_url(&store.edge_endpoint)?;
    let connection = central
        .connect(&config.device_id)
        .await
        .context("native connect failed")?;
    let lease_id = connection.lease_id;
    if edge_tunnel_url(&connection.edge_endpoint)? != immutable_endpoint {
        let _ = central.disconnect(&lease_id, &config.device_id).await;
        bail!("Edge endpoint changed between preflight and connect");
    }

    let result = run_connected(
        &config,
        options,
        central.clone(),
        lease_id.clone(),
        immutable_endpoint,
        ready,
        external_shutdown,
    )
    .await;
    if let Err(error) = central.disconnect(&lease_id, &config.device_id).await {
        warn!(error = %crate::redaction::redact(&error.to_string()), "disconnect failed");
    }
    result
}

async fn run_connected<F>(
    config: &AgentConfig,
    options: RuntimeOptions,
    central: CentralClient,
    lease_id: String,
    immutable_endpoint: Url,
    ready: oneshot::Sender<AgentReady>,
    external_shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    let socks = TcpListener::bind((Ipv4Addr::LOCALHOST, config.local_port))
        .await
        .context("bind loopback SOCKS listener")?;
    let socks_addr = socks.local_addr()?;
    if socks_addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || config.local_port != 0 {
        bail!("SOCKS listener violated loopback ephemeral binding policy");
    }
    let control = bind_control_socket(&config.control_socket_path)?;
    let socket_cleanup = SocketCleanup(&config.control_socket_path);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics = Arc::new(EdgeLatencyTracker::default());
    let mut tasks = JoinSet::new();

    tasks.spawn(heartbeat_loop(
        central.clone(),
        lease_id.clone(),
        config.device_id.clone(),
        options.heartbeat_interval,
        shutdown_tx.clone(),
        shutdown_rx.clone(),
    ));
    tasks.spawn(control_loop(
        control,
        central.clone(),
        config.control_capability.clone(),
        socks_addr.port(),
        config.store_id,
        config.device_id.clone(),
        metrics.clone(),
        shutdown_tx.clone(),
        shutdown_rx.clone(),
    ));

    let _ = ready.send(AgentReady {
        socks_addr,
        control_socket_path: config.control_socket_path.clone(),
    });
    info!(store_id = config.store_id, device_id = %config.device_id, socks_host = "127.0.0.1", socks_port = socks_addr.port(), "agent connected");

    tokio::pin!(external_shutdown);
    let mut accept_shutdown = shutdown_rx.clone();
    loop {
        tokio::select! {
            accepted = socks.accept() => {
                let (stream, peer) = accepted.context("accept SOCKS connection")?;
                let client = central.clone();
                let expected_lease = lease_id.clone();
                let device_id = config.device_id.clone();
                let expected_endpoint = immutable_endpoint.clone();
                let metrics = metrics.clone();
                tasks.spawn(async move {
                    if let Err(error) = handle_socks(
                        stream,
                        client,
                        expected_lease,
                        device_id,
                        expected_endpoint,
                        metrics,
                    ).await {
                        warn!(peer = %peer, error = %crate::redaction::redact(&error.to_string()), "SOCKS connection failed closed");
                    }
                });
            }
            changed = accept_shutdown.changed() => {
                if changed.is_err() || *accept_shutdown.borrow() { break; }
            }
            () = &mut external_shutdown => {
                info!("external shutdown requested");
                let _ = shutdown_tx.send(true);
                break;
            }
        }
    }

    let _ = shutdown_tx.send(true);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(socket_cleanup);
    info!(store_id = config.store_id, "agent stopped");
    Ok(())
}

async fn handle_socks(
    mut stream: TcpStream,
    central: CentralClient,
    expected_lease: String,
    device_id: String,
    immutable_endpoint: Url,
    metrics: Arc<EdgeLatencyTracker>,
) -> Result<()> {
    let target = match negotiate(&mut stream).await {
        Ok(target) => target,
        Err(error) => {
            let _ = send_reply(&mut stream, 1).await;
            return Err(error.context("SOCKS negotiation"));
        }
    };
    let ticket = match central
        .ticket(&target.host(), target.port(), &expected_lease, &device_id)
        .await
    {
        Ok(ticket) => ticket,
        Err(error) => {
            let _ = send_reply(&mut stream, 2).await;
            return Err(error.context("request one-time target ticket"));
        }
    };
    let ticket_endpoint = edge_tunnel_url(&ticket.edge_endpoint)?;
    if ticket.lease_id != expected_lease || ticket_endpoint != immutable_endpoint {
        send_reply(&mut stream, 2).await?;
        bail!("ticket changed immutable lease or Edge endpoint");
    }
    let secret = SecretString::from(ticket.ticket);
    if let Err(error) = connect_and_relay(stream, immutable_endpoint, &secret, &metrics).await {
        return Err(error.context("Edge binary relay"));
    }
    Ok(())
}

async fn heartbeat_loop(
    central: CentralClient,
    lease_id: String,
    device_id: String,
    interval: Duration,
    shutdown: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    timer.tick().await;
    loop {
        tokio::select! {
            _ = timer.tick() => {
                if let Err(error) = central.heartbeat(&lease_id, &device_id).await {
                    error!(error = %crate::redaction::redact(&error.to_string()), "heartbeat failed; shutting down");
                    let _ = shutdown.send(true);
                    return;
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() { return; }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(unix)]
async fn control_loop(
    listener: UnixListener,
    central: CentralClient,
    capability: SecretString,
    socks_port: u16,
    store_id: u64,
    device_id: String,
    metrics: Arc<EdgeLatencyTracker>,
    shutdown: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let central = central.clone();
                    let capability = capability.clone();
                    let device_id = device_id.clone();
                    let metrics = metrics.clone();
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_control(
                            stream,
                            &central,
                            &capability,
                            socks_port,
                            store_id,
                            device_id,
                            metrics,
                            shutdown,
                        )
                        .await
                        {
                            warn!(error = %crate::redaction::redact(&error.to_string()), "control request rejected");
                        }
                    });
                }
                Err(error) => {
                    warn!(error = %error, "control accept failed");
                    return;
                }
            },
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() { return; }
            }
        }
    }
}

#[cfg(windows)]
struct WindowsControlEndpoint {
    path: String,
    first: NamedPipeServer,
}

#[allow(clippy::too_many_arguments)]
#[cfg(windows)]
async fn control_loop(
    endpoint: WindowsControlEndpoint,
    central: CentralClient,
    capability: SecretString,
    socks_port: u16,
    store_id: u64,
    device_id: String,
    metrics: Arc<EdgeLatencyTracker>,
    shutdown: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let path = endpoint.path;
    let mut listener = endpoint.first;
    loop {
        tokio::select! {
            connected = listener.connect() => match connected {
                Ok(()) => {
                    let stream = listener;
                    listener = match create_secure_named_pipe(&path, false) {
                        Ok(next) => next,
                        Err(error) => {
                            warn!(error = %error, "control pipe create failed");
                            return;
                        }
                    };
                    let central = central.clone();
                    let capability = capability.clone();
                    let device_id = device_id.clone();
                    let metrics = metrics.clone();
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_control(
                            stream,
                            &central,
                            &capability,
                            socks_port,
                            store_id,
                            device_id,
                            metrics,
                            shutdown,
                        )
                        .await
                        {
                            warn!(error = %crate::redaction::redact(&error.to_string()), "control request rejected");
                        }
                    });
                }
                Err(error) => {
                    warn!(error = %error, "control pipe accept failed");
                    return;
                }
            },
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() { return; }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_control<S>(
    stream: S,
    central: &CentralClient,
    capability: &SecretString,
    socks_port: u16,
    store_id: u64,
    device_id: String,
    metrics: Arc<EdgeLatencyTracker>,
    shutdown: watch::Sender<bool>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(stream);
    let mut bytes = Vec::new();
    let count = {
        let mut limited = (&mut reader).take((MAX_CONTROL_REQUEST_BYTES + 1) as u64);
        limited.read_until(b'\n', &mut bytes).await?
    };
    if count == 0 || count > MAX_CONTROL_REQUEST_BYTES || bytes.last() != Some(&b'\n') {
        bail!("invalid control request size");
    }
    let request: ControlRequest =
        serde_json::from_slice(&bytes).context("invalid control request")?;
    if !authorize_secret(&request, capability) {
        bail!("unauthorized control request");
    }
    request.validate()?;
    let stream = reader.get_mut();
    match request.command {
        ControlCommand::Status => {
            let latency = metrics.snapshot();
            let response = StatusResponse {
                status: "connected",
                socks_host: "127.0.0.1",
                socks_port,
                store_id,
                device_id,
                edge_latency: Some(EdgeLatencyStatus::from(latency)),
            };
            let mut payload = serde_json::to_vec(&response)?;
            payload.push(b'\n');
            stream.write_all(&payload).await?;
        }
        ControlCommand::Shutdown => {
            stream
                .write_all(b"{\"status\":\"shutting_down\"}\n")
                .await?;
            let _ = shutdown.send(true);
        }
        ControlCommand::UpdateToken => {
            central.update_token(request.validated_update_token()?)?;
            stream.write_all(b"{\"status\":\"updated\"}\n").await?;
        }
    }
    stream.shutdown().await?;
    Ok(())
}

#[cfg(unix)]
fn bind_control_socket(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        bail!("control socket path already exists");
    }
    let listener = UnixListener::bind(path).context("bind control socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .context("secure control socket permissions")?;
    Ok(listener)
}

#[cfg(windows)]
fn bind_control_socket(path: &Path) -> Result<WindowsControlEndpoint> {
    let path = path.to_string_lossy().into_owned();
    let first = create_secure_named_pipe(&path, true)?;
    Ok(WindowsControlEndpoint { path, first })
}

#[cfg(unix)]
struct SocketCleanup<'a>(&'a Path);
#[cfg(unix)]
impl Drop for SocketCleanup<'_> {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(self.0)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(error = %error, "failed to remove control socket");
        }
    }
}

#[cfg(windows)]
struct SocketCleanup<'a>(#[allow(dead_code)] &'a Path);
#[cfg(windows)]
impl Drop for SocketCleanup<'_> {
    fn drop(&mut self) {}
}
