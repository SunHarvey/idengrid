#![allow(clippy::unwrap_used)]

use axum::{
    Json, Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use futures_util::StreamExt;
use idengrid_agent::{
    agent::{AgentReady, RuntimeOptions, run},
    config::AgentConfig,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    sync::oneshot,
};

#[derive(Clone)]
struct MockState {
    origin: String,
    tickets: Arc<AtomicUsize>,
    heartbeats: Arc<AtomicUsize>,
    disconnects: Arc<AtomicUsize>,
    websocket_upgrades: Arc<AtomicUsize>,
    authorizations: Arc<Mutex<Vec<String>>>,
}

fn record_authorization(state: &MockState, headers: &HeaderMap) {
    if let Some(value) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    {
        state.authorizations.lock().unwrap().push(value.to_owned());
    }
}

async fn stores(State(state): State<MockState>, headers: HeaderMap) -> Json<Value> {
    record_authorization(&state, &headers);
    Json(json!([{
        "id": 42,
        "label": "Singapore",
        "enabled": true,
        "edge_node_name": "edge-test",
        "edge_endpoint": state.origin,
        "expected_egress_ips": ["203.0.113.10"],
        "connection_status": "disconnected",
        "health_status": "healthy"
    }]))
}

async fn connect(State(state): State<MockState>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    record_authorization(&state, &headers);
    (
        StatusCode::CREATED,
        Json(json!({
            "lease_id": "0123456789abcdef0123456789abcdef",
            "status": "active",
            "edge_endpoint": state.origin,
            "created_at": "2026-08-19T00:00:00Z",
            "expires_at": "2026-08-19T08:00:00Z",
            "expires_in": 28800,
            "capabilities": [],
            "recovered": false
        })),
    )
}

async fn ticket(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    record_authorization(&state, &headers);
    assert_eq!(body["lease_id"], "0123456789abcdef0123456789abcdef");
    assert_eq!(body["device_id"], "mac-test-01");
    let number = state.tickets.fetch_add(1, Ordering::SeqCst) + 1;
    let endpoint = if number == 1 {
        state.origin
    } else {
        "https://changed-edge.invalid".to_owned()
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "ticket": format!("single-use-ticket-{number}"),
            "lease_id": "0123456789abcdef0123456789abcdef",
            "edge_endpoint": endpoint,
            "expires_in": 60
        })),
    )
}

async fn heartbeat(State(state): State<MockState>, headers: HeaderMap) -> Json<Value> {
    record_authorization(&state, &headers);
    state.heartbeats.fetch_add(1, Ordering::SeqCst);
    Json(
        json!({"lease_id":"0123456789abcdef0123456789abcdef", "status":"active", "expires_in":28800}),
    )
}

async fn disconnect(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    record_authorization(&state, &headers);
    assert_eq!(body["lease_id"], "0123456789abcdef0123456789abcdef");
    assert_eq!(body["device_id"], "mac-test-01");
    state.disconnects.fetch_add(1, Ordering::SeqCst);
    Json(json!({"lease_id":"0123456789abcdef0123456789abcdef", "status":"disconnected"}))
}

async fn tunnel(
    State(state): State<MockState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer single-use-ticket-1")
    );
    state.websocket_upgrades.fetch_add(1, Ordering::SeqCst);
    upgrade.on_upgrade(echo_binary)
}

async fn echo_binary(mut socket: WebSocket) {
    while let Some(Ok(message)) = socket.next().await {
        match message {
            Message::Binary(bytes) => {
                if socket.send(Message::Binary(bytes)).await.is_err() {
                    break;
                }
            }
            Message::Ping(bytes) => {
                if socket
                    .send(Message::Pong(vec![0_u8; 8].into()))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
                if socket.send(Message::Pong(bytes)).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

fn config(origin: &str, socket: PathBuf) -> AgentConfig {
    AgentConfig {
        central_url: origin.parse().unwrap(),
        native_access_token: SecretString::from("native-token-for-tests"),
        store_id: 42,
        device_id: "mac-test-01".to_owned(),
        control_socket_path: socket,
        control_capability: SecretString::from("control-capability-at-least-32-bytes"),
        local_port: 0,
    }
}

async fn socks_connect(address: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let host = b"example.com";
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host);
    request.extend_from_slice(&443_u16.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    stream
}

async fn read_reply(stream: &mut TcpStream) -> [u8; 10] {
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    reply
}

async fn control_request(socket: &PathBuf, payload: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn full_runtime_is_fail_closed_and_cleans_up() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
    let state = MockState {
        origin: origin.clone(),
        tickets: Arc::new(AtomicUsize::new(0)),
        heartbeats: Arc::new(AtomicUsize::new(0)),
        disconnects: Arc::new(AtomicUsize::new(0)),
        websocket_upgrades: Arc::new(AtomicUsize::new(0)),
        authorizations: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/api/stores", get(stores))
        .route("/api/stores/42/connect", post(connect))
        .route("/api/stores/42/tickets", post(ticket))
        .route("/api/stores/42/heartbeat", post(heartbeat))
        .route("/api/stores/42/disconnect", post(disconnect))
        .route("/v1/tunnel", get(tunnel))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    let control_socket = directory.path().join("agent.sock");
    let (ready_tx, ready_rx) = oneshot::channel::<AgentReady>();
    let agent = tokio::spawn(run(
        config(&origin, control_socket.clone()),
        RuntimeOptions {
            heartbeat_interval: Duration::from_millis(20),
        },
        ready_tx,
    ));
    let ready = ready_rx.await.unwrap();
    assert_eq!(ready.socks_addr.ip().to_string(), "127.0.0.1");
    assert_ne!(ready.socks_addr.port(), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&control_socket)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let denied = control_request(
        &control_socket,
        b"{\"capability\":\"wrong-capability-at-least-32-bytes\",\"command\":\"update_token\",\"native_access_token\":\"unauthorized-replacement\"}\n",
    )
    .await;
    assert!(denied.is_empty());

    let mut first = socks_connect(ready.socks_addr).await;
    assert_eq!(read_reply(&mut first).await[1], 0);
    assert_eq!(
        state
            .authorizations
            .lock()
            .unwrap()
            .last()
            .map(String::as_str),
        Some("Bearer native-token-for-tests")
    );

    let updated = control_request(
        &control_socket,
        b"{\"capability\":\"control-capability-at-least-32-bytes\",\"command\":\"update_token\",\"native_access_token\":\"authorized-replacement-token\"}\n",
    )
    .await;
    assert_eq!(updated, b"{\"status\":\"updated\"}\n");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if state
                .authorizations
                .lock()
                .unwrap()
                .iter()
                .any(|value| value == "Bearer authorized-replacement-token")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    first.write_all(b"binary relay payload").await.unwrap();
    let mut echoed = [0; 20];
    first.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"binary relay payload");
    tokio::time::timeout(Duration::from_secs(1), async {
        while state.heartbeats.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(80)).await;
    let mut ipc = UnixStream::connect(&control_socket).await.unwrap();
    ipc.write_all(
        b"{\"capability\":\"control-capability-at-least-32-bytes\",\"command\":\"status\"}\n",
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    ipc.read_to_end(&mut response).await.unwrap();
    assert_eq!(response.last(), Some(&b'\n'));
    let status: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(status["status"], "connected");
    assert_eq!(status["socks_port"], ready.socks_addr.port());
    assert_eq!(status["edge_latency"]["scope"], "mac_to_edge_websocket_rtt");
    assert_eq!(status["edge_latency"]["source"], "websocket_ping");
    assert_eq!(status["edge_latency"]["state"], "fresh");
    assert!(status["edge_latency"]["latest_rtt_ms"].as_u64().unwrap() >= 35);
    assert_eq!(status["edge_latency"]["sample_count"], 1);
    assert_eq!(status["edge_latency"]["active_relays"], 1);
    assert!(status.get("edge_latency_ms").is_none());

    first
        .write_all(b"traffic survives latency probe")
        .await
        .unwrap();
    let mut survived = [0; 30];
    first.read_exact(&mut survived).await.unwrap();
    assert_eq!(&survived, b"traffic survives latency probe");
    drop(first);

    let mut second = socks_connect(ready.socks_addr).await;
    assert_ne!(read_reply(&mut second).await[1], 0);
    assert_eq!(state.tickets.load(Ordering::SeqCst), 2);
    assert_eq!(state.websocket_upgrades.load(Ordering::SeqCst), 1);

    let mut ipc = UnixStream::connect(&control_socket).await.unwrap();
    ipc.write_all(
        b"{\"capability\":\"control-capability-at-least-32-bytes\",\"command\":\"shutdown\"}\n",
    )
    .await
    .unwrap();
    ipc.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), agent)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(state.disconnects.load(Ordering::SeqCst), 1);
    assert!(!control_socket.exists());
    server.abort();
}
