#![allow(clippy::unwrap_used)]

use idengrid_agent::{
    api::CentralClient,
    config::{AgentConfig, load_config_file},
    dto::{ConnectResponse, TicketResponse},
    endpoint::edge_tunnel_url,
    ipc::{ControlRequest, EdgeLatencyStatus, StatusResponse, authorize},
    metrics::{EdgeLatencyState, EdgeLatencyTracker},
    redaction::redact,
    socks::{Target, parse_request},
};
use secrecy::{ExposeSecret, SecretString};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, UNIX_EPOCH},
};
use tempfile::tempdir;

fn valid_config() -> serde_json::Value {
    serde_json::json!({
        "central_url":"https://central.example",
        "native_access_token":"short-lived-secret",
        "store_id":42,
        "device_id":"mac-01",
        "control_socket_path":"/tmp/idengrid.sock",
        "control_capability":"control-secret-32-bytes-minimum-value",
        "local_port":0
    })
}

#[test]
fn edge_latency_tracker_is_deterministic_and_classifies_health() {
    let tracker = EdgeLatencyTracker::default();
    let base = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let relay = tracker.relay_started();

    assert_eq!(tracker.snapshot_at(base).state, EdgeLatencyState::Warming);
    tracker.record_success(Duration::from_millis(100), base);
    tracker.record_success(Duration::from_millis(200), base + Duration::from_secs(10));
    let fresh = tracker.snapshot_at(base + Duration::from_secs(10));
    assert_eq!(fresh.latest_rtt_ms, Some(200));
    assert_eq!(fresh.ewma_rtt_ms, Some(125));
    assert_eq!(fresh.jitter_ms, Some(25));
    assert_eq!(fresh.sample_count, 2);
    assert_eq!(fresh.active_relays, 1);
    assert_eq!(fresh.consecutive_failures, 0);
    assert_eq!(fresh.state, EdgeLatencyState::Fresh);

    tracker.record_failure();
    assert_eq!(
        tracker.snapshot_at(base + Duration::from_secs(15)).state,
        EdgeLatencyState::Degraded
    );
    assert_eq!(
        tracker.snapshot_at(base + Duration::from_secs(41)).state,
        EdgeLatencyState::Stale
    );
    drop(relay);
    assert_eq!(
        tracker.snapshot_at(base + Duration::from_secs(41)).state,
        EdgeLatencyState::Unavailable
    );
}

#[test]
fn edge_latency_probe_has_only_one_owner_and_fails_over() {
    let tracker = EdgeLatencyTracker::default();
    let first = tracker.relay_started();
    let second = tracker.relay_started();
    assert!(first.try_claim_probe());
    assert!(!second.try_claim_probe());
    drop(first);
    assert!(second.try_claim_probe());
}

#[test]
fn ipc_latency_is_nested_scoped_and_contains_no_secrets() {
    let response = StatusResponse {
        status: "connected",
        socks_host: "127.0.0.1",
        socks_port: 1234,
        store_id: 42,
        device_id: "mac-01".to_owned(),
        edge_latency: Some(EdgeLatencyStatus {
            scope: "mac_to_edge_websocket_rtt",
            source: "websocket_ping",
            state: EdgeLatencyState::Fresh,
            latest_rtt_ms: Some(80),
            ewma_rtt_ms: Some(75),
            jitter_ms: Some(4),
            sample_count: 3,
            active_relays: 1,
            consecutive_failures: 0,
            updated_at_unix_ms: Some(1_800_000_000_000),
        }),
    };
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["edge_latency"]["scope"], "mac_to_edge_websocket_rtt");
    assert_eq!(value["edge_latency"]["source"], "websocket_ping");
    assert!(value.get("edge_latency_ms").is_none());
    let encoded = value.to_string();
    assert!(!encoded.contains("endpoint"));
    assert!(!encoded.contains("ticket"));
    assert!(!encoded.contains("nonce"));
}

#[test]
fn config_is_strict_and_validated() {
    let config: AgentConfig = serde_json::from_value(valid_config()).unwrap();
    assert_eq!(config.validate().unwrap().store_id, 42);
    let mut bad = valid_config();
    bad["surprise"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AgentConfig>(bad).is_err());
}

#[cfg(unix)]
#[test]
fn config_file_rejects_group_readable_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.json");
    fs::write(&path, valid_config().to_string()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(load_config_file(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_config_file(&path).is_ok());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(load_config_file(&path).is_err());
}

#[cfg(unix)]
#[test]
fn config_file_rejects_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempdir().unwrap();
    let target = dir.path().join("target.json");
    let link = dir.path().join("config.json");
    fs::write(&target, valid_config().to_string()).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &link).unwrap();
    assert!(load_config_file(&link).is_err());
}

#[test]
fn redaction_removes_bearer_and_named_secrets() {
    let text = r#"Authorization: Bearer abc.def {"ticket":"once","native_access_token":"native"}"#;
    let safe = redact(text);
    assert!(!safe.contains("abc.def"));
    assert!(!safe.contains("once"));
    assert!(!safe.contains(":\"native\""));
}

#[test]
fn response_dtos_reject_missing_and_empty_but_accept_backend_extensions() {
    let good = r#"{"lease_id":"l1","status":"active","edge_endpoint":"https://edge.example","created_at":"now","expires_at":"later","expires_in":60}"#;
    assert!(
        serde_json::from_str::<ConnectResponse>(good)
            .unwrap()
            .validate()
            .is_ok()
    );
    let unknown = good.replace('}', ",\"secret\":\"leak\"}");
    assert!(serde_json::from_str::<ConnectResponse>(&unknown).is_ok());
    let ticket =
        r#"{"ticket":"t1","lease_id":"l1","edge_endpoint":"https://edge.example","expires_in":60}"#;
    assert!(
        serde_json::from_str::<TicketResponse>(ticket)
            .unwrap()
            .validate()
            .is_ok()
    );
}

#[test]
fn endpoint_conversion_is_origin_only_and_tls_by_default() {
    assert_eq!(
        edge_tunnel_url("https://edge.example/base")
            .unwrap()
            .as_str(),
        "wss://edge.example/v1/tunnel"
    );
    assert_eq!(
        edge_tunnel_url("http://127.0.0.1:8080").unwrap().as_str(),
        "ws://127.0.0.1:8080/v1/tunnel"
    );
    assert!(edge_tunnel_url("ftp://edge.example").is_err());
    assert!(edge_tunnel_url("https://user:pass@edge.example").is_err());
}

#[test]
fn socks_parses_hostname_ipv4_ipv6_and_restricts_ports() {
    let host = [
        5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 1, 187,
    ];
    assert_eq!(
        parse_request(&host).unwrap(),
        Target::Hostname("example.com".into(), 443)
    );
    let ip4 = [5, 1, 0, 1, 1, 1, 1, 1, 0, 80];
    assert_eq!(
        parse_request(&ip4).unwrap(),
        Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80)
    );
    let mut ip6 = vec![5, 1, 0, 4];
    ip6.extend(Ipv6Addr::LOCALHOST.octets());
    ip6.extend(443u16.to_be_bytes());
    assert!(matches!(
        parse_request(&ip6).unwrap(),
        Target::Ip(IpAddr::V6(_), 443)
    ));
    let mut forbidden = ip4;
    forbidden[8..].copy_from_slice(&22u16.to_be_bytes());
    assert!(parse_request(&forbidden).is_err());
}

#[test]
fn ipc_auth_uses_capability_and_strict_request_dto() {
    let req: ControlRequest =
        serde_json::from_str(r#"{"capability":"right","command":"status"}"#).unwrap();
    assert!(authorize(&req, "right"));
    assert!(!authorize(&req, "wrong"));
    assert!(
        serde_json::from_str::<ControlRequest>(
            r#"{"capability":"x","command":"status","extra":1}"#
        )
        .is_err()
    );
}

#[test]
fn update_token_request_is_strict_validated_and_redacted() {
    let request: ControlRequest = serde_json::from_str(
        r#"{"capability":"right","command":"update_token","native_access_token":"replacement-token"}"#,
    )
    .unwrap();
    let token = request.validated_update_token().unwrap();
    assert_eq!(token.expose_secret(), "replacement-token");
    assert!(!format!("{request:?}").contains("replacement-token"));

    for invalid in [
        r#"{"capability":"right","command":"update_token"}"#,
        r#"{"capability":"right","command":"update_token","native_access_token":"short"}"#,
        r#"{"capability":"right","command":"status","native_access_token":"replacement-token"}"#,
    ] {
        let request: ControlRequest = serde_json::from_str(invalid).unwrap();
        assert!(request.validate().is_err());
    }
    assert!(
        serde_json::from_str::<ControlRequest>(
            r#"{"capability":"right","command":"update_token","native_access_token":"replacement-token","extra":true}"#
        )
        .is_err()
    );
}

#[test]
fn central_token_generation_advances_only_after_valid_update() {
    let config: AgentConfig = serde_json::from_value(valid_config()).unwrap();
    let client = CentralClient::new(&config).unwrap();
    let initial = client.token_generation();
    assert!(client.update_token(SecretString::from("short")).is_err());
    assert_eq!(client.token_generation(), initial);
    client
        .update_token(SecretString::from("replacement-native-access-token"))
        .unwrap();
    assert_eq!(client.token_generation(), initial + 1);
}
