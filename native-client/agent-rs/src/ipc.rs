use crate::{
    api::validate_native_access_token,
    metrics::{EdgeLatencySnapshot, EdgeLatencyState},
};
use anyhow::{Result, bail};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ControlCommand {
    Status,
    Shutdown,
    UpdateToken,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub capability: SecretString,
    pub command: ControlCommand,
    pub native_access_token: Option<SecretString>,
}

impl ControlRequest {
    pub fn validate(&self) -> Result<()> {
        match (&self.command, &self.native_access_token) {
            (ControlCommand::UpdateToken, Some(token)) => validate_native_access_token(token),
            (ControlCommand::UpdateToken, None) => bail!("native_access_token is required"),
            (_, Some(_)) => bail!("native_access_token is only valid for update_token"),
            (_, None) => Ok(()),
        }
    }

    pub fn validated_update_token(&self) -> Result<SecretString> {
        self.validate()?;
        match (&self.command, &self.native_access_token) {
            (ControlCommand::UpdateToken, Some(token)) => Ok(token.clone()),
            _ => bail!("control command is not update_token"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
    pub socks_host: &'static str,
    pub socks_port: u16,
    pub store_id: u64,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_latency: Option<EdgeLatencyStatus>,
}

#[derive(Debug, Serialize)]
pub struct EdgeLatencyStatus {
    pub scope: &'static str,
    pub source: &'static str,
    pub state: EdgeLatencyState,
    pub latest_rtt_ms: Option<u64>,
    pub ewma_rtt_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub sample_count: u64,
    pub active_relays: u64,
    pub consecutive_failures: u64,
    pub updated_at_unix_ms: Option<u64>,
}

impl From<EdgeLatencySnapshot> for EdgeLatencyStatus {
    fn from(snapshot: EdgeLatencySnapshot) -> Self {
        Self {
            scope: "mac_to_edge_websocket_rtt",
            source: "websocket_ping",
            state: snapshot.state,
            latest_rtt_ms: snapshot.latest_rtt_ms,
            ewma_rtt_ms: snapshot.ewma_rtt_ms,
            jitter_ms: snapshot.jitter_ms,
            sample_count: snapshot.sample_count,
            active_relays: snapshot.active_relays,
            consecutive_failures: snapshot.consecutive_failures,
            updated_at_unix_ms: snapshot.updated_at_unix_ms,
        }
    }
}

#[must_use]
pub fn authorize(request: &ControlRequest, expected: &str) -> bool {
    request
        .capability
        .expose_secret()
        .as_bytes()
        .ct_eq(expected.as_bytes())
        .into()
}

#[must_use]
pub fn authorize_secret(request: &ControlRequest, expected: &SecretString) -> bool {
    authorize(request, expected.expose_secret())
}
