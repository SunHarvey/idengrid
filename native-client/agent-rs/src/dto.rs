use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct StoreDto {
    pub id: u64,
    pub label: String,
    pub edge_endpoint: String,
    pub expected_egress_ips: Vec<String>,
}

impl StoreDto {
    pub fn validate(&self) -> Result<()> {
        if self.id == 0 || self.label.trim().is_empty() || self.expected_egress_ips.is_empty() {
            bail!("invalid store response");
        }
        crate::endpoint::edge_tunnel_url(&self.edge_endpoint)?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct ConnectResponse {
    pub lease_id: String,
    pub status: String,
    pub edge_endpoint: String,
    pub created_at: String,
    pub expires_at: String,
    pub expires_in: u64,
}
impl ConnectResponse {
    pub fn validate(&self) -> Result<()> {
        nonempty(&self.lease_id)?;
        nonempty(&self.created_at)?;
        nonempty(&self.expires_at)?;
        if self.status != "active" || self.expires_in == 0 {
            bail!("invalid connection response");
        }
        crate::endpoint::edge_tunnel_url(&self.edge_endpoint)?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct TicketResponse {
    pub ticket: String,
    pub lease_id: String,
    pub edge_endpoint: String,
    pub expires_in: u64,
}
impl TicketResponse {
    pub fn validate(&self) -> Result<()> {
        nonempty(&self.ticket)?;
        nonempty(&self.lease_id)?;
        if self.expires_in == 0 || self.expires_in > 60 {
            bail!("invalid ticket response");
        }
        crate::endpoint::edge_tunnel_url(&self.edge_endpoint)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct ConnectRequest<'a> {
    pub device_id: &'a str,
}
#[derive(Serialize)]
pub struct HeartbeatRequest<'a> {
    pub lease_id: &'a str,
    pub device_id: &'a str,
}
#[derive(Serialize)]
pub struct TicketRequest<'a> {
    pub host: &'a str,
    pub port: u16,
    pub lease_id: &'a str,
    pub device_id: &'a str,
}
#[derive(Serialize)]
pub struct DisconnectRequest<'a> {
    pub lease_id: &'a str,
    pub device_id: &'a str,
}

fn nonempty(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 8192 {
        bail!("required DTO string is invalid");
    }
    Ok(())
}
