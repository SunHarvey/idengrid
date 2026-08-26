use crate::{
    config::AgentConfig,
    dto::{
        ConnectRequest, ConnectResponse, DisconnectRequest, HeartbeatRequest, StoreDto,
        TicketRequest, TicketResponse,
    },
};
use anyhow::{Context, Result, bail};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};
use url::Url;

const MIN_ACCESS_TOKEN_BYTES: usize = 8;
const MAX_ACCESS_TOKEN_BYTES: usize = 8 * 1024;

pub fn validate_native_access_token(token: &SecretString) -> Result<()> {
    let value = token.expose_secret();
    if !(MIN_ACCESS_TOKEN_BYTES..=MAX_ACCESS_TOKEN_BYTES).contains(&value.len())
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        bail!("native_access_token is invalid");
    }
    Ok(())
}

#[derive(Clone)]
pub struct CentralClient {
    client: Client,
    base: Url,
    token: Arc<RwLock<SecretString>>,
    token_generation: Arc<AtomicU64>,
    store_id: u64,
}

impl CentralClient {
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let client = Client::builder()
            .https_only(config.central_url.scheme() == "https")
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        Ok(Self {
            client,
            base: config.central_url.clone(),
            token: Arc::new(RwLock::new(config.native_access_token.clone())),
            token_generation: Arc::new(AtomicU64::new(0)),
            store_id: config.store_id,
        })
    }
    fn url(&self, suffix: &str) -> Result<Url> {
        self.base.join(suffix).context("build Central API URL")
    }
    async fn checked<T: DeserializeOwned>(&self, response: reqwest::Response) -> Result<T> {
        let status = response.status();
        if !status.is_success() {
            bail!("Central API rejected request with HTTP {status}");
        }
        response
            .json::<T>()
            .await
            .context("invalid Central API response")
    }
    fn auth(&self, request: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder> {
        let token = self
            .token
            .read()
            .map_err(|_| anyhow::anyhow!("access token lock poisoned"))?;
        Ok(request.bearer_auth(token.expose_secret()))
    }
    fn token_snapshot(&self) -> Result<(SecretString, u64)> {
        let current = self
            .token
            .read()
            .map_err(|_| anyhow::anyhow!("access token lock poisoned"))?;
        let generation = self.token_generation.load(Ordering::Acquire);
        let token = current.clone();
        drop(current);
        Ok((token, generation))
    }
    #[must_use]
    pub fn token_generation(&self) -> u64 {
        self.token_generation.load(Ordering::Acquire)
    }
    pub fn update_token(&self, token: SecretString) -> Result<()> {
        validate_native_access_token(&token)?;
        let mut current = self
            .token
            .write()
            .map_err(|_| anyhow::anyhow!("access token lock poisoned"))?;
        *current = token;
        self.token_generation.fetch_add(1, Ordering::AcqRel);
        drop(current);
        Ok(())
    }
    pub async fn preflight(&self) -> Result<StoreDto> {
        let url = self.url("/api/stores")?;
        let stores: Vec<StoreDto> = self
            .checked(self.auth(self.client.get(url))?.send().await?)
            .await?;
        let store = stores
            .into_iter()
            .find(|s| s.id == self.store_id)
            .context("configured store is unavailable")?;
        store.validate()?;
        Ok(store)
    }
    pub async fn connect(&self, device_id: &str) -> Result<ConnectResponse> {
        let url = self.url(&format!("/api/stores/{}/connect", self.store_id))?;
        let dto: ConnectResponse = self
            .checked(
                self.auth(self.client.post(url))?
                    .json(&ConnectRequest { device_id })
                    .send()
                    .await?,
            )
            .await?;
        dto.validate()?;
        Ok(dto)
    }
    pub async fn ticket(
        &self,
        host: &str,
        port: u16,
        lease_id: &str,
        device_id: &str,
    ) -> Result<TicketResponse> {
        let url = self.url(&format!("/api/stores/{}/tickets", self.store_id))?;
        let response = self
            .auth(self.client.post(url))?
            .json(&TicketRequest {
                host,
                port,
                lease_id,
                device_id,
            })
            .send()
            .await?;
        if response.status() != StatusCode::CREATED && response.status() != StatusCode::OK {
            bail!(
                "Central API rejected ticket request with HTTP {}",
                response.status()
            );
        }
        let dto = response
            .json::<TicketResponse>()
            .await
            .context("invalid ticket response")?;
        dto.validate()?;
        Ok(dto)
    }
    pub async fn heartbeat(&self, lease_id: &str, device_id: &str) -> Result<()> {
        let url = self.url(&format!("/api/stores/{}/heartbeat", self.store_id))?;
        let (token, generation) = self.token_snapshot()?;
        let mut response = self
            .client
            .post(url.clone())
            .bearer_auth(token.expose_secret())
            .json(&HeartbeatRequest {
                lease_id,
                device_id,
            })
            .send()
            .await?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) && self.token_generation() != generation
        {
            response = self
                .auth(self.client.post(url))?
                .json(&HeartbeatRequest {
                    lease_id,
                    device_id,
                })
                .send()
                .await?;
        }
        if !response.status().is_success() {
            bail!("heartbeat rejected with HTTP {}", response.status());
        }
        Ok(())
    }
    pub async fn disconnect(&self, lease_id: &str, device_id: &str) -> Result<()> {
        let url = self.url(&format!("/api/stores/{}/disconnect", self.store_id))?;
        let response = self
            .auth(self.client.post(url))?
            .json(&DisconnectRequest {
                lease_id,
                device_id,
            })
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("disconnect rejected with HTTP {}", response.status());
        }
        Ok(())
    }
}
