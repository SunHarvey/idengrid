use crate::api::validate_native_access_token;
use anyhow::{Context, Result, bail};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
#[cfg(unix)]
use std::fs;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use url::Url;

const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_CONFIG_BYTES_U64: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub central_url: Url,
    pub native_access_token: SecretString,
    pub store_id: u64,
    pub device_id: String,
    pub control_socket_path: PathBuf,
    pub control_capability: SecretString,
    pub local_port: u16,
}

impl AgentConfig {
    pub fn validate(self) -> Result<Self> {
        let local_central = self.central_url.scheme() == "http"
            && self
                .central_url
                .host_str()
                .is_some_and(|h| h == "127.0.0.1" || h == "localhost" || h == "::1");
        if self.central_url.scheme() != "https" && !local_central {
            bail!("central_url must use HTTPS (HTTP is allowed only for loopback tests)");
        }
        if self.central_url.cannot_be_a_base()
            || self.central_url.host_str().is_none()
            || !self.central_url.username().is_empty()
            || self.central_url.password().is_some()
            || self.central_url.query().is_some()
            || self.central_url.fragment().is_some()
        {
            bail!("central_url must be an origin URL without credentials, query, or fragment");
        }
        if self.store_id == 0 {
            bail!("store_id must be positive");
        }
        if self.local_port != 0 {
            bail!("local_port must be 0 so the OS selects an ephemeral port");
        }
        validate_identifier("device_id", &self.device_id)?;
        if !self.control_socket_path.is_absolute() {
            bail!("control_socket_path must be absolute");
        }
        validate_native_access_token(&self.native_access_token)?;
        if self.control_capability.expose_secret().len() < 32 {
            bail!("control_capability must have at least 32 characters");
        }
        Ok(self)
    }
}

fn validate_identifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        bail!("{name} is invalid");
    }
    Ok(())
}

pub fn parse_config(bytes: &[u8]) -> Result<AgentConfig> {
    if bytes.len() > MAX_CONFIG_BYTES {
        bail!("config exceeds size limit");
    }
    serde_json::from_slice::<AgentConfig>(bytes)
        .context("invalid config JSON")?
        .validate()
}

pub fn load_config_stdin() -> Result<AgentConfig> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_CONFIG_BYTES_U64 + 1)
        .read_to_end(&mut bytes)
        .context("read config from stdin")?;
    parse_config(&bytes)
}

#[cfg(unix)]
pub fn load_config_file(path: &Path) -> Result<AgentConfig> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("open config file without following symlinks")?;
    let metadata = file.metadata().context("inspect opened config file")?;
    if !metadata.file_type().is_file() {
        bail!("config must be a regular non-symlink file");
    }
    if metadata.mode() & 0o777 != 0o600 {
        bail!("config permissions must be exactly 0600");
    }
    if metadata.len() > MAX_CONFIG_BYTES_U64 {
        bail!("config exceeds size limit");
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES_U64 + 1)
        .read_to_end(&mut bytes)
        .context("read config file")?;
    parse_config(&bytes)
}

#[cfg(not(unix))]
pub fn load_config_file(_path: &Path) -> Result<AgentConfig> {
    bail!("secure config file permission checks are unsupported on this platform; use stdin")
}
