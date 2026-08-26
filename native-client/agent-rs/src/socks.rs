use anyhow::{Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Hostname(String, u16),
    Ip(IpAddr, u16),
}
impl Target {
    #[must_use]
    pub fn host(&self) -> String {
        match self {
            Self::Hostname(h, _) => h.clone(),
            Self::Ip(ip, _) => ip.to_string(),
        }
    }
    #[must_use]
    pub const fn port(&self) -> u16 {
        match self {
            Self::Hostname(_, p) | Self::Ip(_, p) => *p,
        }
    }
}

pub fn parse_request(bytes: &[u8]) -> Result<Target> {
    if bytes.len() < 7 || bytes[0..3] != [5, 1, 0] {
        bail!("only SOCKS5 CONNECT is supported");
    }
    let (host, offset) = match bytes[3] {
        1 if bytes.len() >= 10 => (
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])).to_string(),
            8,
        ),
        3 => {
            let len = usize::from(bytes[4]);
            if !(1..=253).contains(&len) || bytes.len() < 5 + len + 2 {
                bail!("invalid hostname");
            }
            let host = std::str::from_utf8(&bytes[5..5 + len])?;
            validate_hostname(host)?;
            (host.to_ascii_lowercase(), 5 + len)
        }
        4 if bytes.len() >= 22 => {
            let octets: [u8; 16] = bytes[4..20].try_into()?;
            (IpAddr::V6(Ipv6Addr::from(octets)).to_string(), 20)
        }
        _ => bail!("unsupported SOCKS address type"),
    };
    let port = u16::from_be_bytes(bytes[offset..offset + 2].try_into()?);
    if port != 80 && port != 443 {
        bail!("only target ports 80 and 443 are permitted");
    }
    if bytes[3] == 3 {
        Ok(Target::Hostname(host, port))
    } else {
        Ok(Target::Ip(host.parse()?, port))
    }
}

fn validate_hostname(host: &str) -> Result<()> {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        bail!("invalid hostname");
    }
    Ok(())
}

pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<Target> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 || greeting[1] == 0 {
        bail!("invalid SOCKS greeting");
    }
    let mut methods = vec![0; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255]).await?;
        bail!("no-auth method unavailable");
    }
    stream.write_all(&[5, 0]).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let tail_len = match head[3] {
        1 => 6,
        4 => 18,
        3 => usize::from(stream.read_u8().await?) + 2,
        _ => {
            send_reply(stream, 8).await?;
            bail!("unsupported address type")
        }
    };
    let mut request = head.to_vec();
    if head[3] == 3 {
        request.push(u8::try_from(tail_len - 2)?);
    }
    let mut tail = vec![0; tail_len];
    stream.read_exact(&mut tail).await?;
    request.extend(tail);
    parse_request(&request)
}

pub async fn send_reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> std::io::Result<()> {
    stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}
