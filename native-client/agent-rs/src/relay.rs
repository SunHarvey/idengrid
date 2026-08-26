use crate::metrics::EdgeLatencyTracker;
use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use http::header::{AUTHORIZATION, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use url::Url;

const BUFFER_SIZE: usize = 16 * 1024;
const PROBE_INTERVAL: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const OWNER_RETRY_INTERVAL: Duration = Duration::from_secs(1);

pub async fn connect_and_relay<S>(
    mut local: S,
    endpoint: Url,
    ticket: &SecretString,
    tracker: &EdgeLatencyTracker,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = endpoint
        .as_str()
        .into_client_request()
        .context("build Edge WebSocket request")?;
    let authorization = HeaderValue::from_str(&format!("Bearer {}", ticket.expose_secret()))
        .context("invalid Edge ticket")?;
    request.headers_mut().insert(AUTHORIZATION, authorization);
    let (websocket, _) = connect_async(request)
        .await
        .context("connect to Edge WebSocket")?;
    crate::socks::send_reply(&mut local, 0).await?;

    let lease = tracker.relay_started();
    let _ = lease.try_claim_probe();
    let (mut websocket_write, mut websocket_read) = websocket.split();
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut next_probe = tokio::time::Instant::now();
    let mut owner_retry = tokio::time::interval(OWNER_RETRY_INTERVAL);
    owner_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut outstanding: Option<([u8; 8], Instant)> = None;

    loop {
        tokio::select! {
            read = local_read.read(&mut buffer) => {
                let read = read?;
                if read == 0 {
                    websocket_write.send(Message::Close(None)).await?;
                    return Ok(());
                }
                websocket_write
                    .send(Message::Binary(buffer[..read].to_vec().into()))
                    .await?;
            }
            message = websocket_read.next() => {
                match message.transpose()? {
                    Some(Message::Binary(bytes)) => local_write.write_all(&bytes).await?,
                    Some(Message::Close(_)) | None => return Ok(()),
                    Some(Message::Text(_)) => bail!("Edge sent a forbidden text frame"),
                    Some(Message::Ping(bytes)) => websocket_write.send(Message::Pong(bytes)).await?,
                    Some(Message::Pong(bytes)) => {
                        if let Some((expected, started)) = outstanding
                            && bytes.as_ref() == expected
                        {
                            tracker.record_success(started.elapsed(), std::time::SystemTime::now());
                            outstanding = None;
                        }
                    }
                    Some(Message::Frame(_)) => {}
                }
            }
            () = tokio::time::sleep_until(next_probe), if lease.owns_probe() && outstanding.is_none() => {
                let payload = lease.next_nonce().to_be_bytes();
                websocket_write.send(Message::Ping(payload.to_vec().into())).await?;
                outstanding = Some((payload, Instant::now()));
                next_probe = tokio::time::Instant::now() + PROBE_INTERVAL;
            }
            () = probe_timeout(outstanding.as_ref()), if outstanding.is_some() => {
                tracker.record_failure();
                outstanding = None;
            }
            _ = owner_retry.tick() => {
                if !lease.owns_probe() && lease.try_claim_probe() {
                    next_probe = tokio::time::Instant::now();
                }
            }
        }
    }
}

async fn probe_timeout(outstanding: Option<&([u8; 8], Instant)>) {
    if let Some((_, started)) = outstanding {
        tokio::time::sleep_until((*started + PROBE_TIMEOUT).into()).await;
    } else {
        std::future::pending::<()>().await;
    }
}
