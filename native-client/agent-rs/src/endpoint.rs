use anyhow::{Result, bail};
use url::Url;

pub fn edge_tunnel_url(endpoint: &str) -> Result<Url> {
    let mut url = Url::parse(endpoint)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("invalid Edge endpoint");
    }
    match url.scheme() {
        "https" => url
            .set_scheme("wss")
            .map_err(|()| anyhow::anyhow!("invalid Edge scheme"))?,
        "http"
            if url
                .host_str()
                .is_some_and(|h| h == "127.0.0.1" || h == "localhost" || h == "::1") =>
        {
            url.set_scheme("ws")
                .map_err(|()| anyhow::anyhow!("invalid Edge scheme"))?;
        }
        _ => bail!("Edge endpoint must use HTTPS (HTTP only on loopback)"),
    }
    url.set_path("/v1/tunnel");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}
