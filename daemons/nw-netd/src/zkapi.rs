//! Experimental client-side protocol adapter, excluded from the daemon factory.
//! A caller must supply an already authenticated/isolated stream; this module
//! cannot resolve names, open sockets, start clientd or sign/fund anything.
//! No real connector is allowed until ADR 0107's deployment/rewrite gates pass.
use nw_net::wire::Request;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn exchange<S>(
    stream: S,
    authority: &str,
    request: &Request,
) -> Result<String, &'static str>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::validate(request)?;
    // This protocol probe is intentionally restricted to numeric loopback.
    // Production has no connector to it and no route around nw-netd.
    let address: std::net::SocketAddr = authority.parse().map_err(|_| "invalid_zkapi_endpoint")?;
    if !address.ip().is_loopback() || address.port() == 0 || request.authorization.len() < 32 {
        return Err("invalid_zkapi_endpoint");
    }
    tokio::time::timeout(
        Duration::from_secs(120),
        crate::http_exchange_to(stream, authority, nw_net::zkapi::PATH, request, true),
    )
    .await
    .map_err(|_| "zkapi_timeout")?
}

#[cfg(test)]
#[path = "../../../tests/leak/src/netd_zkapi.rs"]
mod tests;
