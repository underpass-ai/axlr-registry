//! The loopback listener: plain HTTP/1.1, one task per connection.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::{HttpBridge, LocalError, LocalRegistry};

/// A bound listener, ready to serve a registry.
#[derive(Debug)]
pub struct LocalServer {
    listener: TcpListener,
    address: SocketAddr,
}

impl LocalServer {
    /// Binds `address`; port 0 picks a free one.
    pub async fn bind(address: SocketAddr) -> Result<Self, LocalError> {
        let listener = TcpListener::bind(address).await.map_err(|e| LocalError::io(address, e))?;
        let address = listener.local_addr().map_err(|e| LocalError::io(address, e))?;
        Ok(Self { listener, address })
    }

    /// The address bound.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// `http://<address>`: the catalog's URL and the publish API's.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Serves until the task is dropped or accepting fails.
    pub async fn serve(self, registry: Arc<LocalRegistry>) -> Result<(), LocalError> {
        loop {
            let (stream, peer) = self.listener.accept().await.map_err(|e| LocalError::io(self.address, e))?;
            let registry = Arc::clone(&registry);
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let registry = Arc::clone(&registry);
                    async move { Ok::<_, Infallible>(HttpBridge::serve(&registry, request, peer.ip()).await) }
                });
                if let Err(error) = http1::Builder::new().serve_connection(TokioIo::new(stream), service).await {
                    eprintln!("connection from {peer}: {error}");
                }
            });
        }
    }
}
