#[macro_use]
extern crate log;

use crate::util::opt_timeout;
use anyhow::{Context, Result, bail};
use futures_core::future::BoxFuture;
use lazy_static::lazy_static;
use routing::RoutingNode;
use std::{
    collections::HashMap, convert::TryFrom, iter::FromIterator, panic::AssertUnwindSafe,
    path::PathBuf, sync::Arc, time::Duration,
};
use tls::{tls_config, tls_sni_config};
use tokio::{
    io::{self, AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

pub mod routing;
pub mod tls;
pub mod types;
pub mod util;

pub use mime;
pub use types::*;
pub use uriparse as uri;

pub const REQUEST_URI_MAX_LEN: usize = 1024;
pub const GEMINI_PORT: u16 = 1965;

type Handler = Arc<dyn Fn(Request) -> HandlerResponse + Send + Sync>;
pub(crate) type HandlerResponse = BoxFuture<'static, Result<Response>>;

#[derive(Clone)]
pub struct Server {
    tls_acceptor: TlsAcceptor,
    listener: Arc<TcpListener>,
    routes: Arc<RoutingNode<Handler>>,
    timeout: Duration,
    complex_timeout: Option<Duration>,
}

impl Server {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Builder<A> {
        Builder::bind(addr)
    }

    async fn serve(self) -> Result<()> {
        loop {
            let (stream, _addr) = self
                .listener
                .accept()
                .await
                .context("Failed to accept client")?;
            let this = self.clone();

            tokio::spawn(async move {
                if let Err(err) = this.serve_client(stream).await {
                    error!("{:?}", err);
                }
            });
        }
    }

    async fn serve_client(self, stream: TcpStream) -> Result<()> {
        let fut_accept_request = async {
            let stream = self
                .tls_acceptor
                .accept(stream)
                .await
                .context("Failed to establish TLS session")?;
            let mut stream = BufStream::new(stream);

            let request = receive_request(&mut stream)
                .await
                .context("Failed to receive request")?;

            Result::<_, anyhow::Error>::Ok((request, stream))
        };

        // Use a timeout for interacting with the client
        let fut_accept_request = timeout(self.timeout, fut_accept_request);
        let (mut request, mut stream) = fut_accept_request
            .await
            .context("Client timed out while waiting for response")??;

        let server_name = stream.get_ref().get_ref().1.server_name();

        if let Some(name) = server_name {
            debug!("[{}] Client requested: {}", name, request.uri());
        } else {
            debug!("[] Client requested: {}", request.uri());
        }

        // Identify the client certificate from the tls stream.  This is the first
        // certificate in the certificate chain.
        let client_cert = stream
            .get_ref()
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|v| {
                if v.is_empty() {
                    None
                } else {
                    Some(v[0].clone())
                }
            });

        request.set_server_name(server_name.map(str::to_string));
        request.set_cert(client_cert);
        request.set_peer(
            stream
                .get_ref()
                .get_ref()
                .0
                .peer_addr()
                .ok()
                .map(|a| a.to_string()),
        );

        let response = if let Some((trailing, handler)) = self.routes.match_request(&request) {
            request.set_trailing(trailing);

            let handler = (handler)(request);
            let handler = AssertUnwindSafe(handler);

            util::HandlerCatchUnwind::new(handler)
                .await
                .unwrap_or_else(|_| Response::server_error(""))
                .or_else(|err| {
                    error!("Handler failed: {:?}", err);
                    Response::server_error("")
                })
                .context("Request handler failed")?
        } else {
            Response::not_found()
        };

        self.send_response(response, &mut stream)
            .await
            .context("Failed to send response")?;

        Ok(())
    }

    async fn send_response(
        &self,
        mut response: Response,
        stream: &mut (impl AsyncWrite + Unpin),
    ) -> Result<()> {
        let maybe_body = response.take_body();
        let header = response.header();

        let use_complex_timeout = header.status.is_success()
            && maybe_body.is_some()
            && header.meta.as_str() != "text/plain"
            && header.meta.as_str() != "text/gemini"
            && self.complex_timeout.is_some();

        let send_general_timeout;
        let send_header_timeout;
        let send_body_timeout;

        if use_complex_timeout {
            send_general_timeout = None;
            send_header_timeout = Some(self.timeout);
            send_body_timeout = self.complex_timeout;
        } else {
            send_general_timeout = Some(self.timeout);
            send_header_timeout = None;
            send_body_timeout = None;
        }

        opt_timeout(send_general_timeout, async {
            // Send the header
            opt_timeout(
                send_header_timeout,
                send_response_header(response.header(), stream),
            )
            .await
            .context("Timed out while sending response header")?
            .context("Failed to write response header")?;

            // Send the body
            opt_timeout(
                send_body_timeout,
                maybe_send_response_body(maybe_body, stream),
            )
            .await
            .context("Timed out while sending response body")?
            .context("Failed to write response body")?;

            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("Timed out while sending response data")??;

        Ok(())
    }
}

pub struct Builder<A> {
    addr: A,

    cert_path: PathBuf,
    key_path: PathBuf,
    cert_key_mapping: Option<HashMap<String, (PathBuf, PathBuf)>>,

    timeout: Duration,
    complex_body_timeout_override: Option<Duration>,
    routes: RoutingNode<Handler>,
}

impl<A: ToSocketAddrs> Builder<A> {
    fn bind(addr: A) -> Self {
        Self {
            addr,
            timeout: Duration::from_secs(1),
            complex_body_timeout_override: Some(Duration::from_secs(30)),
            cert_path: PathBuf::from("cert/cert.pem"),
            key_path: PathBuf::from("cert/key.pem"),
            cert_key_mapping: None,
            routes: RoutingNode::default(),
        }
    }

    /// Sets the directory that twinstar should look for TLS certs and keys into
    ///
    /// Northstar will look for files called `cert.pem` and `key.pem` in the provided
    /// directory.
    ///
    /// This does not need to be set if both [`set_cert()`](Self::set_cert()) and
    /// [`set_key()`](Self::set_key()) have been called.
    ///
    /// If not set, the default is `cert/`
    pub fn set_tls_dir(self, dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        self.set_cert(dir.join("cert.pem"))
            .set_key(dir.join("key.pem"))
    }

    /// Set the path to the TLS certificate twinstar will use
    ///
    /// This defaults to `cert/cert.pem`.
    ///
    /// This does not need to be called it [`set_tls_dir()`](Self::set_tls_dir()) has been
    /// called.
    pub fn set_cert(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.cert_path = cert_path.into();
        self
    }

    /// Set the path to the ertificate key twinstar will use
    ///
    /// This defaults to `cert/key.pem`.
    ///
    /// This does not need to be called it [`set_tls_dir()`](Self::set_tls_dir()) has been
    /// called.
    ///
    /// This should of course correspond to the key set in
    /// [`set_cert()`](Self::set_cert())
    pub fn set_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.key_path = key_path.into();
        self
    }

    /// Set the mapping between hostname and (certificate, key) pairs.
    /// This allows serving different certificates for different hostnames and effectively
    /// setting up vhosts.
    ///
    /// In this case certificates are required to have DNS name set using `subjectAltName`.
    ///
    /// This overrides calls to [`set_tls_dir()`](Self::set_tls_dir()), [`set_cert()`](Self::set_cert())
    /// and [`set_key()`](Self::set_key()).
    ///
    /// This method can also be used to setup single host instead of mentioned methods.
    pub fn set_key_cert_map(mut self, host_cert_key: HashMap<String, (String, String)>) -> Self {
        self.cert_key_mapping =
            Some(HashMap::from_iter(host_cert_key.into_iter().map(
                |(hostname, cert_key)| (hostname, (cert_key.0.into(), cert_key.1.into())),
            )));

        self
    }

    /// Set the timeout on incoming requests
    ///
    /// Note that this timeout is applied twice, once for the delivery of the request, and
    /// once for sending the client's response.  This means that for a 1 second timeout,
    /// the client will have 1 second to complete the TLS handshake and deliver a request
    /// header, then your API will have as much time as it needs to handle the request,
    /// before the client has another second to receive the response.
    ///
    /// If you would like a timeout for your code itself, please use
    /// [`tokio::time::Timeout`] to implement it internally.
    ///
    /// **The default timeout is 1 second.**  As somewhat of a workaround for
    /// shortcomings of the specification, this timeout, and any timeout set using this
    /// method, is overridden in special cases, specifically for MIME types outside of
    /// `text/plain` and `text/gemini`, to be 30 seconds.  If you would like to change or
    /// prevent this, please see
    /// [`override_complex_body_timeout`](Self::override_complex_body_timeout()).
    pub fn set_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the timeout for complex body types
    ///
    /// Many clients choose to handle body types which cannot be displayed by prompting
    /// the user if they would like to download or open the request body.  However, since
    /// this prompt occurs in the middle of receiving a request, often the connection
    /// times out before the end user is able to respond to the prompt.
    ///
    /// As a workaround, it is possible to set an override on the request timeout in
    /// specific conditions:
    ///
    /// 1. **Only override the timeout for receiving the body of the request.**  This will
    ///    not override the timeout on sending the request header, nor on receiving the
    ///    response header.
    /// 2. **Only override the timeout for successful responses.**  The only bodies which
    ///    have bodies are successful ones.  In all other cases, there's no body to
    ///    timeout for
    /// 3. **Only override the timeout for complex body types.**  Almost all clients are
    ///    able to display `text/plain` and `text/gemini` responses, and will not prompt
    ///    the user for these response types.  This means that there is no reason to
    ///    expect a client to have a human-length response time for these MIME types.
    ///    Because of this, responses of this type will not be overridden.
    ///
    /// This method is used to override the timeout for responses meeting these specific
    /// criteria.  All other stages of the connection will use the timeout specified in
    /// [`set_timeout()`](Self::set_timeout()).
    ///
    /// If this is set to [`None`], then the client will have the default amount of time
    /// to both receive the header and the body.  If this is set to [`Some`], the client
    /// will have the default amount of time to recieve the header, and an *additional*
    /// alotment of time to recieve the body.
    ///
    /// The default timeout for this is 30 seconds.
    pub fn override_complex_body_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.complex_body_timeout_override = timeout;
        self
    }

    /// Add a handler for a route
    ///
    /// A route must be an absolute path, for example "/endpoint" or "/", but not
    /// "endpoint".  Entering a relative or malformed path will result in a panic.
    ///
    /// For more information about routing mechanics, see the docs for [`RoutingNode`].
    pub fn add_route<H>(mut self, path: &'static str, handler: H) -> Self
    where
        H: Fn(Request) -> HandlerResponse + Send + Sync + 'static,
    {
        self.routes.add_route(path, Arc::new(handler));
        self
    }

    pub async fn serve(mut self) -> Result<()> {
        let config = if self.cert_key_mapping.is_none() {
            tls_config(&self.cert_path, &self.key_path).context("Failed to create TLS config")?
        } else {
            tls_sni_config(&self.cert_key_mapping.unwrap())
                .context("Failed to create TLS config")?
        };

        let listener = TcpListener::bind(self.addr)
            .await
            .context("Failed to create socket")?;

        self.routes.shrink();

        let server = Server {
            tls_acceptor: TlsAcceptor::from(config),
            listener: Arc::new(listener),
            routes: Arc::new(self.routes),
            timeout: self.timeout,
            complex_timeout: self.complex_body_timeout_override,
        };

        server.serve().await
    }
}

async fn receive_request(stream: &mut (impl AsyncBufRead + Unpin)) -> Result<Request> {
    let limit = REQUEST_URI_MAX_LEN + "\r\n".len();
    let mut stream = stream.take(limit as u64);
    let mut uri = Vec::new();

    stream.read_until(b'\n', &mut uri).await?;

    if !uri.ends_with(b"\r\n") {
        if uri.len() < REQUEST_URI_MAX_LEN {
            bail!("Request header not terminated with CRLF")
        } else {
            bail!("Request URI too long")
        }
    }

    // Strip CRLF
    uri.pop();
    uri.pop();

    let uri = URIReference::try_from(&*uri)
        .context("Request URI is invalid")?
        .into_owned();
    let request = Request::from_uri(uri).context("Failed to create request from URI")?;

    Ok(request)
}

async fn send_response_header(
    header: &ResponseHeader,
    stream: &mut (impl AsyncWrite + Unpin),
) -> Result<()> {
    let header = format!(
        "{status} {meta}\r\n",
        status = header.status.code(),
        meta = header.meta.as_str(),
    );

    stream.write_all(header.as_bytes()).await?;
    stream.flush().await?;

    Ok(())
}

async fn maybe_send_response_body(
    maybe_body: Option<Body>,
    stream: &mut (impl AsyncWrite + Unpin),
) -> Result<()> {
    if let Some(body) = maybe_body {
        send_response_body(body, stream).await?;
    }

    Ok(())
}

async fn send_response_body(body: Body, stream: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
    match body {
        Body::Bytes(bytes) => stream.write_all(&bytes).await?,
        Body::Reader(mut reader) => {
            io::copy(&mut reader, stream).await?;
        }
    }

    stream.flush().await?;

    Ok(())
}

/// Mime for Gemini documents
pub const GEMINI_MIME_STR: &str = "text/gemini";

lazy_static! {
    /// Mime for Gemini documents ("text/gemini")
    pub static ref GEMINI_MIME: Mime = GEMINI_MIME_STR.parse().expect("twinstar BUG");
}

#[deprecated(note = "Use `GEMINI_MIME` instead", since = "0.3.0")]
pub fn gemini_mime() -> Result<Mime> {
    Ok(GEMINI_MIME.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemini_mime_parses() {
        let _: &Mime = &GEMINI_MIME;
    }
}
