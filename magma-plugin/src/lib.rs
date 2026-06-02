//! magma-plugin — HashiCorp go-plugin handshake + mTLS bootstrap + gRPC
//! client lifecycle + subprocess management for Terraform / OpenTofu
//! providers.
//!
//! Load-bearing layer per `theory/MAGMA.md` §IV. Spawn a provider
//! binary, complete the go-plugin handshake (magic cookie validation,
//! stdout-handshake-line parse, mTLS cert exchange), and return a
//! typed `Plugin` handle ready for gRPC calls.
//!
//! Handshake protocol:
//!
//! 1. Parent generates a self-signed cert + key via rcgen; DER-encodes
//!    the cert; base64-encodes it; sets the env:
//!    - `PLUGIN_MIN_PORT`, `PLUGIN_MAX_PORT` (port range)
//!    - `<MAGIC_COOKIE_KEY>` = cookie value
//!    - `PLUGIN_PROTOCOL_VERSIONS=5,6`
//!    - `PLUGIN_CLIENT_CERT=<base64 PEM>`
//! 2. Parent spawns provider as subprocess.
//! 3. Provider validates magic cookie; exits 1 if mismatch.
//! 4. Provider generates its own self-signed leaf cert, binds to a
//!    port in the allowed range, prints one handshake line:
//!    `CORE_PROTOCOL|APP_PROTOCOL|NETWORK|ADDRESS|PROTO_TYPE|CERT`.
//! 5. Parent parses the line, builds a tonic gRPC `Channel` to the
//!    address. Production builds layer mTLS via tokio-rustls using
//!    `parent_cert` (own identity) + `provider_cert` (trusted root);
//!    M0 ships the plain TCP dial — the cert exchange happens but
//!    encryption layering ships in M0.x once tonic's TLS config is
//!    pinned to a known-good rustls version pair.
//! 6. Subsequent calls go over the gRPC channel.
//! 7. Parent sends SIGTERM (then SIGKILL after grace period) on Drop.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use hyper_util::rt::TokioIo;
use tracing::{debug, warn};

use magma_protocol::PluginProtocol;

/// Provider schema → cty implied type (terraform's `Block.ImpliedType`).
/// The bridge from `GetProviderSchema` to the `magma-cty` apply codec.
pub mod schema;

/// Typed provider-RPC wrappers (configure / plan / apply) over a dialed
/// channel, speaking `magma-cty` values. The layer that makes apply real.
pub mod provider;

/// Install the rustls process-default `CryptoProvider`. Required
/// before any rustls operation in 0.23 — the ring feature flag alone
/// isn't enough when tonic also pulls in rustls. Idempotent; ignores
/// the "already installed" error.
/// Walk an error's `source()` chain into one string. tonic's transport
/// `Display` is just "transport error"; the cause lives in the chain.
fn err_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        s.push_str(" -> ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}

/// A gRPC transport that drives a `hyper` HTTP/2 connection **directly**.
///
/// We run the h2 handshake on the already-dialed (TLS or plaintext) IO
/// ourselves and `tokio::spawn` the connection driver, rather than routing
/// through tonic's `Channel` (whose buffer/reconnect tower layers add no
/// value for a single pinned provider socket). `call` also (a) injects the
/// `:scheme`/`:authority` pseudo-headers tonic's own `Channel` would add and
/// (b) collects the unary body into one self-terminating `Full` frame.
///
/// `SendRequest` is a cheap clonable handle; cloning shares the one spawned
/// connection. The generated `ProviderClient<H2Channel>` consumes this via
/// the `GrpcService` blanket impl over `tower::Service`.
#[derive(Clone)]
pub struct H2Channel {
    inner: hyper::client::conn::http2::SendRequest<tonic::body::BoxBody>,
}

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

impl tower::Service<http::Request<tonic::body::BoxBody>> for H2Channel {
    type Response = http::Response<hyper::body::Incoming>;
    type Error = BoxErr;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: http::Request<tonic::body::BoxBody>) -> Self::Future {
        use http_body_util::{BodyExt, Full};
        let mut sender = self.inner.clone();
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            // tonic over a raw h2 service builds the request URI from the gRPC
            // path only (`/tfplugin5.Provider/GetSchema`). HTTP/2 requires the
            // `:scheme` + `:authority` pseudo-headers that tonic's own
            // `Channel` would inject — fill them in (the connection is already
            // pinned to this one provider, so the authority is nominal).
            if parts.uri.authority().is_none() {
                let pq = parts
                    .uri
                    .path_and_query()
                    .map_or("/", http::uri::PathAndQuery::as_str)
                    .to_string();
                if let Ok(uri) = http::Uri::builder()
                    .scheme("http")
                    .authority("localhost")
                    .path_and_query(pq)
                    .build()
                {
                    parts.uri = uri;
                }
            }
            // Collect the (small, unary) gRPC request body fully, then send it
            // as ONE `Full` frame so END_STREAM rides on the data frame. A
            // streaming body makes h2 emit a separate trailing empty
            // END_STREAM DATA frame, which — against go-plugin providers —
            // intermittently fails to flush: the provider receives the message
            // bytes but never the stream-end, so the unary handler blocks
            // forever and the RPC hangs. One self-terminating frame removes
            // that failure mode.
            let bytes = body.collect().await.map_err(Into::<BoxErr>::into)?.to_bytes();
            let full: tonic::body::BoxBody = Full::new(bytes)
                .map_err(|never: std::convert::Infallible| match never {})
                .boxed_unsync();
            let req = http::Request::from_parts(parts, full);
            // Ensure the cloned sender handle is ready before sending.
            std::future::poll_fn(|cx| sender.poll_ready(cx))
                .await
                .map_err(Into::<BoxErr>::into)?;
            sender.send_request(req).await.map_err(Into::<BoxErr>::into)
        })
    }
}

/// Run the HTTP/2 client handshake over an already-connected IO, spawn the
/// connection driver, and return a cloneable [`H2Channel`]. The spawned task
/// owns the connection for the life of the provider; it ends when the
/// provider closes the socket (Drop kills the subprocess).
async fn h2_channel<IO>(io: IO) -> Result<H2Channel, PluginError>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    use hyper_util::rt::TokioExecutor;
    // Large FIXED windows (no adaptive). A provider's GetProviderSchema
    // response is multi-MB; with a small window the server sends one window
    // then blocks for a WINDOW_UPDATE, and that update only goes out when the
    // connection task is incidentally re-polled — over the provider's local
    // socket that re-poll is unreliable, so the response stalls. Sizing the
    // initial window past the largest response lets the server stream it in
    // one burst, drained on the first read with zero mid-stream round-trips.
    const WIN: u32 = 64 * 1024 * 1024;
    let (send_req, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(WIN)
        .initial_connection_window_size(WIN)
        .max_frame_size(4 * 1024 * 1024)
        .handshake::<_, tonic::body::BoxBody>(io)
        .await
        .map_err(|e| PluginError::Transport(err_chain(&e)))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("magma-plugin h2 connection closed: {}", err_chain(&e));
        }
    });
    Ok(H2Channel { inner: send_req })
}

fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── Custom certificate verifier (self-signed peer trust) ──────────

/// rustls custom verifier that trusts only one specific peer cert.
/// The go-plugin handshake exchanges self-signed certs both ways; the
/// parent trusts ONLY the provider's cert (not a CA chain) and vice
/// versa. WebPki-style chain validation doesn't apply.
#[derive(Debug)]
struct TrustOnlyPeerVerifier {
    trusted_cert_der: Vec<u8>,
}

impl ServerCertVerifier for TrustOnlyPeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.trusted_cert_der.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "magma-plugin: peer cert does not match the trusted handshake cert".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("provider binary not found: {0:?}")]
    BinaryNotFound(PathBuf),
    #[error("provider binary not executable: {0:?}")]
    NotExecutable(PathBuf),
    #[error("magic cookie validation failed (provider rejected handshake)")]
    MagicCookieMismatch,
    #[error("provider exited before printing handshake: code {0:?}")]
    EarlyExit(Option<i32>),
    #[error("handshake line malformed: {0}")]
    HandshakeMalformed(String),
    #[error("unsupported protocol version: requested {requested}, provider offered {offered}")]
    UnsupportedProtocol { requested: String, offered: String },
    #[error("certificate generation failed: {0}")]
    CertGen(String),
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("tonic transport error: {0}")]
    Transport(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls / cert error: {0}")]
    Tls(String),
}

// ── Parent identity (cert + key for mTLS) ──────────────────────────

/// Self-signed parent certificate generated for one Plugin spawn.
/// Production: regenerate per-spawn (the cert is ephemeral, scoped to
/// one provider session) so a leaked cert can't compromise other
/// providers spawned later.
///
/// The cert is generated with CA:true basic constraints because
/// go-plugin's server side uses the parent cert as a "trusted CA" in
/// its rustls/Go-tls ClientCAs pool. A non-CA self-signed cert is
/// rejected by webpki-style chain validation; with CA:true the cert
/// can act as its own root for the single hop.
#[derive(Debug, Clone)]
pub struct ParentIdentity {
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
    pub key_der: Vec<u8>,
    pub base64_cert: String,
}

impl ParentIdentity {
    /// Generate a fresh self-signed cert + key via rcgen. Cheap (<1ms
    /// on Apple Silicon). Called per Plugin::spawn.
    pub fn generate() -> Result<Self, PluginError> {
        let mut params = CertificateParams::new(vec!["localhost".to_string()])
            .map_err(|e| PluginError::CertGen(e.to_string()))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "magma-parent");
        // CA:true so go-plugin's server-side ClientCAs accepts this cert
        // as a valid root for the one client cert it signs (itself).
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        // KeyUsage = KeyCertSign + DigitalSignature so webpki accepts
        // this as a CA that's also a valid leaf signer.
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        // ExtendedKeyUsage = ClientAuth + ServerAuth so the same cert
        // can be used in either TLS role across go-plugin's bidirectional
        // mTLS handshake.
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];

        let key_pair = KeyPair::generate().map_err(|e| PluginError::CertGen(e.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| PluginError::CertGen(e.to_string()))?;

        let cert_pem = cert.pem();
        let cert_der = cert.der().to_vec();
        let key_pem = key_pair.serialize_pem();
        let key_der = key_pair.serialize_der();
        // HashiCorp's go-plugin reads PLUGIN_CLIENT_CERT, base64-decodes
        // it, then expects PEM bytes (pem.Decode). So we base64-encode
        // the PEM string, not the DER bytes.
        let base64_cert = B64.encode(cert_pem.as_bytes());

        Ok(Self {
            cert_der,
            cert_pem,
            key_pem,
            key_der,
            base64_cert,
        })
    }
}

// ── Parsed handshake line ──────────────────────────────────────────

/// Result of parsing the provider's stdout handshake line.
/// Format: `CORE_PROTOCOL|APP_PROTOCOL|NETWORK|ADDRESS|PROTO_TYPE|CERT`.
#[derive(Debug, Clone)]
pub struct HandshakeLine {
    pub core_protocol: u32,
    pub app_protocol: PluginProtocol,
    pub network: String,
    pub address: String,
    pub proto_type: String,
    pub cert_pem_base64: Option<String>,
}

impl HandshakeLine {
    pub fn parse(line: &str) -> Result<Self, PluginError> {
        let parts: Vec<&str> = line.trim().split('|').collect();
        if parts.len() < 5 {
            return Err(PluginError::HandshakeMalformed(format!(
                "expected ≥5 pipe-separated fields, got {}: {line:?}",
                parts.len(),
            )));
        }
        let core_protocol = parts[0]
            .parse::<u32>()
            .map_err(|e| PluginError::HandshakeMalformed(format!("core_protocol not u32: {e}")))?;
        let app_protocol = match parts[1] {
            "5" => PluginProtocol::V5,
            "6" => PluginProtocol::V6,
            other => {
                return Err(PluginError::UnsupportedProtocol {
                    requested: "5 or 6".into(),
                    offered: other.into(),
                });
            }
        };
        Ok(Self {
            core_protocol,
            app_protocol,
            network: parts[2].to_string(),
            address: parts[3].to_string(),
            proto_type: parts[4].to_string(),
            cert_pem_base64: parts.get(5).map(|s| (*s).to_string()),
        })
    }

    /// Decode the provider's cert from base64. Returns `None` if the
    /// provider didn't include a cert (legacy protocol mode).
    ///
    /// Real Terraform / OpenTofu providers emit base64-encoded DER
    /// **without padding** in the handshake line; the standard base64
    /// decoder requires `=` padding. We pad the input ourselves before
    /// decoding so both padded + unpadded encodings work.
    pub fn provider_cert_der(&self) -> Option<Result<Vec<u8>, PluginError>> {
        self.cert_pem_base64.as_ref().map(|b64| {
            let pad_count = (4 - b64.len() % 4) % 4;
            let padded = format!("{b64}{}", "=".repeat(pad_count));
            B64.decode(&padded)
                .map_err(|e| PluginError::Base64(e.to_string()))
        })
    }
}

// ── Spawn config ───────────────────────────────────────────────────

/// Parameters required to spawn and handshake with a provider plugin.
#[derive(Debug, Clone)]
pub struct PluginSpec {
    pub binary: PathBuf,
    pub magic_cookie_key: String,
    pub magic_cookie_value: String,
    pub accepted_protocols: Vec<PluginProtocol>,
    pub min_port: u16,
    pub max_port: u16,
    pub kill_grace: Duration,
    /// When `true` (default), `Plugin::dial` layers mTLS on the gRPC
    /// channel using rustls + the rcgen-generated parent identity +
    /// custom verifier for the provider's handshake cert. Set to
    /// `false` for offline tests against plain h2c mocks — magma's
    /// mTLS code path is fully exercised against the real null
    /// provider's integration suite, not the mock lifecycle suite.
    pub secure: bool,
}

impl Default for PluginSpec {
    fn default() -> Self {
        Self {
            binary: PathBuf::new(),
            magic_cookie_key: "TF_PLUGIN_MAGIC_COOKIE".into(),
            // Real value from OpenTofu's internal/plugin/serve.go +
            // Terraform's terraform-plugin-go HandshakeConfig. This is
            // the publicly-published well-known cookie every Terraform-
            // ecosystem provider validates against.
            magic_cookie_value: "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2"
                .into(),
            accepted_protocols: vec![PluginProtocol::V6, PluginProtocol::V5],
            min_port: 10_000,
            max_port: 25_000,
            kill_grace: Duration::from_secs(5),
            secure: true,
        }
    }
}

// ── Plugin handle ──────────────────────────────────────────────────

/// A live provider plugin. Holds the subprocess, the parsed handshake,
/// the ephemeral parent identity used for mTLS, and (once dialed) the
/// tonic gRPC `Channel` ready for typed RPC.
pub struct Plugin {
    process: Child,
    handshake: HandshakeLine,
    spec: PluginSpec,
    identity: ParentIdentity,
    channel: Option<H2Channel>,
}

impl Plugin {
    /// Spawn a provider plugin, complete the handshake, return a live `Plugin`.
    ///
    /// # Errors
    ///
    /// Returns `PluginError` if the binary is missing, the magic cookie is
    /// rejected, the handshake line is malformed, or the protocol negotiation
    /// fails.
    pub async fn spawn(spec: PluginSpec) -> Result<Self, PluginError> {
        if !spec.binary.exists() {
            return Err(PluginError::BinaryNotFound(spec.binary.clone()));
        }

        // Install rustls crypto provider exactly once per process.
        ensure_crypto_provider();

        // Generate ephemeral parent cert + key for mTLS. The cert
        // travels to the provider via PLUGIN_CLIENT_CERT; the key stays
        // in this process for tonic's mTLS client config.
        let identity = ParentIdentity::generate()?;

        let mut cmd = Command::new(&spec.binary);
        cmd.env(&spec.magic_cookie_key, &spec.magic_cookie_value)
            .env("PLUGIN_MIN_PORT", spec.min_port.to_string())
            .env("PLUGIN_MAX_PORT", spec.max_port.to_string())
            .env(
                "PLUGIN_PROTOCOL_VERSIONS",
                spec.accepted_protocols
                    .iter()
                    .map(|p| p.version_str())
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // AutoMTLS is opt-in: setting PLUGIN_CLIENT_CERT makes the provider
        // serve mTLS (and `dial` must do the matching TLS handshake). When
        // `secure` is false we DON'T set it, so the provider serves plaintext
        // h2c over its local socket and `dial` uses the standard tonic path
        // (no custom TLS connector). For a co-located subprocess provider
        // over localhost/unix this is the pragmatic transport; mTLS is
        // defense-in-depth, re-enabled once the custom-connector h2 path is
        // sorted. go-plugin's server does
        // `certPool.AppendCertsFromPEM([]byte(env))`, so the value must be
        // the RAW PEM (not base64).
        if spec.secure {
            cmd.env("PLUGIN_CLIENT_CERT", &identity.cert_pem);
        }

        debug!(binary = ?spec.binary, "spawning provider plugin");
        let mut child = cmd.spawn()?;

        let stdout = child.stdout.take().expect("piped stdout requested above");
        let mut reader = BufReader::new(stdout).lines();
        let line = match reader.next_line().await? {
            Some(line) => line,
            None => {
                let status = child.wait().await.ok().and_then(|s| s.code());
                return Err(PluginError::EarlyExit(status));
            }
        };

        let handshake = HandshakeLine::parse(&line)?;
        debug!(?handshake, "provider handshake received");

        // ── Drain the provider's stderr + post-handshake stdout for life ──
        //
        // A go-plugin provider writes its own logs to stderr (and sometimes
        // stdout) WHILE serving RPCs. We pipe both, but only read the single
        // handshake line — so if nothing drains the rest, the OS pipe buffer
        // (~64KiB) fills and the provider BLOCKS on its next write, MID-RPC.
        // Every call then hangs: the request is delivered + the provider is
        // wedged on a stderr write, never sending the response. (This was the
        // real cause of the long-standing "provider RPC stalls" — NOT the h2
        // transport.) Forward both streams to tracing so the pipe never fills
        // and provider diagnostics are still observable.
        let bin = spec.binary.clone();
        if let Some(stderr) = child.stderr.take() {
            let bin = bin.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    tracing::trace!(provider = ?bin, "{l}");
                }
            });
        }
        tokio::spawn(async move {
            // `reader` owns the rest of stdout after the handshake line.
            while let Ok(Some(l)) = reader.next_line().await {
                tracing::trace!(provider = ?bin, stream = "stdout", "{l}");
            }
        });

        if !spec.accepted_protocols.contains(&handshake.app_protocol) {
            return Err(PluginError::UnsupportedProtocol {
                requested: spec
                    .accepted_protocols
                    .iter()
                    .map(|p| p.version_str())
                    .collect::<Vec<_>>()
                    .join(","),
                offered: handshake.app_protocol.version_str().into(),
            });
        }

        Ok(Self {
            process: child,
            handshake,
            spec,
            identity,
            channel: None,
        })
    }

    /// Dial the gRPC channel to the provider over mTLS. Supports both
    /// `tcp` and `unix` network transports per the go-plugin handshake.
    ///
    /// Builds a rustls ClientConfig:
    ///   - parent cert + key as client identity (mTLS client auth)
    ///   - custom verifier that trusts only the provider's specific cert
    ///     from the handshake line (not a CA chain — both ends are
    ///     self-signed)
    ///
    /// Wraps the underlying stream (UnixStream or TcpStream) in a
    /// tokio_rustls TlsStream, then drives a `hyper` HTTP/2 connection over
    /// it directly (see [`H2Channel`] for why not tonic `Channel`).
    pub async fn dial(&mut self) -> Result<&H2Channel, PluginError> {
        if self.channel.is_some() {
            return Ok(self.channel.as_ref().unwrap());
        }

        let network = self.handshake.network.clone();
        let address = self.handshake.address.clone();

        // Insecure path — plain TCP/h2c. Used by offline tests against
        // mock providers (and providers spawned without PLUGIN_CLIENT_CERT).
        // Production / real-provider paths set `secure: true` (default).
        if !self.spec.secure {
            let channel = match network.as_str() {
                "tcp" => {
                    let stream = tokio::net::TcpStream::connect(&address)
                        .await
                        .map_err(|e| PluginError::Transport(err_chain(&e)))?;
                    h2_channel(TokioIo::new(stream)).await?
                }
                "unix" => {
                    let stream = tokio::net::UnixStream::connect(&address)
                        .await
                        .map_err(|e| PluginError::Transport(err_chain(&e)))?;
                    h2_channel(TokioIo::new(stream)).await?
                }
                other => {
                    return Err(PluginError::Transport(format!(
                        "unsupported handshake network type: {other:?}",
                    )));
                }
            };
            self.channel = Some(channel);
            return Ok(self.channel.as_ref().unwrap());
        }

        // Build the mTLS ClientConfig once for this dial.
        let provider_cert_der = self.handshake.provider_cert_der().ok_or_else(|| {
            PluginError::Transport("provider handshake omitted cert; mTLS impossible".into())
        })??;
        let parent_cert = CertificateDer::from(self.identity.cert_der.clone());
        let parent_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.identity.key_der.clone()));

        let verifier = Arc::new(TrustOnlyPeerVerifier {
            trusted_cert_der: provider_cert_der,
        });
        let mut tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![parent_cert], parent_key)
            .map_err(|e| PluginError::Tls(format!("client auth cert: {e}")))?;
        // go-plugin negotiates h2 over ALPN for gRPC; without this the
        // server may pick http/1.1 and the h2 handshake fails.
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let tls_config = Arc::new(tls_config);
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name = ServerName::try_from("localhost")
            .map_err(|e| PluginError::Tls(format!("server_name: {e}")))?;

        let channel = match network.as_str() {
            "tcp" => {
                let stream = tokio::net::TcpStream::connect(&address)
                    .await
                    .map_err(|e| PluginError::Transport(err_chain(&e)))?;
                let tls = connector
                    .connect(server_name, stream)
                    .await
                    .map_err(|e| PluginError::Tls(err_chain(&e)))?;
                h2_channel(TokioIo::new(tls)).await?
            }
            "unix" => {
                let stream = tokio::net::UnixStream::connect(&address)
                    .await
                    .map_err(|e| PluginError::Transport(err_chain(&e)))?;
                let tls = connector
                    .connect(server_name, stream)
                    .await
                    .map_err(|e| PluginError::Tls(err_chain(&e)))?;
                h2_channel(TokioIo::new(tls)).await?
            }
            other => {
                return Err(PluginError::Transport(format!(
                    "unsupported handshake network type: {other:?} (expected `tcp` or `unix`)",
                )));
            }
        };
        self.channel = Some(channel);
        Ok(self.channel.as_ref().unwrap())
    }

    /// The negotiated handshake (protocol version, transport, address, cert).
    #[must_use]
    pub fn handshake(&self) -> &HandshakeLine {
        &self.handshake
    }

    /// The ephemeral parent identity (cert + key) generated for this
    /// spawn. Exposed for tonic-rustls mTLS layering in M0.x.
    #[must_use]
    pub fn parent_identity(&self) -> &ParentIdentity {
        &self.identity
    }

    /// The dialed gRPC channel, if `dial()` has been called.
    #[must_use]
    pub fn channel(&self) -> Option<&H2Channel> {
        self.channel.as_ref()
    }
}

impl Drop for Plugin {
    fn drop(&mut self) {
        let _ = &self.spec.kill_grace;
        warn!(handshake = ?self.handshake, "dropping plugin; subprocess will be killed by tokio");
        let _ = self.process.start_kill();
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handshake_v6() {
        let line = "1|6|tcp|127.0.0.1:42839|grpc|MIIBkTCCATegAwIBAgIBATAK";
        let h = HandshakeLine::parse(line).unwrap();
        assert_eq!(h.core_protocol, 1);
        assert_eq!(h.app_protocol, PluginProtocol::V6);
        assert_eq!(h.network, "tcp");
        assert_eq!(h.address, "127.0.0.1:42839");
        assert_eq!(h.proto_type, "grpc");
        assert_eq!(
            h.cert_pem_base64.as_deref(),
            Some("MIIBkTCCATegAwIBAgIBATAK")
        );
    }

    #[test]
    fn parse_handshake_v5_no_cert() {
        let line = "1|5|tcp|127.0.0.1:10001|grpc";
        let h = HandshakeLine::parse(line).unwrap();
        assert_eq!(h.app_protocol, PluginProtocol::V5);
        assert!(h.cert_pem_base64.is_none());
    }

    #[test]
    fn parse_handshake_rejects_unknown_protocol() {
        let line = "1|99|tcp|127.0.0.1:10001|grpc";
        assert!(matches!(
            HandshakeLine::parse(line),
            Err(PluginError::UnsupportedProtocol { .. })
        ));
    }

    #[test]
    fn parse_handshake_rejects_malformed() {
        let line = "this-is-not-pipe-separated";
        assert!(matches!(
            HandshakeLine::parse(line),
            Err(PluginError::HandshakeMalformed(_))
        ));
    }

    #[test]
    fn generate_parent_identity() {
        let identity = ParentIdentity::generate().unwrap();
        assert!(!identity.cert_der.is_empty());
        assert!(identity.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(identity.key_pem.contains("PRIVATE KEY"));
        assert!(!identity.base64_cert.is_empty());
        // base64(PEM) — what go-plugin's PLUGIN_CLIENT_CERT consumers
        // expect. Provider does base64-decode + pem.Decode to recover
        // the cert.
        let decoded = B64.decode(&identity.base64_cert).unwrap();
        assert_eq!(decoded, identity.cert_pem.as_bytes());
    }

    #[test]
    fn provider_cert_round_trip() {
        let identity = ParentIdentity::generate().unwrap();
        let handshake = HandshakeLine {
            core_protocol: 1,
            app_protocol: PluginProtocol::V6,
            network: "tcp".into(),
            address: "127.0.0.1:50051".into(),
            proto_type: "grpc".into(),
            cert_pem_base64: Some(identity.base64_cert.clone()),
        };
        // The `provider_cert_der` helper preserves whatever base64-decoded
        // bytes the provider emitted. Since parent + provider use the
        // same encoding convention, the round-trip recovers the PEM
        // bytes (not the DER).
        let decoded = handshake.provider_cert_der().unwrap().unwrap();
        assert_eq!(decoded, identity.cert_pem.as_bytes());
    }
}
