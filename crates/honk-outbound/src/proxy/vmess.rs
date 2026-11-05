//! VMess AEAD outbound handler (alterId = 0).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use async_trait::async_trait;
use futures_util::FutureExt;
use honk_config::node::Node;
use md5::{Digest, Md5};
use rand::Rng;
use rand::RngExt;
use sha2::Sha256;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use super::addr::{self, SocksAddr};
use super::{
    AsyncReadWrite, FramePoison, PacketOutbound, PacketRejection, PacketTransport,
    ProbeableOutbound, ProxyStream, TcpOutbound, WarmRequirement, WarmableOutbound,
};

/// VMess protocol version byte.
const VMESS_VERSION: u8 = 0x01;
/// Request options: ChunkStream | ChunkMasking — what Xray's outbound sets
/// for AES-128-GCM security (`proxy/vmess/outbound/outbound.go`).
const REQUEST_OPTION: u8 = 0x01 | 0x04;
/// Security nibble: AES-128-GCM (`SecurityType_AES128_GCM`, what "auto"
/// resolves to on any AES-capable host).
const SECURITY_AES128_GCM: u8 = 0x03;
/// Request command: TCP.
const CMD_TCP: u8 = 0x01;
/// Request command: UDP (`protocol.RequestCommandUDP` in Xray-core). The
/// header still names one destination: each AEAD body chunk is one datagram
/// for that destination, and each response chunk is one datagram back.
const CMD_UDP: u8 = 0x02;
/// Suffix for cmd_key derivation (`vmess.Account.ID.CmdKey`).
const CMD_KEY_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
/// Seed of the chained KDF (`aead/kdf.go` KDFSaltConstVMessAEADKDF).
const KDF_SALT_SEED: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_RESP_IV: &[u8] = b"AEAD Resp Header IV";
/// AES-GCM tag length in bytes.
const GCM_TAG_LEN: usize = 16;
/// Maximum plaintext per body chunk (Xray `buf.Size` - tag - size field,
/// no global padding).
const CHUNK_MAX_LEN: usize = 16384 - GCM_TAG_LEN - 2;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<Sha256>>::new_from_slice(key).expect("HMAC key length is free");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// HMAC block pads for a key that fits the 64-byte block (every KDF path
/// element does, so the >64-byte pre-hash branch never applies).
fn hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    debug_assert!(key.len() <= 64);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    (ipad, opad)
}

/// The chained hash of `aead/kdf.go`: `chain[0]` is the innermost HMAC key
/// (the salt seed); each further element wraps the previous hash as an HMAC
/// whose "hash function" is the previous level — `H_k(m) = H_{k-1}(opad_k
/// || H_{k-1}(ipad_k || m))`. Verified byte-identical to both Xray-core's
/// `KDF` and sing-vmess's `KDF` against their Go sources.
fn chain_hash(chain: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    if let &[seed] = chain {
        return hmac_sha256(seed, msg);
    }
    let (rest, last) = chain.split_at(chain.len() - 1);
    let (ipad, opad) = hmac_pads(last[0]);
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner = chain_hash(rest, &inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner);
    chain_hash(rest, &outer)
}

fn kdf(key: &[u8], salt: &[u8], extra: &[&[u8]]) -> [u8; 32] {
    let mut chain: Vec<&[u8]> = Vec::with_capacity(2 + extra.len());
    chain.push(KDF_SALT_SEED);
    chain.push(salt);
    chain.extend_from_slice(extra);
    chain_hash(&chain, key)
}

fn kdf16(key: &[u8], salt: &[u8], extra: &[&[u8]]) -> [u8; 16] {
    kdf(key, salt, extra)[..16]
        .try_into()
        .expect("slice length")
}

fn kdf12(key: &[u8], salt: &[u8], extra: &[&[u8]]) -> [u8; 12] {
    kdf(key, salt, extra)[..12]
        .try_into()
        .expect("slice length")
}

/// CRC-32 IEEE (gzip polynomial), used by the auth ID
/// (`crc32.ChecksumIEEE` in `aead/authid.go`).
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// FNV-1a 32 (`hash/fnv` in `EncodeRequestHeader`; Go's `Sum` appends
/// big-endian).
fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = 0x811C_9DC5u32;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// VMess AEAD proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct VmessHandler;

/// Per-connection session material (`encoding.NewClientSession`).
#[derive(Clone)]
struct Session {
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    resp_header: u8,
}

impl Session {
    fn new() -> Self {
        let mut rng = rand::rng();
        let mut req_key = [0u8; 16];
        let mut req_iv = [0u8; 16];
        rng.fill_bytes(&mut req_key);
        rng.fill_bytes(&mut req_iv);
        // Response body keys derive from the request keys
        // (encoding/client.go NewClientSession).
        let resp_key: [u8; 16] = Sha256::digest(req_key)[..16]
            .try_into()
            .expect("sha256 > 16");
        let resp_iv: [u8; 16] = Sha256::digest(req_iv)[..16]
            .try_into()
            .expect("sha256 > 16");
        Self {
            req_key,
            req_iv,
            resp_key,
            resp_iv,
            resp_header: rng.random(),
        }
    }
}

/// How the relay task ended, when it failed: a rejected response header or
/// an invalid chunk reads as that error, not as EOF.
type RelayFailure = std::sync::Arc<std::sync::OnceLock<(std::io::ErrorKind, crate::SharedError)>>;

struct VmessStream {
    inner: tokio::io::DuplexStream,
    relay: tokio::task::AbortHandle,
    failure: RelayFailure,
}

impl VmessStream {
    fn relay_error(&self) -> Option<std::io::Error> {
        self.failure
            .get()
            .map(|(kind, message)| std::io::Error::new(*kind, message.clone()))
    }
}

/// The failure is recorded before the duplex half closes, so the owner sees it
/// on the poll that would otherwise be EOF.
async fn vmess_relay_recorded(
    server: Box<dyn AsyncReadWrite>,
    mut client: tokio::io::DuplexStream,
    header_wire: Vec<u8>,
    session: Session,
    failure: RelayFailure,
) {
    if let Err(error) = vmess_relay(server, &mut client, header_wire, session).await {
        let kind = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .map(std::io::Error::kind)
            .unwrap_or(std::io::ErrorKind::InvalidData);
        let _ = failure.set((
            kind,
            crate::SharedError::new(error.context("VMess relay failed")),
        ));
    }
    drop(client);
}

impl std::fmt::Debug for VmessStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessStream").finish_non_exhaustive()
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before => match self.relay_error() {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Ready(Ok(())),
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.relay_error().unwrap_or(error))),
            other => other,
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.relay_error().unwrap_or(error))),
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.relay_error().unwrap_or(error))),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for VmessStream {
    fn drop(&mut self) {
        self.relay.abort();
    }
}

impl VmessHandler {
    pub fn new() -> Self {
        Self
    }

    /// Derive the command key: `MD5(uuid || CMD_KEY_SUFFIX)`.
    fn derive_cmd_key(uuid: &[u8]) -> [u8; 16] {
        let mut h = Md5::new();
        h.update(uuid);
        h.update(CMD_KEY_SUFFIX);
        h.finalize().into()
    }

    /// `CreateAuthID`: AES-128 single-block encryption of
    /// `ts(8 BE) | rand(4) | crc32(ts|rand)(4 BE)` under the auth-ID key.
    fn create_auth_id(cmd_key: &[u8; 16], ts: u64, rand4: [u8; 4]) -> [u8; 16] {
        use aes_gcm::aes::cipher::BlockCipherEncrypt;
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&ts.to_be_bytes());
        block[8..12].copy_from_slice(&rand4);
        let crc = crc32_ieee(&block[..12]);
        block[12..].copy_from_slice(&crc.to_be_bytes());
        let key = kdf16(cmd_key, KDF_SALT_AUTH_ID, &[]);
        let cipher = aes_gcm::aes::Aes128::new_from_slice(&key).expect("key length");
        cipher.encrypt_block((&mut block).into());
        block
    }

    /// Header plaintext per `EncodeRequestHeader` (fnv checksum included).
    fn build_header_plain(
        session: &Session,
        padding_len: u8,
        padding: &[u8],
        target: SocketAddr,
        target_domain: Option<&str>,
        command: u8,
    ) -> anyhow::Result<Vec<u8>> {
        debug_assert_eq!(padding_len as usize, padding.len());
        let addr = SocksAddr::new(target, target_domain)?;
        let mut plain = Vec::with_capacity(41 + addr.encoded_len() + padding.len() + 4);
        plain.push(VMESS_VERSION);
        plain.extend_from_slice(&session.req_iv);
        plain.extend_from_slice(&session.req_key);
        plain.push(session.resp_header);
        plain.push(REQUEST_OPTION);
        plain.push((padding_len << 4) | SECURITY_AES128_GCM);
        plain.push(0);
        plain.push(command);
        plain.extend_from_slice(&target.port().to_be_bytes());
        // V2Ray writes port first, then ATYP + address
        // (protocol.AddressSerializer with PortThenAddress).
        match &addr {
            SocksAddr::V4(v4) => {
                plain.push(addr::ATYP_VMESS.ipv4);
                plain.extend_from_slice(&v4.ip().octets());
            }
            SocksAddr::V6(v6) => {
                plain.push(addr::ATYP_VMESS.ipv6);
                plain.extend_from_slice(&v6.ip().octets());
            }
            SocksAddr::Domain(domain, _) => {
                plain.push(addr::ATYP_VMESS.domain);
                plain.push(domain.len() as u8);
                plain.extend_from_slice(domain.as_bytes());
            }
        }
        plain.extend_from_slice(padding);
        plain.extend_from_slice(&fnv1a32(&plain).to_be_bytes());
        Ok(plain)
    }

    /// `SealVMessAEADHeader`: auth_id | enc_len | conn_nonce | enc_header,
    /// both AEAD blocks authenticated with auth_id as AAD.
    fn seal_request_header(
        cmd_key: &[u8; 16],
        auth_id: &[u8; 16],
        conn_nonce: &[u8; 8],
        plain: &[u8],
    ) -> Vec<u8> {
        let extra: [&[u8]; 2] = [auth_id, conn_nonce];
        let len_key = kdf16(cmd_key, KDF_SALT_HEADER_LEN_KEY, &extra);
        let len_nonce = kdf12(cmd_key, KDF_SALT_HEADER_LEN_IV, &extra);
        let hdr_key = kdf16(cmd_key, KDF_SALT_HEADER_KEY, &extra);
        let hdr_nonce = kdf12(cmd_key, KDF_SALT_HEADER_IV, &extra);

        let mut out = Vec::with_capacity(16 + 18 + 8 + plain.len() + GCM_TAG_LEN);
        out.extend_from_slice(auth_id);
        out.extend_from_slice(&Self::seal_aad(
            &len_key,
            &len_nonce,
            &(plain.len() as u16).to_be_bytes(),
            auth_id,
        ));
        out.extend_from_slice(conn_nonce);
        out.extend_from_slice(&Self::seal_aad(&hdr_key, &hdr_nonce, plain, auth_id));
        out
    }

    fn seal_aad(key: &[u8; 16], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("valid key length");
        cipher
            .encrypt(
                <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                    .expect("nonce size"),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("seal")
    }

    fn open(
        key: &[u8; 16],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("valid key length");
        cipher.decrypt(
            <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                .expect("nonce size"),
            ciphertext,
        )
    }

    #[cfg(test)]
    fn open_aad(
        key: &[u8; 16],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("valid key length");
        cipher.decrypt(
            <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                .expect("nonce size"),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
    }

    /// Build the AEAD request header for one connection. The session is
    /// returned as well: its body keys encrypt both TCP and UDP chunks.
    fn request_header(
        uuid_bytes: &[u8],
        target: SocketAddr,
        target_domain: Option<&str>,
        command: u8,
    ) -> anyhow::Result<(Vec<u8>, Session)> {
        let cmd_key = Self::derive_cmd_key(uuid_bytes);
        let session = Session::new();

        let mut rng = rand::rng();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let auth_id = Self::create_auth_id(&cmd_key, ts, rng.random());
        let conn_nonce: [u8; 8] = rng.random();
        // dice.Roll(16): 0..=15 — the length lives in the high nibble.
        let padding_len: u8 = rng.random_range(0..16);
        let mut padding = vec![0u8; padding_len as usize];
        rng.fill_bytes(&mut padding);

        let plain = Self::build_header_plain(
            &session,
            padding_len,
            &padding,
            target,
            target_domain,
            command,
        )?;
        let header_wire = Self::seal_request_header(&cmd_key, &auth_id, &conn_nonce, &plain);
        Ok((header_wire, session))
    }

    /// Build the request header and return a proxy stream backed by a
    /// duplex pipe + background relay task.
    fn perform_handshake(
        uuid_bytes: &[u8],
        stream: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> anyhow::Result<ProxyStream> {
        let (header_wire, session) =
            Self::request_header(uuid_bytes, target, target_domain, CMD_TCP)?;

        let (client_half, server_half) = tokio::io::duplex(65536);
        let failure = RelayFailure::default();
        let relay_future =
            vmess_relay_recorded(stream, server_half, header_wire, session, failure.clone());
        let relay_future = crate::runtime::flow_observation::scope(
            crate::runtime::flow_observation::current(),
            relay_future,
        );
        let relay = crate::runtime::spawn_owned(relay_future)
            .ok_or(crate::proxy::PacketRejection::Cancelled)?;

        Ok(ProxyStream {
            stream: Box::new(VmessStream {
                inner: client_half,
                relay,
                failure,
            }),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    /// Open one command-UDP association. Xray's inbound dispatches the whole
    /// connection to the single destination named in the request header, so
    /// this is a connected transport: one stream per UDP target, with one AEAD
    /// chunk per datagram in each direction.
    async fn dial_udp_stream(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::require_udp(node)?;
        let uuid = uuid(node)?;
        let stream = match runtime {
            Some(runtime) => {
                let detour = runtime.detour();
                super::transport::wrap_transport_runtime(
                    runtime,
                    None,
                    connect_timeout,
                    detour.as_deref(),
                )
                .await?
            }
            None => super::transport::wrap_transport(node, None, connect_timeout, None).await?,
        };
        Self::open_udp_stream(uuid.as_bytes(), stream, target, target_domain).await
    }

    /// UDP counterpart of [`TcpOutbound::dial_runtime_detoured`]: the
    /// command-UDP stream *is* the path the datagrams ride, so open it over
    /// the detour the caller named rather than the node's own.
    async fn dial_udp_stream_detoured(
        node: &Node,
        runtime: &Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        detour: &Arc<crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::require_udp(node)?;
        let uuid = uuid(node)?;
        let stream =
            super::transport::wrap_transport_runtime(runtime, None, connect_timeout, Some(detour))
                .await?;
        Self::open_udp_stream(uuid.as_bytes(), stream, target, target_domain).await
    }

    fn require_udp(node: &Node) -> anyhow::Result<()> {
        if !crate::descriptor::network_allows_udp(node) {
            anyhow::bail!(
                "VMess UDP: node network {:?} does not include \"udp\"",
                node.network()
            );
        }
        Ok(())
    }

    async fn open_udp_stream(
        uuid_bytes: &[u8],
        mut stream: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (header_wire, session) =
            Self::request_header(uuid_bytes, target, target_domain, CMD_UDP)?;
        super::transport::write_request(&mut stream, &header_wire).await?;
        Ok(Self::new_udp_transport(stream, session, target)?)
    }

    fn new_udp_transport(
        stream: Box<dyn AsyncReadWrite>,
        session: Session,
        target: SocketAddr,
    ) -> anyhow::Result<Arc<VmessUdpTransport>> {
        let (reader, writer) = tokio::io::split(stream);
        Ok(Arc::new(VmessUdpTransport {
            writer: tokio::sync::Mutex::new(VmessUdpWriter {
                stream: writer,
                body: BodyChunks::new(&session.req_key, &session.req_iv)?,
            }),
            poison: FramePoison::default(),
            reader: tokio::sync::Mutex::new(VmessUdpReader {
                stream: reader,
                // Xray writes the response header with the first reply. Read
                // it lazily so a dial can send before any reply exists.
                response_header: Some(session),
                body: None,
            }),
            target,
        }))
    }
}

fn uuid(node: &Node) -> anyhow::Result<uuid::Uuid> {
    uuid::Uuid::parse_str(node.vmess().unwrap().uuid.as_deref().unwrap_or(""))
        .map_err(|error| anyhow::anyhow!("invalid VMess UUID: {}", error))
}

#[async_trait]
impl TcpOutbound for VmessHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let uuid = uuid(node)?;

        let stream = super::transport::wrap_transport(node, None, connect_timeout, None).await?;
        Self::perform_handshake(uuid.as_bytes(), stream, target, target_domain)
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let uuid = uuid(node)?;

        let stream =
            super::transport::wrap_transport(node, Some(tcp), connect_timeout, None).await?;
        Self::perform_handshake(uuid.as_bytes(), stream, target, target_domain)
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let uuid = uuid(&runtime.node)?;
        let detour = runtime.detour();
        let stream = super::transport::wrap_transport_runtime(
            &runtime,
            None,
            connect_timeout,
            detour.as_deref(),
        )
        .await?;
        Self::perform_handshake(uuid.as_bytes(), stream, target, target_domain)
    }

    async fn dial_runtime_detoured(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        detour: &Arc<crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<ProxyStream> {
        let uuid = uuid(&runtime.node)?;
        let stream =
            super::transport::wrap_transport_runtime(&runtime, None, connect_timeout, Some(detour))
                .await?;
        Self::perform_handshake(uuid.as_bytes(), stream, target, target_domain)
    }
}

#[async_trait]
impl PacketOutbound for VmessHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::dial_udp_stream(node, None, target, target_domain, connect_timeout).await
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::dial_udp_stream(
            &runtime.node,
            Some(&runtime),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    async fn dial_udp_transport_runtime_detoured(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        detour: &Arc<crate::proxy::detour::DetourPath>,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::dial_udp_stream_detoured(
            &runtime.node,
            &runtime,
            target,
            target_domain,
            connect_timeout,
            detour,
        )
        .await
    }
}

#[async_trait]
impl WarmableOutbound for VmessHandler {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: std::time::Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        super::transport::xhttp::XhttpRuntime::warm(&runtime, connect_timeout).await
    }
}

#[async_trait]
impl ProbeableOutbound for VmessHandler {}

/// `ShakeSizeParser` (encoding/auth.go): a SHAKE128 stream over the body IV
/// yielding the 2-byte XOR mask for each chunk's length field, in order.
struct ShakeSizeParser(shake::ShakeReader<168>);

impl ShakeSizeParser {
    fn new(iv: &[u8; 16]) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        let mut h = shake::Shake128::default();
        h.update(iv);
        Self(h.finalize_xof())
    }

    fn next_mask(&mut self) -> [u8; 2] {
        use sha3::digest::XofReader;
        let mut mask = [0u8; 2];
        self.0.read(&mut mask);
        mask
    }

    fn encode_len(&mut self, size: u16) -> [u8; 2] {
        let mask = self.next_mask();
        let [a, b] = size.to_be_bytes();
        [a ^ mask[0], b ^ mask[1]]
    }

    fn decode_len(&mut self, encoded: [u8; 2]) -> u16 {
        let mask = self.next_mask();
        u16::from_be_bytes([encoded[0] ^ mask[0], encoded[1] ^ mask[1]])
    }
}

/// `GenerateChunkNonce`: the 12-byte nonce is the body IV's first 12 bytes
/// with the first two replaced by the big-endian chunk counter.
fn chunk_nonce(iv: &[u8; 16], count: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

/// Per-direction body chunk coder: SHAKE128 length masking + AES-128-GCM.
/// The AEAD runs on BoringSSL (`AeadCtx`): RustCrypto's aes-gcm measured
/// ~0.4 GB/s single-core vs BoringSSL's multi-GB/s on AES-NI
/// (benches/ss_aead.rs, same finding as the Shadowsocks `AeadCipher`),
/// which made the VMess relay single-core-bound. The header AEAD and the
/// auth-ID block stay on RustCrypto — two AEAD ops and one AES block per
/// connection are not hot.
struct BodyChunks {
    ctx: boring::aead::AeadCtx,
    iv: [u8; 16],
    size: ShakeSizeParser,
    count: u16,
}

impl BodyChunks {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> anyhow::Result<Self> {
        Ok(Self {
            ctx: boring::aead::AeadCtx::new_default_tag(
                &boring::aead::Algorithm::aes_128_gcm(),
                key,
            )?,
            iv: *iv,
            size: ShakeSizeParser::new(iv),
            count: 0,
        })
    }

    /// Seal one chunk: masked length field + AEAD(payload). An empty
    /// payload is the request-body termination chunk (Xray's outbound
    /// writes an empty MultiBuffer on upload EOF; without it the server
    /// keeps waiting for more request data).
    fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        debug_assert!(payload.len() <= CHUNK_MAX_LEN);
        let mut out = Vec::with_capacity(2 + payload.len() + GCM_TAG_LEN);
        out.extend_from_slice(&self.size.encode_len((payload.len() + GCM_TAG_LEN) as u16));
        out.extend_from_slice(payload);
        out.resize(out.len() + GCM_TAG_LEN, 0);
        let (body, tag) = out[2..].split_at_mut(payload.len());
        self.ctx
            .seal_in_place(&chunk_nonce(&self.iv, self.count), body, tag, b"")
            .expect("AES-128-GCM seal");
        self.count = self.count.wrapping_add(1);
        out
    }

    fn decode_len(&mut self, encoded: [u8; 2]) -> u16 {
        self.size.decode_len(encoded)
    }

    /// Decrypt a chunk in place (ciphertext+tag → plaintext prefix) and
    /// return the plaintext length.
    fn open_chunk(&mut self, ct: &mut [u8]) -> anyhow::Result<usize> {
        anyhow::ensure!(ct.len() >= GCM_TAG_LEN, "short VMess chunk");
        let (body, tag) = ct.split_at_mut(ct.len() - GCM_TAG_LEN);
        self.ctx
            .open_in_place(&chunk_nonce(&self.iv, self.count), body, tag, b"")
            .map_err(|e| anyhow::anyhow!("VMess response chunk decrypt failed: {e}"))?;
        self.count = self.count.wrapping_add(1);
        Ok(body.len())
    }
}

/// Background task that encrypts client→server data and decrypts
/// server→client data using the VMess AEAD chunking format.
async fn vmess_relay(
    server: Box<dyn AsyncReadWrite>,
    client: &mut tokio::io::DuplexStream,
    header_wire: Vec<u8>,
    session: Session,
) -> anyhow::Result<()> {
    let (mut server_read, mut server_write) = tokio::io::split(server);
    let (mut client_read, mut client_write) = tokio::io::split(client);

    let upload = async {
        super::transport::write_request(&mut server_write, &header_wire).await?;

        let mut body = BodyChunks::new(&session.req_key, &session.req_iv)?;
        let mut buf = vec![0u8; CHUNK_MAX_LEN];
        loop {
            let n = match client_read.read(&mut buf).now_or_never() {
                Some(read) => read?,
                None => {
                    server_write.flush().await?;
                    client_read.read(&mut buf).await?
                }
            };
            if n == 0 {
                break;
            }
            let chunk = body.seal_chunk(&buf[..n]);
            server_write.write_all(&chunk).await?;
        }
        let term = body.seal_chunk(&[]);
        server_write.write_all(&term).await?;
        server_write.flush().await?;
        Ok::<(), anyhow::Error>(())
    };

    let download = async {
        read_response_header(&mut server_read, &session).await?;

        let mut body = BodyChunks::new(&session.resp_key, &session.resp_iv)?;
        loop {
            let mut len_buf = [0u8; 2];
            if server_read.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let chunk_len = body.decode_len(len_buf) as usize;
            // size == AEAD overhead is the server's termination chunk
            // (AuthenticationReader.readInternal).
            if chunk_len == GCM_TAG_LEN {
                break;
            }
            if !(chunk_len > GCM_TAG_LEN && chunk_len <= CHUNK_MAX_LEN + GCM_TAG_LEN) {
                return Err(crate::proxy::NodeFailure(
                    anyhow::anyhow!("invalid VMess chunk size {chunk_len}")
                        .context("VMess response body"),
                )
                .into());
            }
            let mut ct = vec![0u8; chunk_len];
            server_read.read_exact(&mut ct).await?;
            let n = body
                .open_chunk(&mut ct)
                .map_err(|error| crate::proxy::NodeFailure(error.context("VMess response body")))?;
            client_write.write_all(&ct[..n]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    // Upload EOF only half-closes the request body — the response must
    // still be drained (HTTP: the reply arrives after the request ends).
    tokio::pin!(upload);
    tokio::pin!(download);
    tokio::select! {
        r = &mut download => r,
        r = &mut upload => {
            r?;
            download.await
        }
    }
}

/// `DecodeResponseHeader`: AEAD-sealed length then AEAD-sealed payload,
/// keyed from the response body key/IV with no AAD.
async fn read_response_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    session: &Session,
) -> anyhow::Result<()> {
    let mut len_ct = [0u8; 2 + GCM_TAG_LEN];
    let received = reader.read(&mut len_ct).await.map_err(|error| {
        crate::proxy::NodeFailure(anyhow::Error::new(error).context("VMess response header"))
    })?;
    // sing-vmess writes its response header lazily with the first target data;
    // no response bytes cannot distinguish target closure from a carrier fault.
    if received == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    async {
        reader.read_exact(&mut len_ct[received..]).await?;
        let len_plain = VmessHandler::open(
            &kdf16(&session.resp_key, KDF_SALT_RESP_LEN_KEY, &[]),
            &kdf12(&session.resp_iv, KDF_SALT_RESP_LEN_IV, &[]),
            &len_ct,
        )
        .map_err(|e| anyhow::anyhow!("VMess response header length decrypt failed: {:?}", e))?;
        let hdr_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        anyhow::ensure!(
            (4..=256).contains(&hdr_len),
            "invalid VMess response header length {hdr_len}"
        );

        let mut hdr_ct = vec![0u8; hdr_len + GCM_TAG_LEN];
        reader.read_exact(&mut hdr_ct).await?;
        let hdr = VmessHandler::open(
            &kdf16(&session.resp_key, KDF_SALT_RESP_KEY, &[]),
            &kdf12(&session.resp_iv, KDF_SALT_RESP_IV, &[]),
            &hdr_ct,
        )
        .map_err(|e| anyhow::anyhow!("VMess response header decrypt failed: {:?}", e))?;

        anyhow::ensure!(
            hdr[0] == session.resp_header,
            "unexpected VMess response header byte {:#x}, expected {:#x}",
            hdr[0],
            session.resp_header
        );
        // hdr[1] option, hdr[2] command id, hdr[3] command data length; the
        // command data rides inside the same header block and carries nothing
        // a plain TCP outbound needs.
        Ok::<(), anyhow::Error>(())
    }
    .await
    .map_err(|error| crate::proxy::NodeFailure(error.context("VMess response header")).into())
}

/// One command-UDP association. The request header names `target`, and each
/// AEAD chunk in either direction is exactly one datagram for/from it:
/// Xray's inbound dispatches `RequestCommandUDP` to
/// `net.UDPDestination(header.Address, header.Port)` and copies whole
/// MultiBuffers, so nothing on the wire carries a per-packet address or a
/// full-cone reply source. One stream per UDP target is therefore the correct
/// shape, not a shared multi-target source.
struct VmessUdpWriter {
    stream: WriteHalf<Box<dyn AsyncReadWrite>>,
    body: BodyChunks,
}

struct VmessUdpReader {
    stream: ReadHalf<Box<dyn AsyncReadWrite>>,
    /// `Some` until the lazily written response header has been consumed.
    response_header: Option<Session>,
    body: Option<BodyChunks>,
}

struct VmessUdpTransport {
    writer: tokio::sync::Mutex<VmessUdpWriter>,
    /// A cancelled chunk write leaves a partial frame on a reliable stream.
    poison: FramePoison,
    reader: tokio::sync::Mutex<VmessUdpReader>,
    target: SocketAddr,
}

impl std::fmt::Debug for VmessUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessUdpTransport")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl VmessUdpTransport {
    async fn send(&self, data: &[u8], admitted: Option<&AtomicBool>) -> std::io::Result<()> {
        // A zero-length chunk is the protocol's end-of-stream marker, so an
        // empty datagram cannot be represented and must be refused locally
        // rather than silently closing the association.
        if data.is_empty() || data.len() > CHUNK_MAX_LEN {
            return Err(PacketRejection::InvalidSize.into());
        }
        let mut writer = self.writer.lock().await;
        let frame = writer.body.seal_chunk(data);
        let write = self.poison.begin(admitted)?;
        writer.stream.write_all(&frame).await?;
        writer.stream.flush().await?;
        write.complete();
        Ok(())
    }
}

#[async_trait]
impl PacketTransport for VmessUdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data, None).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data, None).await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        let VmessUdpReader {
            stream,
            response_header,
            body,
        } = &mut *reader;
        if let Some(session) = response_header.take() {
            read_response_header(stream, &session)
                .await
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("VMess UDP response header: {error:#}"),
                    )
                })?;
            *body = Some(
                BodyChunks::new(&session.resp_key, &session.resp_iv)
                    .map_err(|error| std::io::Error::other(error.to_string()))?,
            );
        }
        let body = body.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VMess UDP response body is missing",
            )
        })?;
        loop {
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let chunk_len = body.decode_len(len_buf) as usize;
            if chunk_len == GCM_TAG_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "VMess UDP association closed",
                ));
            }
            if !(chunk_len > GCM_TAG_LEN && chunk_len <= CHUNK_MAX_LEN + GCM_TAG_LEN) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid VMess UDP chunk size {chunk_len}"),
                ));
            }
            if chunk_len - GCM_TAG_LEN > buf.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "VMess UDP datagram exceeds buffer",
                ));
            }
            let mut ct = vec![0u8; chunk_len];
            stream.read_exact(&mut ct).await?;
            let n = body.open_chunk(&mut ct).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })?;
            if n == 0 {
                continue;
            }
            buf[..n].copy_from_slice(&ct[..n]);
            return Ok((n, self.target));
        }
    }
}

#[cfg(test)]
mod tests;
