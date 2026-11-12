use crate::config::{log_debug, log_warn, STATS};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

const CLIENT_RANDOM_OFFSET: usize = 11;
const CLIENT_RANDOM_LEN: usize = 32;
const SESSION_ID_OFFSET: usize = 44;

const TIMESTAMP_TOLERANCE: i64 = 120;
const REPLAY_WINDOW: Duration = Duration::from_secs(2 * TIMESTAMP_TOLERANCE as u64 + 1);
const REPLAY_CACHE_SIZE: usize = 65536;

// Process-wide, so stopping and restarting the proxy does not admit a replay.
static REPLAY_CACHE: once_cell::sync::Lazy<parking_lot::Mutex<ReplayCache>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(ReplayCache::new(REPLAY_WINDOW, REPLAY_CACHE_SIZE)));

struct ReplayCache {
    window: Duration,
    capacity: usize,
    expiry: HashMap<[u8; 32], Instant>,
    order: VecDeque<([u8; 32], Instant)>,
}

impl ReplayCache {
    fn new(window: Duration, capacity: usize) -> Self {
        assert!(capacity > 0);
        Self { window, capacity, expiry: HashMap::new(), order: VecDeque::new() }
    }

    fn first_seen_at(&mut self, random: [u8; 32], now: Instant) -> bool {
        while self.order.front().is_some_and(|(_, expiry)| *expiry <= now) {
            let (key, _) = self.order.pop_front().unwrap();
            self.expiry.remove(&key);
        }
        // Check before eviction: a repeated key in a full cache is still a replay.
        if self.expiry.contains_key(&random) { return false; }
        if self.expiry.len() >= self.capacity {
            let (key, _) = self.order.pop_front().unwrap();
            self.expiry.remove(&key);
        }
        let expiry = now + self.window;
        self.expiry.insert(random, expiry);
        self.order.push_back((random, expiry));
        true
    }
}
const TLS_APPDATA_MAX: usize = 16384;

const READ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_RECORD_TIMEOUT: Duration = Duration::from_secs(10);
const MASKING_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

const SH_RANDOM_OFF: usize = 11;

type HmacSha256 = Hmac<Sha256>;

pub struct FakeTlsStream {
    pub read: Box<dyn AsyncRead + Send + Unpin>,
    pub write: Box<dyn AsyncWrite + Send + Unpin>,
}

#[derive(Default)]
struct ClientHelloInfo {
    suites: Vec<u16>,
    hybrid: bool,
}
static PROFILED_APPDATA_LEN: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn parse_client_hello(data: &[u8]) -> Option<ClientHelloInfo> {
    fn word(d: &[u8], p: usize) -> Option<usize> {
        Some(u16::from_be_bytes(d.get(p..p + 2)?.try_into().ok()?) as usize)
    }
    let mut p = 43;
    p += 1 + *data.get(p)? as usize;
    let len = word(data, p)?;
    p += 2;
    let suites = data
        .get(p..p + len)?
        .chunks_exact(2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .collect();
    p += len;
    p += 1 + *data.get(p)? as usize;
    let end = p + 2 + word(data, p)?;
    p += 2;
    if end > data.len() {
        return None;
    }
    let mut hybrid = false;
    while p + 4 <= end {
        let kind = word(data, p)?;
        let len = word(data, p + 2)?;
        p += 4;
        let ext = data.get(p..p + len)?;
        if kind == 0x33 && ext.len() >= 2 {
            let mut off = 2;
            let end = (2 + word(ext, 0)?).min(ext.len());
            while off + 4 <= end {
                let group = word(ext, off)?;
                let n = word(ext, off + 2)?;
                off += 4;
                if off + n > end {
                    return None;
                }
                if group == 0x11ec && n == 1216 {
                    hybrid = true;
                }
                off += n;
            }
        }
        p += len;
    }
    Some(ClientHelloInfo { suites, hybrid })
}

fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<([u8; 32], Vec<u8>, i64)> {
    if data.len() < 43 {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random
        .copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    for b in &mut zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] {
        *b = 0;
    }

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    if expected[..28].ct_eq(&client_random[..28]).unwrap_u8() != 1 {
        return None;
    }

    let mut ts_bytes = [0u8; 4];
    for i in 0..4 {
        ts_bytes[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_bytes) as i64;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - timestamp).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let session_len = *data.get(43)? as usize;
    if session_len > 32 {
        return None;
    }
    let session_id = data
        .get(SESSION_ID_OFFSET..SESSION_ID_OFFSET + session_len)?
        .to_vec();

    Some((client_random, session_id, timestamp))
}

fn build_server_hello(
    secret: &[u8],
    client_random: &[u8; 32],
    session_id: &[u8],
    info: &ClientHelloInfo,
) -> Vec<u8> {
    let private = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let public = x25519_dalek::PublicKey::from(&private);
    let mut key = Vec::new();
    let group: u16 = if info.hybrid {
        key.resize(1088, 0);
        rand::thread_rng().fill_bytes(&mut key);
        0x11ec
    } else {
        0x001d
    };
    key.extend_from_slice(public.as_bytes());
    let suite = [0x1301u16, 0x1303, 0x1302]
        .into_iter()
        .find(|v| info.suites.contains(v))
        .unwrap_or(0x1301);
    let mut extensions = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33];
    extensions.extend_from_slice(&((4 + key.len()) as u16).to_be_bytes());
    extensions.extend_from_slice(&group.to_be_bytes());
    extensions.extend_from_slice(&(key.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0; 32]);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![
        2,
        ((body.len() >> 16) & 255) as u8,
        ((body.len() >> 8) & 255) as u8,
        body.len() as u8,
    ];
    handshake.extend_from_slice(&body);
    let mut response = vec![0x16, 0x03, 0x03];
    response.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    response.extend_from_slice(&handshake);
    response.extend_from_slice(&CCS_FRAME);
    let profile = PROFILED_APPDATA_LEN.load(Ordering::Relaxed);
    let size = if profile == 0 {
        64 + (rand::thread_rng().next_u32() % 97) as usize
    } else {
        profile.clamp(64, TLS_APPDATA_MAX)
    };
    response.extend_from_slice(&[0x17, 0x03, 0x03]);
    response.extend_from_slice(&(size as u16).to_be_bytes());
    let off = response.len();
    response.resize(off + size, 0);
    rand::thread_rng().fill_bytes(&mut response[off..]);
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(client_random);
    mac.update(&response);
    response[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&mac.finalize().into_bytes());
    response
}

fn first_appdata_record_len(data: &[u8]) -> Option<usize> {
    let mut p = 0;
    while p + 5 <= data.len() {
        let n = u16::from_be_bytes([data[p + 3], data[p + 4]]) as usize;
        match data[p] {
            TLS_RECORD_APPDATA => return Some(n),
            TLS_RECORD_HANDSHAKE | TLS_RECORD_CCS => {}
            _ => return Some(0),
        }
        p += 5 + n;
    }
    None
}

pub async fn profile_masking_site(domain: &str) {
    PROFILED_APPDATA_LEN.store(0, Ordering::Relaxed);
    if domain.is_empty() {
        return;
    }
    let probe = async {
        let name = rustls_pki_types::ServerName::try_from(domain.to_string()).ok()?;
        let mut cfg = crate::ws::tls_config(false, false);
        cfg.enable_sni = true;
        let mut hello = rustls::ClientConnection::new(std::sync::Arc::new(cfg), name).ok()?;
        let mut initial = Vec::new();
        hello.write_tls(&mut initial).ok()?;
        let addresses = tokio::net::lookup_host((domain, 443)).await.ok()?;
        let addr = addresses
            .into_iter()
            .find(|a| !a.ip().is_loopback() && !a.ip().is_unspecified())?;
        let mut stream = TcpStream::connect(addr).await.ok()?;
        stream.write_all(&initial).await.ok()?;
        let mut data = Vec::new();
        let mut buf = [0u8; 16384];
        while data.len() < 128 * 1024 {
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            data.extend_from_slice(&buf[..n]);
            if let Some(n) = first_appdata_record_len(&data) {
                return if n > 0 { Some(n) } else { None };
            }
        }
        None
    };
    match tokio::time::timeout(Duration::from_secs(5), probe).await {
        Ok(Some(n)) => {
            PROFILED_APPDATA_LEN.store(n.clamp(64, TLS_APPDATA_MAX), Ordering::Relaxed);
            log_debug(&format!(
                "Fake TLS profile: first encrypted record {} bytes",
                n
            ));
        }
        _ => log_warn("Fake TLS profile unavailable; using bounded random record sizes"),
    }
}

fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / TLS_APPDATA_MAX + 1));
    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + TLS_APPDATA_MAX, data.len());
        let chunk = &data[offset..end];
        out.push(TLS_RECORD_APPDATA);
        out.push(0x03);
        out.push(0x03);
        out.push((chunk.len() >> 8) as u8);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
        offset = end;
    }
    out
}

struct TlsRecordReader {
    inner: ReadHalf<TcpStream>,
    buf: Vec<u8>,
    pos: usize,
    read_left: usize,
}

impl TlsRecordReader {
    fn new(inner: ReadHalf<TcpStream>) -> Self {
        TlsRecordReader {
            inner,
            buf: Vec::new(),
            pos: 0,
            read_left: 0,
        }
    }

    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn next_payload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            loop {
                if self.read_left > 0 {
                    let want = std::cmp::min(self.read_left, 16384);
                    let mut chunk = vec![0u8; want];
                    let n = self.inner.read(&mut chunk).await?;
                    if n == 0 {
                        return Ok(Vec::new());
                    }
                    chunk.truncate(n);
                    self.read_left -= n;
                    return Ok(chunk);
                }

                let mut hdr = [0u8; 5];
                self.inner.read_exact(&mut hdr).await?;
                let rtype = hdr[0];
                let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;

                if rtype == TLS_RECORD_CCS {
                    if rec_len > 0 {
                        let mut junk = vec![0u8; rec_len];
                        self.inner.read_exact(&mut junk).await?;
                    }
                    continue;
                }

                if rtype != TLS_RECORD_APPDATA {
                    return Ok(Vec::new());
                }

                let want = std::cmp::min(rec_len, 65536);
                let mut chunk = vec![0u8; want];
                let n = self.inner.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(Vec::new());
                }
                chunk.truncate(n);
                if rec_len > n {
                    self.read_left = rec_len - n;
                }
                return Ok(chunk);
            }
        })
    }
}

impl AsyncRead for TlsRecordReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            let avail = this.buf.len() - this.pos;
            if avail > 0 {
                let n = std::cmp::min(avail, buf.remaining());
                let src = &this.buf[this.pos..this.pos + n];
                buf.put_slice(src);
                this.pos += n;
                if this.pos == this.buf.len() {
                    this.buf.clear();
                    this.pos = 0;
                }
                return std::task::Poll::Ready(Ok(()));
            }

            this.compact();
            let polled = {
                let mut fut = this.next_payload();
                Pin::new(&mut fut).poll(cx)
            };
            match polled {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Err(
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "faketls eof")
                        } else {
                            e
                        },
                    ))
                }
                std::task::Poll::Ready(Ok(payload)) => {
                    if payload.is_empty() {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    this.buf = payload;
                    this.pos = 0;
                }
            }
        }
    }
}

struct TlsRecordWriter {
    inner: WriteHalf<TcpStream>,
}

impl TlsRecordWriter {
    fn new(inner: WriteHalf<TcpStream>) -> Self {
        TlsRecordWriter { inner }
    }
}

impl AsyncWrite for TlsRecordWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let wrapped = wrap_tls_record(buf);
        match Pin::new(&mut this.inner).poll_write(cx, &wrapped) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(n)) => {
                std::task::Poll::Ready(Ok(if n >= buf.len() { buf.len() } else { n }))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn verify_fresh_client_hello(data: &[u8], secret: &[u8]) -> Result<([u8; 32], Vec<u8>, i64), &'static str> {
    let verified = verify_client_hello(data, secret).ok_or("verify failed")?;
    // Only authenticated hellos can occupy the cache; random probes cannot evict it.
    if !REPLAY_CACHE.lock().first_seen_at(verified.0, Instant::now()) {
        return Err("hello replayed");
    }
    Ok(verified)
}

pub async fn server_handshake(
    mut conn: TcpStream,
    first: u8,
    secret: &[u8],
    masking: &str,
    label: &str,
) -> Option<FakeTlsStream> {
    let mut hdr_rest = [0u8; 4];
    match tokio::time::timeout(READ_HANDSHAKE_TIMEOUT, conn.read_exact(&mut hdr_rest)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record header", label));
            return None;
        }
    }

    let mut tls_header = [0u8; 5];
    tls_header[0] = first;
    tls_header[1..5].copy_from_slice(&hdr_rest);
    let record_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;

    let mut body = vec![0u8; record_len];
    match tokio::time::timeout(READ_RECORD_TIMEOUT, conn.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record body", label));
            return None;
        }
    }

    let mut client_hello = Vec::with_capacity(5 + record_len);
    client_hello.extend_from_slice(&tls_header);
    client_hello.extend_from_slice(&body);

    match verify_fresh_client_hello(&client_hello, secret) {
        Ok((client_random, session_id, ts)) => {
            log_debug(&format!("[{}] Fake TLS handshake ok (ts={})", label, ts));
            let info = parse_client_hello(&client_hello).unwrap_or_default();
            let delay_ms = 8 + (rand::thread_rng().next_u32() % 17) as u64;
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            let server_hello = build_server_hello(secret, &client_random, &session_id, &info);
            if conn.write_all(&server_hello).await.is_err() {
                return None;
            }
            let _ = conn.flush().await;

            let (r, w) = tokio::io::split(conn);
            Some(FakeTlsStream {
                read: Box::new(TlsRecordReader::new(r)),
                write: Box::new(TlsRecordWriter::new(w)),
            })
        }
        Err(reason) => {
            log_debug(&format!(
                "[{}] Fake TLS {} (size={} rec={}) -> masking",
                label,
                reason,
                client_hello.len(),
                record_len
            ));
            proxy_to_masking_domain(conn, client_hello, masking, label).await;
            None
        }
    }
}

async fn proxy_to_masking_domain(conn: TcpStream, initial: Vec<u8>, domain: &str, label: &str) {
    let upstream = match tokio::time::timeout(
        MASKING_CONNECT_TIMEOUT,
        TcpStream::connect((domain, 443u16)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            log_warn(&format!(
                "[{}] masking: cannot connect to {}:443",
                label, domain
            ));
            return;
        }
    };

    log_debug(&format!("[{}] masking -> {}:443", label, domain));
    STATS.connections_masked.fetch_add(1, Ordering::Relaxed);

    let mut upstream = upstream;
    if upstream.write_all(&initial).await.is_err() {
        return;
    }

    let (mut c_read, mut c_write) = tokio::io::split(conn);
    let (mut u_read, mut u_write) = tokio::io::split(upstream);

    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut c_read, &mut u_write).await;
        let _ = u_write.shutdown().await;
    });
    let down = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut u_read, &mut c_write).await;
        let _ = c_write.shutdown().await;
    });

    let _ = tokio::join!(up, down);
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    #[test]
    fn replay_cache_expires_bounds_memory_and_checks_duplicates_before_eviction() {
        let now = Instant::now();
        let mut cache = ReplayCache::new(Duration::from_secs(10), 2);
        assert!(cache.first_seen_at([1; 32], now));
        assert!(cache.first_seen_at([2; 32], now));
        assert!(!cache.first_seen_at([1; 32], now));
        assert!(!cache.first_seen_at([2; 32], now));
        assert!(cache.first_seen_at([3; 32], now));
        assert_eq!(cache.expiry.len(), 2);
        assert!(!cache.first_seen_at([2; 32], now + Duration::from_millis(9999)));
        assert!(cache.first_seen_at([2; 32], now + Duration::from_secs(10)));
        assert_eq!(cache.expiry.len(), 1);
        assert_eq!(cache.order.len(), 1);
    }

    #[test]
    fn replay_window_includes_timestamp_rounding_and_cache_survives_runtime_restart() {
        let now = Instant::now();
        let mut cache = ReplayCache::new(REPLAY_WINDOW, REPLAY_CACHE_SIZE);
        assert!(cache.first_seen_at([1; 32], now));
        assert!(!cache.first_seen_at([1; 32], now + Duration::from_millis(240999)));
        assert!(cache.first_seen_at([1; 32], now + REPLAY_WINDOW));
        let key: [u8; 32] = rand::random();
        assert!(REPLAY_CACHE.lock().first_seen_at(key, now));
        // No pool or runtime owns the cache; it remains the same process-wide object.
        assert!(!REPLAY_CACHE.lock().first_seen_at(key, now));
    }

    #[test]
    fn only_authenticated_client_hellos_enter_the_process_wide_replay_cache() {
        let secret = [17u8; 16];
        let mut hello = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut hello[48..]);
        hello[..6].copy_from_slice(&[0x16, 3, 1, 0, 59, 1]);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&hello);
        let mut random: [u8; 32] = mac.finalize().into_bytes().into();
        for (byte, time) in random[28..].iter_mut().zip(timestamp.to_le_bytes()) { *byte ^= time; }
        hello[11..43].copy_from_slice(&random);
        assert!(verify_client_hello(&hello, &secret).is_some());
        assert_eq!(verify_fresh_client_hello(&hello, &[18; 16]), Err("verify failed"));
        assert!(verify_fresh_client_hello(&hello, &secret).is_ok());
        assert_eq!(verify_fresh_client_hello(&hello, &secret), Err("hello replayed"));
    }
    #[test]
    fn server_hello_mirrors_hybrid_and_authenticates_all_records() {
        let secret = [9u8; 16];
        let random = [7u8; 32];
        let session = [5u8; 32];
        let response = build_server_hello(
            &secret,
            &random,
            &session,
            &ClientHelloInfo {
                suites: vec![0x1303],
                hybrid: true,
            },
        );
        let handshake_end = 5 + u16::from_be_bytes([response[3], response[4]]) as usize;
        assert_eq!(&response[76..78], &0x1303u16.to_be_bytes());
        assert!(response[..handshake_end]
            .windows(4)
            .any(|w| w == [0x11, 0xec, 0x04, 0x60]));
        assert_eq!(&response[handshake_end..handshake_end + 6], &CCS_FRAME);
        let mut zeroed = response.clone();
        zeroed[11..43].fill(0);
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&random);
        mac.update(&zeroed);
        assert_eq!(&response[11..43], mac.finalize().into_bytes().as_slice());
        let n = first_appdata_record_len(&response).unwrap();
        assert!((64..=160).contains(&n));
    }
    #[test]
    fn profile_parser_handles_fragmented_and_invalid_flights() {
        assert_eq!(first_appdata_record_len(&[0x16, 3, 3, 0]), None);
        assert_eq!(
            first_appdata_record_len(&[0x16, 3, 3, 0, 2, 1, 2, 0x17, 3, 3, 1, 44]),
            Some(300)
        );
        assert_eq!(first_appdata_record_len(&[0x15, 3, 3, 0, 2]), Some(0));
        for n in 0..100 {
            assert!(parse_client_hello(&vec![0; n]).is_none() || n >= 49);
        }
    }
}
