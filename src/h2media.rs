//! Native equivalent of Flowseal's cf_h2.py and h2_transport.py (50d539c).
//! One verified TLS/H2 connection per host, bounded multiplexing and native MTProto framing.
use crate::balancer::BALANCER;
use crate::config::*;
use crate::crypto::TrackedStream;
use crate::{ldebug, linfo, lwarn};
use bytes::{Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, Id, JoinSet};
use tokio_util::sync::CancellationToken;

const MAX_PACKET: usize = 4 * 1024 * 1024;
const CHANNEL_BYTES: usize = 8 * 1024 * 1024;
const LANE_BYTES: usize = 32 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(65);
const COOLDOWN: f64 = 30.0;

#[derive(Debug)]
enum Error {
    Io(String),
    Transport(i32),
    Budget,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => f.write_str(s),
            Self::Transport(code) => write!(f, "MTProto transport error {}", code),
            Self::Budget => f.write_str("H2 memory bound"),
        }
    }
}
impl From<h2::Error> for Error {
    fn from(e: h2::Error) -> Self {
        Self::Io(e.to_string())
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[derive(Default)]
struct Progress {
    phase: AtomicU8,
    sent: AtomicU64,
}
impl Progress {
    fn sent_at(&self) -> f64 {
        f64::from_bits(self.sent.load(Ordering::Relaxed))
    }
    fn waiting(&self, now: f64, age: f64) -> bool {
        self.phase.load(Ordering::Relaxed) == 2
            && self.sent_at() > 0.0
            && now - self.sent_at() >= age
    }
}

async fn timed<F: std::future::Future>(future: F) -> Result<F::Output, Error> {
    tokio::time::timeout(REQUEST_TIMEOUT, future)
        .await
        .map_err(|_| Error::Io("H2 operation timed out".into()))
}

struct Reply {
    body: Bytes,
    _budget: Vec<OwnedSemaphorePermit>,
}

pub struct Lane {
    host: String,
    sender: h2::client::SendRequest<Bytes>,
    slots: Arc<Semaphore>,
    uploads: Arc<Semaphore>,
    replies: Arc<Semaphore>,
    failed_until: AtomicU64,
    cancel: CancellationToken,
}

impl Lane {
    async fn connect(host: &str, cancel: CancellationToken) -> Result<Arc<Self>, Error> {
        let socket = TcpStream::connect((host, 443)).await?;
        socket.set_nodelay(true)?;
        let name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| Error::Io(e.to_string()))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(crate::ws::tls_config(false, true)))
            .connect(name, socket)
            .await?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(Error::Io("H2 ALPN was not negotiated".into()));
        }
        Self::from_io(host.to_string(), tls, cancel).await
    }

    async fn from_io<T>(host: String, io: T, cancel: CancellationToken) -> Result<Arc<Self>, Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(256 * 1024)
            .initial_connection_window_size(4 * 1024 * 1024);
        let (sender, connection) = builder.handshake(io).await?;
        let driver_cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::select! { _=driver_cancel.cancelled()=>{}, _=connection=>{} }
            driver_cancel.cancel();
        });
        STATS.h2_tcp_connections.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(Self {
            host,
            sender,
            slots: Arc::new(Semaphore::new(64)),
            uploads: Arc::new(Semaphore::new(LANE_BYTES)),
            replies: Arc::new(Semaphore::new(LANE_BYTES)),
            failed_until: AtomicU64::new(0),
            cancel,
        }))
    }

    fn cooling(&self) -> bool {
        now_monotonic() < f64::from_bits(self.failed_until.load(Ordering::Relaxed))
    }
    fn fail(&self) {
        self.failed_until
            .store((now_monotonic() + COOLDOWN).to_bits(), Ordering::Relaxed);
    }

    async fn preflight(&self) -> Result<(), Error> {
        let mut sender = self.sender.clone().ready().await?;
        let request = Request::builder()
            .method(Method::HEAD)
            .uri(format!("https://{}/api", self.host))
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true)?;
        let response = response.await?;
        if response.status().is_success() || matches!(response.status().as_u16(), 405 | 501) {
            Ok(())
        } else {
            Err(Error::Io(format!(
                "H2 preflight HTTP {}",
                response.status()
            )))
        }
    }

    async fn post(
        &self,
        body: Bytes,
        progress: Arc<Progress>,
        channel_budget: Arc<Semaphore>,
    ) -> Result<Reply, Error> {
        let request = async {
            let _slot = timed(self.slots.acquire())
                .await?
                .map_err(|_| Error::Budget)?;
            let _upload = timed(self.uploads.acquire_many(body.len() as u32))
                .await?
                .map_err(|_| Error::Budget)?;
            let mut sender = timed(self.sender.clone().ready()).await??;
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("https://{}/api", self.host))
                .header("content-type", "application/octet-stream")
                .header("accept-encoding", "identity")
                .header("content-length", body.len())
                .body(())
                .unwrap();
            let (response, mut stream) = sender.send_request(request, body.is_empty())?;
            progress.phase.store(1, Ordering::Relaxed);
            let mut offset = 0;
            while offset < body.len() {
                let wanted = (body.len() - offset).min(64 * 1024);
                stream.reserve_capacity(wanted);
                let capacity = timed(poll_fn(|cx| stream.poll_capacity(cx)))
                    .await?
                    .ok_or_else(|| Error::Io("H2 upload closed".into()))??;
                let n = capacity.min(wanted);
                if n == 0 {
                    continue;
                }
                stream.send_data(body.slice(offset..offset + n), offset + n == body.len())?;
                offset += n;
            }
            progress
                .sent
                .store(now_monotonic().to_bits(), Ordering::Relaxed);
            progress.phase.store(2, Ordering::Relaxed);
            STATS.h2_requests.fetch_add(1, Ordering::Relaxed);
            let response = timed(response).await??;
            progress.phase.store(3, Ordering::Relaxed);
            if matches!(response.status().as_u16(), 403 | 404 | 429 | 444) {
                return Err(Error::Transport(-(response.status().as_u16() as i32)));
            }
            if response.status() != StatusCode::OK {
                return Err(Error::Io(format!("H2 HTTP {}", response.status())));
            }
            if response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_ascii_lowercase().contains("text/html"))
                .unwrap_or(false)
            {
                return Err(Error::Io("H2 response is HTML".into()));
            }
            let length = response
                .headers()
                .get("content-length")
                .map(|v| {
                    v.to_str()
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .ok_or_else(|| Error::Io("Invalid Content-Length".into()))
                })
                .transpose()?;
            if length.is_some_and(|n| n > MAX_PACKET) {
                return Err(Error::Budget);
            }
            let mut recv = response.into_body();
            let mut content = BytesMut::new();
            let mut budget = Vec::new();
            while let Some(chunk) = timed(recv.data()).await? {
                let chunk = chunk?;
                if content.len() + chunk.len() > MAX_PACKET {
                    return Err(Error::Budget);
                }
                if !chunk.is_empty() {
                    budget.push(
                        self.replies
                            .clone()
                            .try_acquire_many_owned(chunk.len() as u32)
                            .map_err(|_| Error::Budget)?,
                    );
                    budget.push(
                        channel_budget
                            .clone()
                            .try_acquire_many_owned(chunk.len() as u32)
                            .map_err(|_| Error::Budget)?,
                    );
                }
                content.extend_from_slice(&chunk);
                recv.flow_control().release_capacity(chunk.len())?;
            }
            if length.is_some_and(|n| n != content.len()) || content.len() % 4 != 0 {
                return Err(Error::Io("Incomplete or unaligned H2 body".into()));
            }
            if content.len() == 4 {
                let code = i32::from_le_bytes(content[..].try_into().unwrap());
                if code < 0 {
                    return Err(Error::Transport(code));
                }
            }
            Ok(Reply {
                body: content.freeze(),
                _budget: budget,
            })
        };
        tokio::select! {
            _=self.cancel.cancelled()=>Err(Error::Io("H2 pool stopped".into())),
            result=request=>{
                if matches!(&result,Err(Error::Io(_))) {self.fail();
                    if self.slots.available_permits()==64 {self.cancel.cancel();}
                } result
            }
        }
    }
}
impl Drop for Lane {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

type LaneSlot = Arc<Mutex<Option<Arc<Lane>>>>;
pub struct H2Pool {
    lanes: Mutex<HashMap<String, LaneSlot>>,
    failed: Mutex<HashMap<String, f64>>,
    retry: Mutex<HashMap<i32, f64>>,
    cancel: CancellationToken,
}
impl H2Pool {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            lanes: Mutex::new(HashMap::new()),
            failed: Mutex::new(HashMap::new()),
            retry: Mutex::new(HashMap::new()),
            cancel,
        }
    }
    pub async fn open(&self, dc: i32, label: &str) -> Option<Arc<Lane>> {
        if !DC_DEFAULT_IPS.contains_key(&dc)
            || self.cancel.is_cancelled()
            || now_monotonic() < self.retry.lock().await.get(&dc).copied().unwrap_or(0.0)
        {
            return None;
        }
        let setup = async {
            let domains = BALANCER.read().get_domains_for_dc(dc);
            for base in domains {
                let host = format!("kws{}.{}", dc, base);
                if now_monotonic() < self.failed.lock().await.get(&host).copied().unwrap_or(0.0) {
                    continue;
                }
                let slot = self
                    .lanes
                    .lock()
                    .await
                    .entry(host.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(None)))
                    .clone();
                let mut guard = slot.lock().await;
                if let Some(lane) = guard.as_ref() {
                    if lane.cooling() {
                        continue;
                    }
                    if !lane.cancel.is_cancelled() {
                        return Some(lane.clone());
                    }
                    *guard = None;
                }
                let result = async {
                    let lane = Lane::connect(&host, self.cancel.child_token()).await?;
                    lane.preflight().await?;
                    Ok::<_, Error>(lane)
                }
                .await;
                match result {
                    Ok(lane) => {
                        if self.cancel.is_cancelled() {
                            return None;
                        }
                        *guard = Some(lane.clone());
                        BALANCER.write().update_domain_for_dc(dc, &base);
                        linfo!("[{}] ROUTE DC{} media -> H2 {}", label, dc, host);
                        return Some(lane);
                    }
                    Err(error) => {
                        self.failed
                            .lock()
                            .await
                            .insert(host.clone(), now_monotonic() + COOLDOWN);
                        STATS.h2_errors.fetch_add(1, Ordering::Relaxed);
                        ldebug!("H2 preflight {} failed: {:?}", host, error);
                    }
                }
            }
            None
        };
        tokio::select! {
            _=self.cancel.cancelled()=>None,
            result=tokio::time::timeout(Duration::from_secs(8),setup)=>match result {
                Ok(lane)=>lane,Err(_)=>{self.retry.lock().await.insert(dc,now_monotonic()+COOLDOWN);
                    STATS.h2_errors.fetch_add(1,Ordering::Relaxed);None}
            }
        }
    }
    pub async fn close(&self) {
        self.cancel.cancel();
        self.lanes.lock().await.clear();
        self.failed.lock().await.clear();
        self.retry.lock().await.clear();
    }
}

async fn plain<R: AsyncRead + Unpin>(
    reader: &mut R,
    dec: &mut TrackedStream,
    n: usize,
) -> io::Result<Vec<u8>> {
    let mut data = vec![0; n];
    reader.read_exact(&mut data).await?;
    dec.xor(&mut data);
    Ok(data)
}
async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    dec: &mut TrackedStream,
    tag: u32,
) -> io::Result<Bytes> {
    let length = if tag == PROTO_TAG_ABRIDGED {
        let first = plain(reader, dec, 1).await?[0] & 0x7f;
        if first == 0x7f {
            let p = plain(reader, dec, 3).await?;
            u32::from_le_bytes([p[0], p[1], p[2], 0]) as usize * 4
        } else {
            first as usize * 4
        }
    } else {
        u32::from_le_bytes(plain(reader, dec, 4).await?.try_into().unwrap()) as usize & 0x7fff_ffff
    };
    if !(24..=MAX_PACKET + if tag == PROTO_TAG_SECURE { 256 } else { 0 }).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MTProto packet bound",
        ));
    }
    let mut body = plain(reader, dec, length).await?;
    if tag == PROTO_TAG_SECURE {
        let unencrypted = body[..8] == [0; 8];
        let packet_length = if unencrypted {
            20 + u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize
        } else {
            24 + (length - 24) / 16 * 16
        };
        if packet_length < 24
            || packet_length > length
            || length - packet_length > if unencrypted { 256 } else { 15 }
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MTProto padding",
            ));
        }
        body.truncate(packet_length);
    }
    if body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MTProto alignment",
        ));
    }
    Ok(body.into())
}

fn encode_reply(body: &[u8], tag: u32) -> io::Result<Vec<u8>> {
    if body.is_empty() || body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MTProto reply bound",
        ));
    }
    let mut frame = Vec::with_capacity(body.len() + 8);
    if tag == PROTO_TAG_ABRIDGED {
        let words = body.len() / 4;
        if words < 127 {
            frame.push(words as u8);
        } else {
            frame.push(127);
            frame.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
        frame.extend_from_slice(body);
    } else {
        use rand::RngCore;
        let padding = if tag == PROTO_TAG_SECURE {
            (rand::thread_rng().next_u32() % 4) as usize
        } else {
            0
        };
        frame.extend_from_slice(&((body.len() + padding) as u32).to_le_bytes());
        frame.extend_from_slice(body);
        let off = frame.len();
        frame.resize(off + padding, 0);
        rand::thread_rng().fill_bytes(&mut frame[off..]);
    }
    Ok(frame)
}

struct History {
    body: Bytes,
    created: f64,
    sequence: u64,
    attempts: u8,
    last_attempt: f64,
    reply_id: Vec<u8>,
    retired: bool,
}
struct Pending {
    length: usize,
    sequence: Option<u64>,
    replay: bool,
    progress: Arc<Progress>,
    abort: AbortHandle,
}

fn launch(
    tasks: &mut JoinSet<Result<Reply, Error>>,
    pending: &mut HashMap<Id, Pending>,
    lane: Arc<Lane>,
    budget: Arc<Semaphore>,
    body: Bytes,
    sequence: Option<u64>,
    replay: bool,
) {
    let length = body.len();
    let progress = Arc::new(Progress::default());
    let p = progress.clone();
    let abort = tasks.spawn(async move { lane.post(body, p, budget).await });
    pending.insert(
        abort.id(),
        Pending {
            length,
            sequence,
            replay,
            progress,
            abort,
        },
    );
    STATS.bytes_up.fetch_add(length as i64, Ordering::Relaxed);
}

pub async fn bridge<R, W>(
    mut reader: R,
    mut writer: W,
    lane: Arc<Lane>,
    mut dec: TrackedStream,
    mut enc: TrackedStream,
    tag: u32,
    label: String,
    cancel: CancellationToken,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel(1);
    let read_task = tokio::spawn(async move {
        loop {
            let result = read_packet(&mut reader, &mut dec, tag).await;
            let failed = result.is_err();
            if tx.send(result).await.is_err() || failed {
                break;
            }
        }
    });
    let mut tasks = JoinSet::new();
    let mut pending = HashMap::<Id, Pending>::new();
    let mut history = VecDeque::<History>::new();
    let budget = Arc::new(Semaphore::new(CHANNEL_BYTES));
    let mut next_body: Option<Bytes> = None;
    let mut sequence = 0u64;
    let mut auth_key = Bytes::new();
    let mut last_progress = now_monotonic();
    let mut transport_error = None;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if let Some(body) = next_body.as_ref() {
            let bytes: usize = pending.values().map(|p| p.length).sum();
            if pending.len() < 8 && bytes + body.len() <= CHANNEL_BYTES {
                let body: Bytes = next_body.take().unwrap();
                sequence += 1;
                let mut retained = None;
                if body[..8] != [0; 8] && body.len() <= 64 * 1024 {
                    if auth_key.as_ref() != &body[..8] {
                        history.clear();
                        auth_key = body.slice(..8);
                    }
                    if let Some(entry) = history.iter().find(|h| h.body == body) {
                        retained = Some(entry.sequence);
                    } else {
                        retained = Some(sequence);
                        history.push_back(History {
                            body: body.clone(),
                            created: now_monotonic(),
                            sequence,
                            attempts: 0,
                            last_attempt: 0.0,
                            reply_id: Vec::new(),
                            retired: false,
                        });
                    }
                    while history.len() > 16
                        || history.iter().map(|h| h.body.len()).sum::<usize>() > 64 * 1024
                    {
                        history.pop_front();
                    }
                }
                launch(
                    &mut tasks,
                    &mut pending,
                    lane.clone(),
                    budget.clone(),
                    body,
                    retained,
                    false,
                );
            }
        }
        tokio::select! {
            _=cancel.cancelled()=>break,
            packet=rx.recv(),if next_body.is_none()=>match packet {
                Some(Ok(body))=>next_body=Some(body),_=>break,
            },
            result=tasks.join_next_with_id(),if !tasks.is_empty()=>{
                let (id,result)=match result.unwrap() {Ok((id,result))=>(id,Some(result)),Err(error)=>(error.id(),None)};
                let meta=pending.remove(&id);
                match result {
                    Some(Ok(reply))=>{
                        last_progress=now_monotonic();
                        if let Some(entry)=meta.as_ref().and_then(|m|m.sequence).and_then(|seq|history.iter_mut().find(|h|h.sequence==seq)) {
                            let identity=&reply.body[..reply.body.len().min(24)];
                            if !reply.body.is_empty() && entry.reply_id!=identity {entry.reply_id=identity.to_vec();entry.attempts=0;}
                        }
                        if !reply.body.is_empty() {
                            let Ok(mut frame)=encode_reply(&reply.body,tag) else {break};enc.xor(&mut frame);
                            let result=tokio::select!{_=cancel.cancelled()=>break,
                                result=tokio::time::timeout(Duration::from_secs(10),writer.write_all(&frame))=>result};
                            if !matches!(result,Ok(Ok(()))){break;}
                            STATS.bytes_down.fetch_add(reply.body.len() as i64,Ordering::Relaxed);
                        }
                    },
                    Some(Err(Error::Transport(code)))=>{transport_error=Some(code);STATS.h2_errors.fetch_add(1,Ordering::Relaxed);break;},
                    Some(Err(error))=>{STATS.h2_errors.fetch_add(1,Ordering::Relaxed);lwarn!("[{}] H2 request ended: {}",label,error);break;},
                    None=>{},
                }
            },
            _=tick.tick(),if !history.is_empty() || !pending.is_empty()=>{
                let now=now_monotonic();
                history.retain(|entry| now-entry.created<=30.0);
                // Free a stalled header request when new native traffic needs a slot.
                if next_body.is_some() {
                    if let Some((_,oldest))=pending.iter().filter(|(_,p)|p.progress.waiting(now,3.0))
                        .min_by(|(_,a),(_,b)|a.progress.sent_at().total_cmp(&b.progress.sent_at())) {
                        if let Some(entry)=oldest.sequence.and_then(|seq|history.iter_mut().find(|h|h.sequence==seq)){entry.retired=true;}
                        oldest.abort.abort();
                    }
                }
                let last=history.back().map(|h|h.sequence);
                for entry in history.iter_mut() {
                    if now-entry.created>30.0 || entry.attempts>=3 || (entry.last_attempt>0.0 && now-entry.last_attempt<2.0) {continue;}
                    let related:Vec<_>=pending.values().filter(|p|p.sequence==Some(entry.sequence)).collect();
                    if related.iter().any(|p|p.progress.phase.load(Ordering::Relaxed)==3){continue;}
                    if let Some(replay)=related.iter().find(|p|p.replay) {
                        if replay.progress.waiting(now,30.0){replay.abort.abort();}continue;
                    }
                    let overdue=entry.retired || related.iter().any(|p|!p.replay && p.progress.waiting(now,3.0));
                    if !overdue && (Some(entry.sequence)!=last || !pending.is_empty() || now-last_progress<1.0){continue;}
                    if !overdue && entry.attempts>0 && now-last_progress<1.0 {continue;}
                    if pending.len()>=8 || pending.values().filter(|p|p.replay).count()>=2 ||
                        pending.values().map(|p|p.length).sum::<usize>()+entry.body.len()>CHANNEL_BYTES {continue;}
                    entry.attempts+=1;entry.last_attempt=now;
                    launch(&mut tasks,&mut pending,lane.clone(),budget.clone(),entry.body.clone(),Some(entry.sequence),true);break;
                }
            }
        }
    }
    read_task.abort();
    let _ = read_task.await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    if let Some(code) = transport_error {
        if let Ok(mut frame) = encode_reply(&code.to_le_bytes(), tag) {
            enc.xor(&mut frame);
            let _ = tokio::time::timeout(Duration::from_secs(5), writer.write_all(&frame)).await;
        }
    }
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn endpoint(
        status: u16,
        content_type: &str,
        reply: Bytes,
    ) -> (Arc<Lane>, CancellationToken) {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let cancel = CancellationToken::new();
        let ct = content_type.to_string();
        tokio::spawn(async move {
            let mut server = h2::server::handshake(server).await.unwrap();
            while let Some(Ok((request, mut response))) = server.accept().await {
                let reply = reply.clone();
                let ct = ct.clone();
                tokio::spawn(async move {
                    let method = request.method().clone();
                    let mut body = request.into_body();
                    while let Some(Ok(data)) = body.data().await {
                        let _ = body.flow_control().release_capacity(data.len());
                    }
                    let reply = if method == Method::HEAD {
                        Bytes::new()
                    } else {
                        reply
                    };
                    let headers = http::Response::builder()
                        .status(if method == Method::HEAD { 405 } else { status })
                        .header("content-type", ct)
                        .header("content-length", reply.len())
                        .body(())
                        .unwrap();
                    if let Ok(mut stream) = response.send_response(headers, reply.is_empty()) {
                        if !reply.is_empty() {
                            let _ = stream.send_data(reply, true);
                        }
                    }
                });
            }
        });
        (
            Lane::from_io("test.example".into(), client, cancel.child_token())
                .await
                .unwrap(),
            cancel,
        )
    }
    #[tokio::test]
    async fn concurrent_posts_share_one_h2_lane_and_release_budgets() {
        let (lane, cancel) =
            endpoint(200, "application/octet-stream", Bytes::from(vec![8; 24])).await;
        lane.preflight().await.unwrap();
        let budget = Arc::new(Semaphore::new(CHANNEL_BYTES));
        let mut tasks = JoinSet::new();
        for _ in 0..12 {
            let lane = lane.clone();
            let budget = budget.clone();
            tasks.spawn(async move {
                lane.post(
                    Bytes::from(vec![1; 24]),
                    Arc::new(Progress::default()),
                    budget,
                )
                .await
                .unwrap()
            });
        }
        while let Some(result) = tasks.join_next().await {
            assert_eq!(result.unwrap().body.len(), 24);
        }
        assert_eq!(budget.available_permits(), CHANNEL_BYTES);
        assert_eq!(lane.replies.available_permits(), LANE_BYTES);
        assert_eq!(lane.slots.available_permits(), 64);
        cancel.cancel();
    }

    #[tokio::test]
    async fn large_reply_crosses_flow_control_windows_and_releases_memory() {
        let (lane,cancel)=endpoint(200,"application/octet-stream",Bytes::from(vec![8;MAX_PACKET])).await;
        let budget=Arc::new(Semaphore::new(CHANNEL_BYTES));
        let reply=tokio::time::timeout(Duration::from_secs(3),lane.post(Bytes::from(vec![1;24]),
            Arc::new(Progress::default()),budget.clone())).await.unwrap().unwrap();
        assert_eq!(reply.body.len(),MAX_PACKET);
        assert_eq!(budget.available_permits(),CHANNEL_BYTES-MAX_PACKET);
        drop(reply);assert_eq!(budget.available_permits(),CHANNEL_BYTES);
        assert_eq!(lane.replies.available_permits(),LANE_BYTES);cancel.cancel();
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_before_buffering() {
        let (lane,cancel)=endpoint(200,"application/octet-stream",Bytes::from(vec![8;MAX_PACKET+4])).await;
        let budget=Arc::new(Semaphore::new(CHANNEL_BYTES));
        let result=lane.post(Bytes::from(vec![1;24]),Arc::new(Progress::default()),budget.clone()).await;
        assert!(matches!(result,Err(Error::Budget)));
        assert_eq!(budget.available_permits(),CHANNEL_BYTES);
        assert_eq!(lane.uploads.available_permits(),LANE_BYTES);cancel.cancel();
    }

    #[tokio::test]
    async fn cancellation_returns_inflight_slots_and_upload_budget() {
        let (client,server)=tokio::io::duplex(64*1024);let cancel=CancellationToken::new();
        tokio::spawn(async move {
            let mut connection=h2::server::handshake(server).await.unwrap();
            let _request=connection.accept().await.unwrap().unwrap();
            std::future::pending::<()>().await;
        });
        let lane=Lane::from_io("test.example".into(),client,cancel.child_token()).await.unwrap();
        let budget=Arc::new(Semaphore::new(CHANNEL_BYTES));let worker=lane.clone();let b=budget.clone();
        let request=tokio::spawn(async move {worker.post(Bytes::from(vec![1;24]),Arc::new(Progress::default()),b).await});
        tokio::time::sleep(Duration::from_millis(10)).await;cancel.cancel();
        assert!(request.await.unwrap().is_err());
        assert_eq!(lane.slots.available_permits(),64);assert_eq!(lane.uploads.available_permits(),LANE_BYTES);
        assert_eq!(budget.available_permits(),CHANNEL_BYTES);
    }
    #[tokio::test]
    async fn endpoint_errors_survive_http_status_and_binary_payload() {
        for (status, body) in [
            (404, Bytes::new()),
            (200, Bytes::copy_from_slice(&(-404i32).to_le_bytes())),
        ] {
            let (lane, cancel) = endpoint(status, "application/octet-stream", body).await;
            let result = lane
                .post(
                    Bytes::from(vec![1; 24]),
                    Arc::new(Progress::default()),
                    Arc::new(Semaphore::new(CHANNEL_BYTES)),
                )
                .await;
            assert!(matches!(result, Err(Error::Transport(-404))));
            assert!(!lane.cooling());
            cancel.cancel();
        }
    }
    #[tokio::test]
    async fn html_and_misaligned_payloads_are_rejected() {
        for (kind, body) in [
            ("text/html", Bytes::from_static(b"html")),
            ("application/octet-stream", Bytes::from_static(b"bad")),
        ] {
            let (lane, cancel) = endpoint(200, kind, body).await;
            let result = lane
                .post(
                    Bytes::from(vec![1; 24]),
                    Arc::new(Progress::default()),
                    Arc::new(Semaphore::new(CHANNEL_BYTES)),
                )
                .await;
            assert!(matches!(result, Err(Error::Io(_))));
            assert!(lane.cooling());
            cancel.cancel();
        }
    }
    #[tokio::test]
    async fn padded_plain_native_packet_accepts_extended_android_padding() {
        let mut body = vec![0; 40];
        body[16..20].copy_from_slice(&20u32.to_le_bytes());
        body.extend_from_slice(&[99; 200]);
        let mut wire = (body.len() as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(&body);
        let mut enc = crate::crypto::new_aes_ctr(&[1; 32], &[2; 16]);
        enc.xor(&mut wire);
        let (mut tx, mut rx) = tokio::io::duplex(1024);
        tx.write_all(&wire).await.unwrap();
        let mut dec = crate::crypto::new_aes_ctr(&[1; 32], &[2; 16]);
        let packet = read_packet(&mut rx, &mut dec, PROTO_TAG_SECURE)
            .await
            .unwrap();
        assert_eq!(packet.len(), 40);
    }
    #[test]
    fn replies_preserve_short_transport_errors_and_abridged_lengths() {
        assert_eq!(
            encode_reply(&(-404i32).to_le_bytes(), PROTO_TAG_INTERMEDIATE).unwrap(),
            [4, 0, 0, 0, 108, 254, 255, 255]
        );
        let frame = encode_reply(&vec![1; 512], PROTO_TAG_ABRIDGED).unwrap();
        assert_eq!(&frame[..4], &[127, 128, 0, 0]);
    }

    #[tokio::test]
    async fn encrypted_native_bridge_delivers_reply_and_transport_error() {
        for (status, reply, expected) in [
            (200, Bytes::from(vec![8; 24]), vec![8; 24]),
            (404, Bytes::new(), (-404i32).to_le_bytes().to_vec()),
        ] {
            let (lane, stop) = endpoint(status, "application/octet-stream", reply).await;
            let (mut client, server) = tokio::io::duplex(4096);
            let (reader, writer) = tokio::io::split(server);
            let cancel = CancellationToken::new();
            let bridge_cancel = cancel.clone();
            let bridge = tokio::spawn(bridge(
                reader,
                writer,
                lane,
                crate::crypto::new_aes_ctr(&[1; 32], &[2; 16]),
                crate::crypto::new_aes_ctr(&[3; 32], &[4; 16]),
                PROTO_TAG_INTERMEDIATE,
                "test".into(),
                bridge_cancel,
            ));
            let mut input = 24u32.to_le_bytes().to_vec();
            input.extend_from_slice(&[1; 24]);
            crate::crypto::new_aes_ctr(&[1; 32], &[2; 16]).xor(&mut input);
            client.write_all(&input).await.unwrap();
            let mut output = vec![0; 4 + expected.len()];
            tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut output))
                .await
                .unwrap()
                .unwrap();
            crate::crypto::new_aes_ctr(&[3; 32], &[4; 16]).xor(&mut output);
            assert_eq!(&output[..4], &(expected.len() as u32).to_le_bytes());
            assert_eq!(&output[4..], &expected);
            cancel.cancel();
            bridge.await.unwrap();
            stop.cancel();
        }
    }

    #[tokio::test]
    async fn overdue_headers_are_replayed_without_waiting_for_request_timeout() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let stop = CancellationToken::new();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_server = count.clone();
        tokio::spawn(async move {
            let mut server = h2::server::handshake(server_io).await.unwrap();
            while let Some(Ok((request, mut response))) = server.accept().await {
                let index = count_server.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut recv = request.into_body();
                    let mut body = Vec::new();
                    while let Some(Ok(data)) = recv.data().await {
                        body.extend_from_slice(&data);
                        let _ = recv.flow_control().release_capacity(data.len());
                    }
                    if index == 0 {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        return;
                    }
                    let headers = http::Response::builder()
                        .status(200)
                        .header("content-length", body.len())
                        .body(())
                        .unwrap();
                    if let Ok(mut stream) = response.send_response(headers, false) {
                        let _ = stream.send_data(Bytes::from(body), true);
                    }
                });
            }
        });
        let lane = Lane::from_io("test.example".into(), client_io, stop.child_token())
            .await
            .unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let cancel = CancellationToken::new();
        let bridge_cancel = cancel.clone();
        let task = tokio::spawn(bridge(
            reader,
            writer,
            lane,
            crate::crypto::new_aes_ctr(&[1; 32], &[2; 16]),
            crate::crypto::new_aes_ctr(&[3; 32], &[4; 16]),
            PROTO_TAG_INTERMEDIATE,
            "recovery".into(),
            bridge_cancel,
        ));
        let mut input = 24u32.to_le_bytes().to_vec();
        input.extend_from_slice(&[1; 24]);
        crate::crypto::new_aes_ctr(&[1; 32], &[2; 16]).xor(&mut input);
        client.write_all(&input).await.unwrap();
        let mut output = [0; 28];
        tokio::time::timeout(Duration::from_secs(6), client.read_exact(&mut output))
            .await
            .unwrap()
            .unwrap();
        crate::crypto::new_aes_ctr(&[3; 32], &[4; 16]).xor(&mut output);
        assert_eq!(&output[4..], &[1; 24]);
        assert_eq!(count.load(Ordering::Relaxed), 2);
        cancel.cancel();
        task.await.unwrap();
        stop.cancel();
    }
}
