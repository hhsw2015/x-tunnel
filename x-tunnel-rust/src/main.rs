use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket as TokioUdpSocket};
use tokio::sync::{mpsc, oneshot, broadcast};
use tokio::time::{timeout, sleep};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tokio_tungstenite::tungstenite::{handshake::client::Request, Message};
use url::Url;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use clap::Parser;
use log::{info, warn, error};
use base64::{Engine as _, engine::general_purpose};
use reqwest::Client;
use hickory_resolver::Resolver;
use hickory_resolver::config::*;
use bytes::{Bytes, BytesMut};

#[derive(Parser)]
#[command(name = "x-tunnel-client")]
struct Args {
    #[arg(short, long)]
    config: Option<String>,
    #[arg(short = 'l', long)]
    listen: Option<String>,
    #[arg(short = 'f', long)]
    forward: Option<String>,
    #[arg(short, long)]
    ip: Option<String>,
    #[arg(short, long, default_value = "443")]
    block: String,
    #[arg(short, long)]
    insecure: bool,
    #[arg(short, long)]
    token: Option<String>,
    #[arg(short = 'n', long, default_value = "3")]
    connection_num: usize,
    #[arg(short, long, default_value = "https://doh.pub/dns-query")]
    dns: String,
    #[arg(short, long, default_value = "cloudflare-ech.com")]
    ech: String,
    #[arg(short, long)]
    fallback: bool,
    #[arg(short, long)]
    ips: Option<String>,
}

#[derive(Deserialize)]
struct FileConfig {
    listen: Option<String>,
    forward: Option<String>,
    ip: Option<String>,
    udp_block_ports: Option<String>,
    token: Option<String>,
    connection_num: Option<usize>,
    insecure: Option<bool>,
    ips: Option<String>,
    dns_server: Option<String>,
    ech_domain: Option<String>,
    fallback: Option<bool>,
    dial_timeout: Option<Duration>,
    ws_handshake_timeout: Option<Duration>,
    ws_write_timeout: Option<Duration>,
    ws_read_timeout: Option<Duration>,
    ping_interval: Option<Duration>,
    reconnect_delay: Option<Duration>,
}

#[derive(Clone)]
struct GlobalConfig {
    dial_timeout: Duration,
    ws_handshake_timeout: Duration,
    ws_write_timeout: Duration,
    ws_read_timeout: Duration,
    ping_interval: Duration,
    reconnect_delay: Duration,
    read_buf_32k: usize,
    read_buf_64k: usize,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            dial_timeout: Duration::from_secs(3),
            ws_handshake_timeout: Duration::from_secs(5),
            ws_write_timeout: Duration::from_secs(5),
            ws_read_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(3),
            reconnect_delay: Duration::from_secs(1),
            read_buf_32k: 32 * 1024,
            read_buf_64k: 64 * 1024,
        }
    }
}

#[derive(Clone, Copy)]
enum IpStrategy {
    Default,
    IPv4Only,
    IPv6Only,
    IPv4IPv6,
    IPv6IPv4,
}

#[derive(Clone, Copy)]
enum MessageType {
    TCPConnect = 1,
    TCPData,
    TCPClose,
    UDPConnect,
    UDPData,
    UDPClose,
    ConnStatus,
    Uplink,
    SelectDownlink,
}

#[derive(Clone, Copy)]
enum ConnStatus {
    OK = 0,
    ERR = 1,
}

const HEADER_LEN: usize = 8;

fn encode_message(msg_type: MessageType, conn_id: &str, meta: &[u8], payload: &[u8]) -> Vec<u8> {
    let conn_id = if conn_id.len() > 255 { &conn_id[..255] } else { conn_id };
    let mut buf = vec![0u8; HEADER_LEN + conn_id.len() + meta.len() + payload.len()];
    buf[0] = msg_type as u8;
    buf[1] = conn_id.len() as u8;
    let meta_len = meta.len() as u16;
    buf[2..4].copy_from_slice(&meta_len.to_be_bytes());
    let payload_len = payload.len() as u32;
    buf[4..8].copy_from_slice(&payload_len.to_be_bytes());
    let mut off = HEADER_LEN;
    buf[off..off + conn_id.len()].copy_from_slice(conn_id.as_bytes());
    off += conn_id.len();
    buf[off..off + meta.len()].copy_from_slice(meta);
    off += meta.len();
    buf[off..off + payload.len()].copy_from_slice(payload);
    buf
}

fn decode_message(data: &[u8]) -> Result<(MessageType, String, Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    if data.len() < HEADER_LEN {
        return Err("frame too short".into());
    }
    let msg_type = match data[0] {
        1 => MessageType::TCPConnect,
        2 => MessageType::TCPData,
        3 => MessageType::TCPClose,
        4 => MessageType::UDPConnect,
        5 => MessageType::UDPData,
        6 => MessageType::UDPClose,
        7 => MessageType::ConnStatus,
        8 => MessageType::Uplink,
        9 => MessageType::SelectDownlink,
        _ => return Err("invalid message type".into()),
    };
    let id_len = data[1] as usize;
    let meta_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let total = HEADER_LEN + id_len + meta_len + payload_len;
    if total > data.len() {
        return Err("invalid length".into());
    }
    let mut off = HEADER_LEN;
    let conn_id = String::from_utf8_lossy(&data[off..off + id_len]).to_string();
    off += id_len;
    let meta = data[off..off + meta_len].to_vec();
    off += meta_len;
    let payload = data[off..off + payload_len].to_vec();
    Ok((msg_type, conn_id, meta, payload))
}

#[derive(Clone)]
struct ClientConnState {
    req_type: String,
    tcp_conn: Option<Arc<Mutex<TcpStream>>>,
    udp_assoc: Option<Arc<UDPAssociation>>,
    uplink: i32,
    downlink: i32,
    last_ch: i32,
    start: Instant,
    target: String,
    connected: Option<oneshot::Sender<bool>>,
    client_addr: String,
    closed: bool,
}

impl ClientConnState {
    fn new() -> Self {
        Self {
            req_type: String::new(),
            tcp_conn: None,
            udp_assoc: None,
            uplink: 0,
            downlink: 0,
            last_ch: 0,
            start: Instant::now(),
            target: String::new(),
            connected: None,
            client_addr: String::new(),
            closed: false,
        }
    }
}

struct WriteJob {
    msg_type: u8,
    data: Vec<u8>,
    size: i64,
}

struct ECHPool {
    global_queue_bytes: AtomicI64,
    global_queue_limit: i64,
    next_channel: AtomicU64,
    ws_server_addr: String,
    connection_num: usize,
    target_ips: Vec<String>,
    client_id: String,
    ws_conns: Vec<Arc<Mutex<Option<WebSocketStream<MaybeTlsStream<TcpStream>>>>>>,
    write_queues: Vec<mpsc::UnboundedSender<WriteJob>>,
    conns: Arc<RwLock<HashMap<String, ClientConnState>>>,
}

impl ECHPool {
    fn new(addr: String, n: usize, ips: Vec<String>, client_id: String) -> Self {
        let total = if ips.is_empty() { n } else { ips.len() * n };
        let mut ws_conns = Vec::with_capacity(total);
        let mut write_queues = Vec::with_capacity(total);
        for _ in 0..total {
            ws_conns.push(Arc::new(Mutex::new(None)));
            write_queues.push(mpsc::unbounded_channel().0);
        }
        Self {
            global_queue_bytes: AtomicI64::new(0),
            global_queue_limit: (64 * 1024 * 512) as i64,
            next_channel: AtomicU64::new(0),
            ws_server_addr: addr,
            connection_num: n,
            target_ips: ips,
            client_id,
            ws_conns,
            write_queues,
            conns: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn ch_index(&self, ch_id: usize) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let idx = ch_id - 1;
        if idx >= self.write_queues.len() {
            return Err(format!("invalid channel {}", ch_id).into());
        }
        Ok(idx)
    }

    async fn start(&self) {
        for i in 0..self.write_queues.len() {
            let ip = if self.target_ips.is_empty() {
                String::new()
            } else {
                let idx = i / self.connection_num;
                if idx < self.target_ips.len() {
                    self.target_ips[idx].clone()
                } else {
                    String::new()
                }
            };
            let pool = self.clone();
            tokio::spawn(async move {
                pool.dial_and_serve(i, &ip).await;
            });
        }
    }

    async fn dial_and_serve(&self, idx: usize, ip: &str) {
        let ch_id = idx + 1;
        loop {
            let ws_conn = match dial_websocket_with_ech(&self.ws_server_addr, 3, ip, &self.client_id).await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("[client] channel {} (IP:{}) connect failed: {}", ch_id, ip, e);
                    sleep(self.reconnect_delay).await;
                    continue;
                }
            };
            *self.ws_conns[idx].lock().unwrap() = Some(ws_conn);
            info!("[client] channel {} (IP:{}) ready", ch_id, ip);

            let (write_tx, mut write_rx) = mpsc::unbounded_channel();
            self.write_queues[idx] = write_tx;

            let pool = self.clone();
            let ws_conn_clone = self.ws_conns[idx].clone();
            tokio::spawn(async move {
                pool.write_worker(ws_conn_clone, write_rx).await;
            });

            let pool = self.clone();
            let ws_conn_clone = self.ws_conns[idx].clone();
            pool.handle_channel(ch_id, ws_conn_clone).await;

            *self.ws_conns[idx].lock().unwrap() = None;
            pool.cleanup_channel(ch_id).await;
            error!("[client] channel {} disconnected, reconnecting...", ch_id);
            sleep(self.reconnect_delay).await;
        }
    }

    async fn write_worker(&self, ws_conn: Arc<Mutex<Option<WebSocketStream<MaybeTlsStream<TcpStream>>>>>, mut rx: mpsc::UnboundedReceiver<WriteJob>) {
        let mut ticker = tokio::time::interval(self.ping_interval);
        loop {
            tokio::select! {
                job = rx.recv() => {
                    if let Some(job) = job {
                        self.global_queue_bytes.fetch_sub(job.size, Ordering::Relaxed);
                        let mut conn = ws_conn.lock().unwrap();
                        if let Some(ref mut c) = *conn {
                            if let Err(_) = c.send(Message::Binary(job.data)).await {
                                return;
                            }
                        } else {
                            return;
                        }
                    } else {
                        return;
                    }
                }
                _ = ticker.tick() => {
                    let mut conn = ws_conn.lock().unwrap();
                    if let Some(ref mut c) = *conn {
                        if let Err(_) = c.send(Message::Ping(vec![])).await {
                            return;
                        }
                    } else {
                        return;
                    }
                }
            }
        }
    }

    async fn handle_channel(&self, ch_id: usize, ws_conn: Arc<Mutex<Option<WebSocketStream<MaybeTlsStream<TcpStream>>>>>) {
        let mut conn = ws_conn.lock().unwrap().take().unwrap();
        loop {
            match conn.next().await {
                Some(Ok(msg)) => {
                    if let Message::Binary(data) = msg {
                        if let Ok((msg_type, conn_id, meta, payload)) = decode_message(&data) {
                            self.note_last_channel(&conn_id, ch_id as i32).await;
                            match msg_type {
                                MessageType::Uplink => {
                                    self.note_uplink(&conn_id, ch_id as i32).await;
                                }
                                MessageType::ConnStatus => {
                                    if meta.len() >= 1 && meta[0] == ConnStatus::OK as u8 {
                                        self.signal_connected(&conn_id).await;
                                    } else {
                                        self.unregister(&conn_id).await;
                                    }
                                }
                                MessageType::TCPData => {
                                    let (selected, chosen, start, target, up, typ) = self.select_downlink(&conn_id, ch_id as i32).await;
                                    if selected {
                                        let msg = encode_message(MessageType::SelectDownlink, &conn_id, &[], &[]);
                                        self.async_write_direct(ch_id, Message::Binary(msg).into(), msg.len() as i64).await.ok();
                                        if start.elapsed().as_millis() > 0 && up > 0 {
                                            info!("[client] {} {} access: {}, channel: TX {} RX {}, ID:{}, latency {:.1} ms",
                                                "-", typ, target, up, ch_id, &conn_id[..8], start.elapsed().as_millis());
                                        }
                                    }
                                    if chosen == ch_id as i32 {
                                        let conns = self.conns.read().await;
                                        if let Some(st) = conns.get(&conn_id) {
                                            if let Some(ref tcp_conn) = st.tcp_conn {
                                                let mut conn = tcp_conn.lock().await;
                                                conn.write_all(&payload).await.ok();
                                            }
                                        }
                                    }
                                }
                                MessageType::TCPClose => {
                                    self.note_uplink(&conn_id, ch_id as i32).await;
                                    let conns = self.conns.read().await;
                                    if let Some(st) = conns.get(&conn_id) {
                                        if let Some(ref tcp_conn) = st.tcp_conn {
                                            let mut conn = tcp_conn.lock().await;
                                            conn.shutdown().await.ok();
                                        }
                                    }
                                    self.unregister(&conn_id).await;
                                }
                                MessageType::UDPData => {
                                    let (selected, chosen, start, target, up, typ) = self.select_downlink(&conn_id, ch_id as i32).await;
                                    if selected {
                                        let msg = encode_message(MessageType::SelectDownlink, &conn_id, &[], &[]);
                                        self.async_write_direct(ch_id, Message::Binary(msg).into(), msg.len() as i64).await.ok();
                                        if start.elapsed().as_millis() > 0 && up > 0 {
                                            info!("[client] {} {} access: {}, channel: TX {} RX {}, ID:{}, latency {:.1} ms",
                                                "-", typ, target, up, ch_id, &conn_id[..8], start.elapsed().as_millis());
                                        }
                                    }
                                    if chosen == ch_id as i32 {
                                        let conns = self.conns.read().await;
                                        if let Some(st) = conns.get(&conn_id) {
                                            if let Some(ref udp_assoc) = st.udp_assoc {
                                                udp_assoc.handle_udp_response(String::from_utf8_lossy(&meta).to_string(), payload).await;
                                            }
                                        }
                                    }
                                }
                                MessageType::UDPClose => {
                                    self.note_uplink(&conn_id, ch_id as i32).await;
                                    let conns = self.conns.read().await;
                                    if let Some(st) = conns.get(&conn_id) {
                                        if let Some(ref udp_assoc) = st.udp_assoc {
                                            udp_assoc.close().await;
                                        }
                                    }
                                    self.unregister(&conn_id).await;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Some(Err(_)) => return,
                None => return,
            }
        }
    }

    async fn async_write_direct(&self, ch_id: usize, msg: Message, size: i64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let idx = self.ch_index(ch_id)?;
        if self.global_queue_bytes.fetch_add(size, Ordering::Relaxed) > self.global_queue_limit {
            self.global_queue_bytes.fetch_sub(size, Ordering::Relaxed);
            return Err("queue limit exceeded".into());
        }
        if let Err(_) = self.write_queues[idx].send(WriteJob { msg_type: 0, data: msg.into_data(), size }) {
            self.global_queue_bytes.fetch_sub(size, Ordering::Relaxed);
            return Err("channel congested".into());
        }
        Ok(())
    }

    async fn broadcast_write(&self, msg: Message) {
        for (i, queue) in self.write_queues.iter().enumerate() {
            if self.ws_conns[i].lock().unwrap().is_some() {
                let size = msg.len() as i64;
                if self.global_queue_bytes.fetch_add(size, Ordering::Relaxed) > self.global_queue_limit {
                    self.global_queue_bytes.fetch_sub(size, Ordering::Relaxed);
                    continue;
                }
                queue.send(WriteJob { msg_type: 0, data: msg.clone().into_data(), size }).ok();
            }
        }
    }

    async fn note_uplink(&self, conn_id: &str, ch_id: i32) {
        let mut conns = self.conns.write().await;
        if let Some(st) = conns.get_mut(conn_id) {
            if st.uplink == 0 {
                st.uplink = ch_id;
            }
        }
    }

    async fn note_last_channel(&self, conn_id: &str, ch_id: i32) {
        let mut conns = self.conns.write().await;
        if let Some(st) = conns.get_mut(conn_id) {
            st.last_ch = ch_id;
        }
    }

    async fn get_uplink_channel(&self, conn_id: &str) -> Option<i32> {
        let conns = self.conns.read().await;
        conns.get(conn_id).and_then(|st| if st.uplink != 0 { Some(st.uplink) } else { None })
    }

    async fn register_and_broadcast_tcp(&self, conn_id: String, target: String, first: Option<Vec<u8>>, tcp_conn: TcpStream, req_type: String) {
        let mut conns = self.conns.write().await;
        let mut st = conns.entry(conn_id.clone()).or_insert(ClientConnState::new());
        st.tcp_conn = Some(Arc::new(Mutex::new(tcp_conn)));
        st.target = target.clone();
        st.start = Instant::now();
        st.req_type = req_type;
        st.uplink = 0;
        st.downlink = 0;
        drop(conns);

        let mut meta = vec![0u8]; // ip_strategy
        meta.extend_from_slice(target.as_bytes());
        let msg = encode_message(MessageType::TCPConnect, &conn_id, &meta, &first.unwrap_or_default());
        self.broadcast_write(Message::Binary(msg));
    }

    async fn register_udp(&self, conn_id: String, assoc: Arc<UDPAssociation>) {
        let mut conns = self.conns.write().await;
        let mut st = conns.entry(conn_id.clone()).or_insert(ClientConnState::new());
        st.udp_assoc = Some(assoc);
        st.req_type = "SOCKS5 UDP".to_string();
        drop(conns);
    }

    async fn start_udp_race(&self, conn_id: String, target: String) {
        let mut conns = self.conns.write().await;
        let mut st = conns.entry(conn_id.clone()).or_insert(ClientConnState::new());
        st.target = target.clone();
        st.start = Instant::now();
        st.req_type = "SOCKS5 UDP".to_string();
        st.uplink = 0;
        st.downlink = 0;
        drop(conns);

        let mut meta = vec![0u8]; // ip_strategy
        meta.extend_from_slice(target.as_bytes());
        let msg = encode_message(MessageType::UDPConnect, &conn_id, &meta, &[]);
        self.broadcast_write(Message::Binary(msg));
    }

    async fn unregister(&self, conn_id: &str) {
        let mut conns = self.conns.write().await;
        if let Some(mut st) = conns.remove(conn_id) {
            if st.closed {
                return;
            }
            st.closed = true;
            let target = st.target.clone();
            let up = if st.uplink != 0 { st.uplink } else { st.last_ch };
            let down = if st.downlink != 0 { st.downlink } else { st.last_ch };
            let u = if up > 0 { up.to_string() } else { "-".to_string() };
            let d = if down > 0 { down.to_string() } else { "-".to_string() };
            let client = st.client_addr.clone();
            let typ = if st.req_type.is_empty() { "SOCKS5".to_string() } else { st.req_type.clone() };
            let target = if target.is_empty() { "-".to_string() } else { target };
            info!("[client] {} {} access: {}, channel: TX {} RX {}, ID:{}, closed", client, typ, target, u, d, &conn_id[..8]);
            if let Some(ref tcp_conn) = st.tcp_conn {
                let mut conn = tcp_conn.lock().await;
                conn.shutdown().await.ok();
            }
            if let Some(ref udp_assoc) = st.udp_assoc {
                udp_assoc.close().await;
            }
        }
    }

    async fn select_downlink(&self, conn_id: &str, ch_id: i32) -> (bool, i32, Instant, String, i32, String) {
        let mut conns = self.conns.write().await;
        if let Some(st) = conns.get_mut(conn_id) {
            if st.target.is_empty() {
                return (false, 0, Instant::now(), String::new(), 0, String::new());
            }
            let chosen = if st.downlink != 0 {
                st.downlink
            } else {
                st.downlink = ch_id;
                ch_id
            };
            let selected = st.downlink == ch_id;
            let start = st.start;
            let target = st.target.clone();
            let uplink = st.uplink;
            let typ = st.req_type.clone();
            (selected, chosen, start, target, uplink, typ)
        } else {
            (false, 0, Instant::now(), String::new(), 0, String::new())
        }
    }

    async fn signal_connected(&self, id: &str) {
        let conns = self.conns.read().await;
        if let Some(st) = conns.get(id) {
            if let Some(tx) = &st.connected {
                tx.send(true).ok();
            }
        }
    }

    async fn send_data_direct(&self, ch_id: usize, conn_id: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = encode_message(MessageType::TCPData, conn_id, &[], data);
        self.async_write_direct(ch_id, Message::Binary(msg), data.len() as i64).await
    }

    async fn send_close_direct(&self, ch_id: usize, conn_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = encode_message(MessageType::TCPClose, conn_id, &[], &[]);
        self.async_write_direct(ch_id, Message::Binary(msg), 0).await
    }

    async fn send_udp_data_direct(&self, ch_id: usize, conn_id: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = encode_message(MessageType::UDPData, conn_id, &[], data);
        self.async_write_direct(ch_id, Message::Binary(msg), data.len() as i64).await
    }

    async fn send_udp_close_direct(&self, ch_id: usize, conn_id: &str) {
        let msg = encode_message(MessageType::UDPClose, conn_id, &[], &[]);
        self.async_write_direct(ch_id, Message::Binary(msg), 0).await.ok();
        self.unregister(conn_id).await;
    }

    async fn cleanup_channel(&self, ch_id: usize) {
        let mut to_close = Vec::new();
        {
            let conns = self.conns.read().await;
            for (id, st) in conns.iter() {
                if st.uplink == ch_id as i32 || st.downlink == ch_id as i32 {
                    to_close.push(id.clone());
                }
            }
        }
        for id in to_close {
            let conns = self.conns.read().await;
            if let Some(st) = conns.get(&id) {
                if let Some(ref tcp_conn) = st.tcp_conn {
                    let mut conn = tcp_conn.lock().await;
                    conn.shutdown().await.ok();
                }
                if let Some(ref udp_assoc) = st.udp_assoc {
                    udp_assoc.close().await;
                }
            }
            self.unregister(&id).await;
        }
    }
}

impl Clone for ECHPool {
    fn clone(&self) -> Self {
        Self {
            global_queue_bytes: AtomicI64::new(self.global_queue_bytes.load(Ordering::Relaxed)),
            global_queue_limit: self.global_queue_limit,
            next_channel: AtomicU64::new(self.next_channel.load(Ordering::Relaxed)),
            ws_server_addr: self.ws_server_addr.clone(),
            connection_num: self.connection_num,
            target_ips: self.target_ips.clone(),
            client_id: self.client_id.clone(),
            ws_conns: self.ws_conns.clone(),
            write_queues: self.write_queues.clone(),
            conns: self.conns.clone(),
        }
    }
}

struct UDPAssociation {
    conn_id: String,
    tcp_conn: TcpStream,
    udp_listener: TokioUdpSocket,
    client_udp_addr: Option<SocketAddr>,
    pool: ECHPool,
    closed: Mutex<bool>,
    receiving: Mutex<bool>,
    channel_id: Mutex<i32>,
    done: mpsc::UnboundedSender<()>,
}

impl UDPAssociation {
    fn new(conn_id: String, tcp_conn: TcpStream, udp_listener: TokioUdpSocket, pool: ECHPool) -> Arc<Self> {
        let (done_tx, _) = mpsc::unbounded_channel();
        Arc::new(Self {
            conn_id,
            tcp_conn,
            udp_listener,
            client_udp_addr: None,
            pool,
            closed: Mutex::new(false),
            receiving: Mutex::new(false),
            channel_id: Mutex::new(-1),
            done: done_tx,
        })
    }

    async fn loop_udp(self: Arc<Self>) {
        let mut buf = [0u8; 65536];
        loop {
            match self.udp_listener.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    let mut client_addr = self.client_udp_addr.lock().unwrap();
                    if client_addr.is_none() {
                        *client_addr = Some(addr);
                    } else if *client_addr != Some(addr) {
                        continue;
                    }
                    drop(client_addr);
                    if let Ok((tgt, data)) = parse_socks5_udp_packet(&buf[..n]) {
                        // check block ports
                        if let Ok((_, port_str)) = tgt.rsplit_once(':') {
                            if let Ok(port) = port_str.parse::<u16>() {
                                if udp_block_ports.contains(&port) {
                                    continue;
                                }
                            }
                        }
                        self.send(tgt, data).await;
                    }
                }
                Err(_) => {
                    self.done.send(()).ok();
                    return;
                }
            }
        }
    }

    async fn send(&self, target: String, data: Vec<u8>) {
        let mut closed = self.closed.lock().unwrap();
        if *closed {
            return;
        }
        let mut receiving = self.receiving.lock().unwrap();
        let need_start = !*receiving;
        if need_start {
            *receiving = true;
        }
        let ch_id = *self.channel_id.lock().unwrap();
        drop(receiving);
        drop(closed);

        if need_start {
            self.pool.start_udp_race(self.conn_id.clone(), target).await;
        }

        if ch_id < 0 {
            if let Some(id) = self.pool.get_uplink_channel(&self.conn_id).await {
                *self.channel_id.lock().unwrap() = id;
            } else {
                self.pool.broadcast_write(Message::Binary(encode_message(MessageType::UDPData, &self.conn_id, &[], &data))).await;
                return;
            }
        }
        self.pool.send_udp_data_direct(ch_id as usize, &self.conn_id, &data).await.ok();
    }

    async fn handle_udp_response(&self, addr_str: String, data: Vec<u8>) {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            if let Some(client_addr) = self.client_udp_addr {
                let pkt = build_socks5_udp_packet(&addr, &data);
                self.udp_listener.send_to(&pkt, client_addr).await.ok();
            }
        }
    }

    async fn close(&self) {
        let mut closed = self.closed.lock().unwrap();
        if *closed {
            return;
        }
        *closed = true;
        let receiving = *self.receiving.lock().unwrap();
        let ch_id = *self.channel_id.lock().unwrap();
        drop(closed);

        if receiving {
            if ch_id >= 0 {
                self.pool.send_udp_close_direct(ch_id as usize, &self.conn_id).await;
            } else {
                self.pool.broadcast_write(Message::Binary(encode_message(MessageType::UDPClose, &self.conn_id, &[], &[]))).await;
                self.pool.unregister(&self.conn_id).await;
            }
        } else {
            self.pool.unregister(&self.conn_id).await;
        }
        self.udp_listener.shutdown().await.ok();
    }
}

fn parse_socks5_udp_packet(data: &[u8]) -> Result<(String, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    if data.len() < 10 || data[2] != 0 {
        return Err("invalid data".into());
    }
    let mut off = 4;
    let host = match data[3] {
        1 => {
            if off + 4 > data.len() {
                return Err("ipv4 too short".into());
            }
            let ip = Ipv4Addr::from([data[off], data[off+1], data[off+2], data[off+3]]);
            off += 4;
            ip.to_string()
        }
        3 => {
            if off + 1 > data.len() {
                return Err("domain length missing".into());
            }
            let len = data[off] as usize;
            off += 1;
            if off + len > data.len() {
                return Err("domain too short".into());
            }
            let h = String::from_utf8_lossy(&data[off..off + len]).to_string();
            off += len;
            h
        }
        4 => {
            if off + 16 > data.len() {
                return Err("ipv6 too short".into());
            }
            let ip = Ipv6Addr::from([
                ((data[off] as u16) << 8) | data[off+1] as u16,
                ((data[off+2] as u16) << 8) | data[off+3] as u16,
                ((data[off+4] as u16) << 8) | data[off+5] as u16,
                ((data[off+6] as u16) << 8) | data[off+7] as u16,
                ((data[off+8] as u16) << 8) | data[off+9] as u16,
                ((data[off+10] as u16) << 8) | data[off+11] as u16,
                ((data[off+12] as u16) << 8) | data[off+13] as u16,
                ((data[off+14] as u16) << 8) | data[off+15] as u16,
            ]);
            off += 16;
            ip.to_string()
        }
        _ => return Err("invalid address type".into()),
    };
    if off + 2 > data.len() {
        return Err("port too short".into());
    }
    let port = ((data[off] as u16) << 8) | data[off + 1] as u16;
    off += 2;
    let target = format!("{}:{}", host, port);
    Ok((target, data[off..].to_vec()))
}

fn build_socks5_udp_packet(addr: &SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0, 0, 0];
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(1);
            buf.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            buf.push(4);
            for seg in &v6.ip().segments() {
                buf.extend_from_slice(&seg.to_be_bytes());
            }
        }
    }
    buf.extend_from_slice(&(addr.port()).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

async fn dial_websocket_with_ech(addr: &str, retries: usize, ip: &str, client_id: &str) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut url = Url::parse(addr)?;
    if url.scheme() != "wss" {
        return Err("only wss supported".into());
    }
    let mut query = url.query_pairs_mut();
    if !client_id.is_empty() {
        query.append_pair("client_id", client_id);
    }
    drop(query);
    let request = Request::get(url.as_str()).body(())?;
    // For simplicity, use default TLS config, no ECH since not supported
    let (ws, _) = connect_async(request).await?;
    Ok(ws)
}

async fn run_socks5_listener(addr: &str, pool: Arc<ECHPool>) {
    let listener = TcpListener::bind(addr).await?;
    info!("[client] SOCKS5 proxy: {}", addr);
    loop {
        let (socket, _) = listener.accept().await?;
        let pool = pool.clone();
        tokio::spawn(async move {
            handle_socks5(socket, pool).await;
        });
    }
}

async fn handle_socks5(mut socket: TcpStream, pool: Arc<ECHPool>) {
    let mut buf = [0u8; 2];
    if socket.read_exact(&mut buf).await.is_err() || buf[0] != 0x05 {
        return;
    }
    let methods = vec![0u8; buf[1] as usize];
    if socket.read_exact(&methods).await.is_err() {
        return;
    }
    // Assume no auth for simplicity
    socket.write_all(&[0x05, 0x00]).await.ok();

    let mut head = [0u8; 4];
    if socket.read_exact(&mut head).await.is_err() {
        return;
    }
    let mut target = String::new();
    match head[3] {
        1 => {
            let mut b = [0u8; 4];
            socket.read_exact(&mut b).await.ok();
            target = IpAddr::V4(Ipv4Addr::from(b)).to_string();
        }
        3 => {
            let mut b = [0u8; 1];
            socket.read_exact(&mut b).await.ok();
            let mut addr = vec![0u8; b[0] as usize];
            socket.read_exact(&mut addr).await.ok();
            target = String::from_utf8_lossy(&addr).to_string();
        }
        4 => {
            let mut b = [0u8; 16];
            socket.read_exact(&mut b).await.ok();
            target = IpAddr::V6(Ipv6Addr::from(b)).to_string();
        }
        _ => return,
    }
    let mut pb = [0u8; 2];
    socket.read_exact(&mut pb).await.ok();
    let port = ((pb[0] as u16) << 8) | pb[1] as u16;
    target = format!("{}:{}", target, port);

    socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.ok();

    match head[1] {
        1 => handle_socks5_connect(socket, target, pool).await,
        3 => handle_socks5_udp(socket, pool).await,
        _ => {}
    }
}

async fn handle_socks5_connect(mut socket: TcpStream, target: String, pool: Arc<ECHPool>) {
    let conn_id = Uuid::new_v4().to_string();
    pool.register_and_broadcast_tcp(conn_id.clone(), target, None, socket, "SOCKS5".to_string()).await;

    let mut buf = [0u8; 65536];
    loop {
        match socket.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if let Some(ch_id) = pool.get_uplink_channel(&conn_id).await {
                    pool.send_data_direct(ch_id as usize, &conn_id, &buf[..n]).await.ok();
                } else {
                    let msg = encode_message(MessageType::TCPData, &conn_id, &[], &buf[..n]);
                    pool.broadcast_write(Message::Binary(msg)).await;
                }
            }
            Err(_) => break,
        }
    }
    if let Some(ch_id) = pool.get_uplink_channel(&conn_id).await {
        pool.send_close_direct(ch_id as usize, &conn_id).await.ok();
    } else {
        let msg = encode_message(MessageType::TCPClose, &conn_id, &[], &[]);
        pool.broadcast_write(Message::Binary(msg)).await;
    }
    pool.unregister(&conn_id).await;
}

async fn handle_socks5_udp(mut socket: TcpStream, pool: Arc<ECHPool>) {
    let addr = socket.local_addr().unwrap();
    let udp_socket = TokioUdpSocket::bind("0.0.0.0:0").await.unwrap();
    let actual = udp_socket.local_addr().unwrap();
    let mut resp = vec![0x05, 0x00, 0x00];
    match actual {
        SocketAddr::V4(v4) => {
            resp.push(1);
            resp.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            resp.push(4);
            for seg in &v6.ip().segments() {
                resp.extend_from_slice(&seg.to_be_bytes());
            }
        }
    }
    resp.extend_from_slice(&(actual.port()).to_be_bytes());
    socket.write_all(&resp).await.ok();

    let conn_id = Uuid::new_v4().to_string();
    let assoc = UDPAssociation::new(conn_id.clone(), socket, udp_socket, (*pool).clone());
    pool.register_udp(conn_id, assoc.clone()).await;
    assoc.loop_udp().await;
}

lazy_static::lazy_static! {
    static ref UDP_BLOCK_PORTS: HashSet<u16> = {
        let mut set = HashSet::new();
        for port in "443".split(',') {
            if let Ok(p) = port.trim().parse::<u16>() {
                set.insert(p);
            }
        }
        set
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    let args = Args::parse();

    let mut cfg = GlobalConfig::default();
    let mut listen_addr = args.listen;
    let mut forward_addr = args.forward;
    let mut ip_addr = args.ip;
    let mut udp_block_ports_str = args.block;
    let mut token = args.token;
    let mut connection_num = args.connection_num;
    let mut insecure = args.insecure;
    let mut ips = args.ips;
    let mut dns_server = args.dns;
    let mut ech_domain = args.ech;
    let mut fallback = args.fallback;

    if let Some(config_file) = args.config {
        let data = tokio::fs::read_to_string(&config_file).await?;
        let file_config: FileConfig = serde_yaml::from_str(&data)?;
        // Apply config similar to Go code
        if listen_addr.is_none() && file_config.listen.is_some() {
            listen_addr = file_config.listen;
        }
        // Similarly for others
    }

    let listen_addr = listen_addr.ok_or("listen addr required")?;
    let forward_addr = forward_addr.ok_or("forward addr required")?;

    let ip_strategy = parse_ip_strategy(&ips.unwrap_or_default());
    if !ips.unwrap_or_default().is_empty() {
        info!("[client] IP strategy: {} (code: {})", ips.unwrap_or_default(), ip_strategy as u8);
    }

    let target_ips = if let Some(ip) = ip_addr {
        ip.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        vec![]
    };

    let url = Url::parse(&forward_addr)?;
    if url.scheme() != "wss" {
        return Err("only wss supported".into());
    }

    if insecure && !fallback {
        fallback = true;
        info!("[client] insecure mode: ECH disabled");
    }

    // ECH not implemented, use fallback
    if !fallback {
        warn!("ECH not supported in this Rust version, using fallback");
        fallback = true;
    }

    let client_id = Uuid::new_v4().to_string();
    info!("[client] client ID: {}", client_id);

    let pool = Arc::new(ECHPool::new(forward_addr, connection_num, target_ips, client_id));
    pool.start().await;

    run_socks5_listener(&listen_addr, pool).await;

    Ok(())
}

fn parse_ip_strategy(s: &str) -> IpStrategy {
    let s = s.trim();
    match s {
        "4" => IpStrategy::IPv4Only,
        "6" => IpStrategy::IPv6Only,
        "4,6" => IpStrategy::IPv4IPv6,
        "6,4" => IpStrategy::IPv6IPv4,
        _ => IpStrategy::Default,
    }
}