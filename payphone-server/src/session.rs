use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn::Connection;
use rand::RngCore;
use tokio::sync::mpsc;

use payphone_auth::{CLIENT_ID_SIZE, SubscriptionClaims, SubscriptionPlan, TOKEN_ID_SIZE};

use payphone_core::{
    all_good_dude::{AllGoodDude, SERVER_NONCE_SIZE, SESSION_ID_SIZE},
    still_good_dude::StillGoodDude,
};

pub type SessionId = [u8; SESSION_ID_SIZE];

pub const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

pub const REKEY_AFTER: Duration = Duration::from_secs(3600);

/// Drop frames this far behind the highest sequence seen.
/// Datagrams reorder; `seq <= last` would kill honest DATA.
pub const SEQUENCE_REORDER_WINDOW: u64 = 1024;

pub fn accept_sequence(last: &AtomicU64, incoming: u64) -> bool {
    let seen = last.fetch_max(incoming, Ordering::Relaxed);

    incoming >= seen || seen - incoming < SEQUENCE_REORDER_WINDOW
}

const STORE_MAGIC: &[u8; 4] = b"PAYS";

const STORE_VERSION: u8 = 1;

const STORE_RECORD_SIZE: usize = 206;

const UNLIMITED_DEVICES: u8 = 255;

#[derive(Clone, Debug)]
pub enum ClientLink {
    Quic(Connection),

    Stream { id: u64, tx: mpsc::Sender<Bytes> },

    Detached,
}

impl ClientLink {
    pub async fn send(&self, bytes: Bytes) {
        match self {
            Self::Quic(connection) => {
                let _ = payphone_transport::send_vpn_datagram(connection, bytes);
            }

            Self::Stream { tx, .. } => {
                let _ = tx.send(bytes).await;
            }

            Self::Detached => {}
        }
    }

    pub fn is_live(&self) -> bool {
        !matches!(self, Self::Detached)
    }

    fn matches_quic_stable_id(&self, stable_id: usize) -> bool {
        match self {
            Self::Quic(connection) => connection.stable_id() == stable_id,
            Self::Stream { .. } | Self::Detached => false,
        }
    }

    fn matches_stream_id(&self, stream_id: u64) -> bool {
        match self {
            Self::Stream { id, .. } => *id == stream_id,
            Self::Quic(_) | Self::Detached => false,
        }
    }
}

/// Token-bucket limiter. `max_mbps == 0` means no cap (Unlimited).
#[derive(Debug)]
pub struct RateLimit {
    max_mbps: u32,

    tokens: AtomicU64,

    last_refill_ms: AtomicU64,
}

impl RateLimit {
    pub fn new(max_mbps: u32) -> Self {
        let burst = burst_bytes(max_mbps);

        Self {
            max_mbps,
            tokens: AtomicU64::new(burst),
            last_refill_ms: AtomicU64::new(unix_ms()),
        }
    }

    pub fn allow(&self, bytes: u64) -> bool {
        if self.max_mbps == 0 || bytes == 0 {
            return true;
        }

        self.refill();

        loop {
            let current = self.tokens.load(Ordering::Relaxed);

            if current < bytes {
                return false;
            }

            if self
                .tokens
                .compare_exchange_weak(
                    current,
                    current - bytes,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    fn refill(&self) {
        let now = unix_ms();

        let last = self.last_refill_ms.load(Ordering::Relaxed);

        if now <= last {
            return;
        }

        let rate = bytes_per_sec(self.max_mbps);

        let added = rate.saturating_mul(now - last) / 1000;

        if added == 0 {
            return;
        }

        if self
            .last_refill_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let cap = burst_bytes(self.max_mbps);

        loop {
            let current = self.tokens.load(Ordering::Relaxed);

            let next = current.saturating_add(added).min(cap);

            if self
                .tokens
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }
}

fn bytes_per_sec(max_mbps: u32) -> u64 {
    u64::from(max_mbps).saturating_mul(125_000)
}

fn burst_bytes(max_mbps: u32) -> u64 {
    bytes_per_sec(max_mbps).max(65_536)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug)]
pub struct Session {
    pub id: SessionId,

    pub ipv4: [u8; 4],

    pub client_address: SocketAddr,

    pub link: ClientLink,

    pub capabilities: u32,

    pub last_sequence: AtomicU64,

    #[allow(dead_code)]
    pub created_at: Instant,

    pub last_activity: Instant,

    pub last_rekey: Instant,

    pub client_nonce: [u8; 32],

    pub server_nonce: [u8; 32],

    pub prev_nonce: Option<[u8; SERVER_NONCE_SIZE]>,

    pub pending_nonce: Option<[u8; SERVER_NONCE_SIZE]>,

    pub client_id: [u8; CLIENT_ID_SIZE],

    pub token_id: [u8; TOKEN_ID_SIZE],

    pub subscription_expires_at: u64,

    pub plan: SubscriptionPlan,

    pub device_limit: u8,

    pub max_mbps: u32,

    pub rate: RateLimit,
}

#[derive(Debug)]
pub struct KickedSession {
    pub id: SessionId,

    pub link: ClientLink,
}

#[derive(Debug)]
pub enum CreateSessionError {
    NoAddresses,
}

pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,

    store_path: Option<PathBuf>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            store_path: None,
        }
    }

    pub fn with_store(path: PathBuf) -> Self {
        let mut manager = match fs::read(&path) {
            Ok(bytes) => match Self::decode_store(&bytes) {
                Ok(loaded) => loaded,

                Err(error) => {
                    eprintln!(
                        "PAYPHONE sessions: ignoring corrupt store {}: {error}",
                        path.display()
                    );

                    Self::new()
                }
            },

            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::new(),

            Err(error) => {
                eprintln!("PAYPHONE sessions: cannot read {}: {error}", path.display());

                Self::new()
            }
        };

        let loaded = manager.len();

        manager.store_path = Some(path.clone());

        if loaded > 0 {
            println!("PAYPHONE sessions: loaded {loaded} from {}", path.display());
        }

        manager
    }

    pub fn create_session(
        &mut self,
        client_address: SocketAddr,
        link: ClientLink,
        capabilities: u32,
        client_nonce: [u8; 32],
        last_sequence: u64,
        mtu: u16,
        subscription: &SubscriptionClaims,
    ) -> Result<(AllGoodDude, Vec<KickedSession>), CreateSessionError> {
        let kicked = self.enforce_device_limit(subscription);

        let assigned_ipv4 = self
            .allocate_ipv4()
            .ok_or(CreateSessionError::NoAddresses)?;

        let response = AllGoodDude::new(assigned_ipv4, mtu, capabilities);

        let now = Instant::now();

        let session = Session {
            id: response.session_id,
            ipv4: assigned_ipv4,
            client_address,
            link,
            capabilities,
            last_sequence: AtomicU64::new(last_sequence),
            created_at: now,
            last_activity: now,
            last_rekey: now,
            client_nonce,
            server_nonce: response.server_nonce,
            prev_nonce: None,
            pending_nonce: None,
            client_id: subscription.client_id,
            token_id: subscription.token_id,
            subscription_expires_at: subscription.expires_at,
            plan: subscription.plan,
            device_limit: subscription.device_limit,
            max_mbps: subscription.max_mbps,
            rate: RateLimit::new(subscription.max_mbps),
        };

        self.sessions.insert(session.id, session);

        self.persist();

        Ok((response, kicked))
    }

    pub fn resume_session(
        &mut self,
        session_id: &SessionId,
        resume_token: &[u8; 32],
        new_client_address: SocketAddr,
        new_link: ClientLink,
        sequence: u64,
        mtu: u16,
    ) -> Option<StillGoodDude> {
        let session = self.sessions.get_mut(session_id)?;

        let matches_current = &session.server_nonce == resume_token;

        let matches_prev = session.prev_nonce.as_ref() == Some(resume_token);

        let matches_pending = session.pending_nonce.as_ref() == Some(resume_token);

        if !matches_current && !matches_prev && !matches_pending {
            return None;
        }

        if matches_pending {
            session.prev_nonce = Some(session.server_nonce);

            session.server_nonce = *resume_token;

            session.pending_nonce = None;
        } else if matches_current {
            session.prev_nonce = None;

            session.pending_nonce = None;
        }

        session.client_address = new_client_address;

        session.link = new_link;

        session.last_sequence.store(sequence, Ordering::Relaxed);

        session.last_activity = Instant::now();

        let still_good = StillGoodDude::new(session.id, session.ipv4, mtu, session.capabilities);

        self.persist();

        Some(still_good)
    }

    pub fn rekey_offer(
        &mut self,
        session_id: &SessionId,
        client_address: SocketAddr,
    ) -> Option<[u8; SERVER_NONCE_SIZE]> {
        let (pending, dirty) = {
            let session = self.sessions.get_mut(session_id)?;

            if session.client_address != client_address {
                return None;
            }

            let dirty = session.pending_nonce.is_none();

            if dirty {
                session.pending_nonce = Some(random_nonce());
            }

            (session.pending_nonce, dirty)
        };

        if dirty {
            self.persist();
        }

        pending
    }

    pub fn rekey_confirm(
        &mut self,
        session_id: &SessionId,
        nonce: &[u8; SERVER_NONCE_SIZE],
        client_address: SocketAddr,
    ) -> Option<[u8; SERVER_NONCE_SIZE]> {
        let (current, dirty) = {
            let session = self.sessions.get_mut(session_id)?;

            if session.client_address != client_address {
                return None;
            }

            let dirty = session.pending_nonce.as_ref() == Some(nonce);

            if dirty {
                session.prev_nonce = Some(session.server_nonce);

                session.server_nonce = *nonce;

                session.pending_nonce = None;

                session.last_rekey = Instant::now();
            }

            (session.server_nonce, dirty)
        };

        if dirty {
            self.persist();
        }

        Some(current)
    }

    pub fn touch_session(
        &mut self,
        session_id: &SessionId,
        client_address: SocketAddr,
        sequence: u64,
    ) -> Option<Option<[u8; SERVER_NONCE_SIZE]>> {
        let (offer, dirty) = {
            let session = self.sessions.get_mut(session_id)?;

            if session.client_address != client_address {
                return None;
            }

            if !accept_sequence(&session.last_sequence, sequence) {
                return None;
            }

            session.last_activity = Instant::now();

            if session.pending_nonce.is_some() {
                (session.pending_nonce, false)
            } else if session.last_rekey.elapsed() >= REKEY_AFTER {
                session.pending_nonce = Some(random_nonce());

                (session.pending_nonce, true)
            } else {
                (None, false)
            }
        };

        if dirty {
            self.persist();
        }

        Some(offer)
    }

    pub fn get(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    pub fn remove(&mut self, id: &SessionId) -> Option<Session> {
        let session = self.sessions.remove(id);

        if session.is_some() {
            self.persist();
        }

        session
    }

    pub fn detach_by_stable_id(&mut self, stable_id: usize) -> usize {
        let mut detached = 0;

        for session in self.sessions.values_mut() {
            if session.link.matches_quic_stable_id(stable_id) {
                session.link = ClientLink::Detached;

                detached += 1;
            }
        }

        detached
    }

    pub fn detach_by_stream_id(&mut self, stream_id: u64) -> usize {
        let mut detached = 0;

        for session in self.sessions.values_mut() {
            if session.link.matches_stream_id(stream_id) {
                session.link = ClientLink::Detached;

                detached += 1;
            }
        }

        detached
    }

    pub fn find_by_ipv4(&self, ipv4: [u8; 4]) -> Option<&Session> {
        self.sessions
            .values()
            .find(|session| session.ipv4 == ipv4 && session.link.is_live())
    }

    pub fn remove_expired(&mut self) -> usize {
        let now = Instant::now();

        let before = self.sessions.len();

        self.sessions
            .retain(|_id, session| now.duration_since(session.last_activity) < SESSION_TIMEOUT);

        let removed = before - self.sessions.len();

        if removed > 0 {
            self.persist();
        }

        removed
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    fn enforce_device_limit(&mut self, subscription: &SubscriptionClaims) -> Vec<KickedSession> {
        if subscription.device_limit == UNLIMITED_DEVICES {
            return Vec::new();
        }

        let limit = usize::from(subscription.device_limit.max(1));

        let mut kicked = Vec::new();

        while self.client_session_count(&subscription.client_id) >= limit {
            match self.kick_oldest(&subscription.client_id) {
                Some(session) => kicked.push(session),

                None => break,
            }
        }

        kicked
    }

    fn client_session_count(&self, client_id: &[u8; CLIENT_ID_SIZE]) -> usize {
        self.sessions
            .values()
            .filter(|session| session.client_id == *client_id)
            .count()
    }

    fn kick_oldest(&mut self, client_id: &[u8; CLIENT_ID_SIZE]) -> Option<KickedSession> {
        let mut detached: Option<(Instant, SessionId)> = None;

        let mut live: Option<(Instant, SessionId)> = None;

        for session in self.sessions.values() {
            if session.client_id != *client_id {
                continue;
            }

            if !session.link.is_live() {
                replace_older(&mut detached, session.last_activity, session.id);
            } else {
                replace_older(&mut live, session.last_activity, session.id);
            }
        }

        let id = detached.or(live)?.1;

        let session = self.sessions.remove(&id)?;

        Some(KickedSession {
            id: session.id,
            link: session.link,
        })
    }

    fn allocate_ipv4(&self) -> Option<[u8; 4]> {
        let mut used = [false; 256];

        for session in self.sessions.values() {
            used[session.ipv4[3] as usize] = true;
        }

        (2u8..=254)
            .find(|&host| !used[host as usize])
            .map(|host| [10, 77, 0, host])
    }

    fn persist(&self) {
        let Some(path) = &self.store_path else {
            return;
        };

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }

        let bytes = self.encode_store();

        let tmp = tmp_path(path);

        if fs::write(&tmp, &bytes).is_ok() {
            let _ = fs::rename(&tmp, path);
        }
    }

    fn encode_store(&self) -> Bytes {
        let mut buffer = BytesMut::with_capacity(9 + self.sessions.len() * STORE_RECORD_SIZE);

        buffer.extend_from_slice(STORE_MAGIC);

        buffer.put_u8(STORE_VERSION);

        buffer.put_u32(self.sessions.len() as u32);

        for session in self.sessions.values() {
            buffer.extend_from_slice(&session.id);

            buffer.extend_from_slice(&session.ipv4);

            buffer.put_u32(session.capabilities);

            buffer.put_u64(session.last_sequence.load(Ordering::Relaxed));

            buffer.extend_from_slice(&session.client_nonce);

            buffer.extend_from_slice(&session.server_nonce);

            buffer.extend_from_slice(&optional_nonce_bytes(session.prev_nonce));

            buffer.extend_from_slice(&optional_nonce_bytes(session.pending_nonce));

            buffer.extend_from_slice(&session.client_id);

            buffer.extend_from_slice(&session.token_id);

            buffer.put_u64(session.subscription_expires_at);

            buffer.put_u8(session.plan as u8);

            buffer.put_u8(session.device_limit);

            buffer.put_u32(session.max_mbps);
        }

        buffer.freeze()
    }

    fn decode_store(mut buffer: &[u8]) -> Result<Self, &'static str> {
        if buffer.len() < 9 {
            return Err("store too short");
        }

        let mut magic = [0u8; 4];

        buffer.copy_to_slice(&mut magic);

        if &magic != STORE_MAGIC {
            return Err("bad magic");
        }

        let version = buffer.get_u8();

        if version != STORE_VERSION {
            return Err("unsupported store version");
        }

        let count = buffer.get_u32() as usize;

        if buffer.len() != count * STORE_RECORD_SIZE {
            return Err("truncated store");
        }

        let mut sessions = HashMap::with_capacity(count);

        let now = Instant::now();

        for _ in 0..count {
            let mut id = [0u8; SESSION_ID_SIZE];

            buffer.copy_to_slice(&mut id);

            let mut ipv4 = [0u8; 4];

            buffer.copy_to_slice(&mut ipv4);

            let capabilities = buffer.get_u32();

            let last_sequence = buffer.get_u64();

            let mut client_nonce = [0u8; 32];

            buffer.copy_to_slice(&mut client_nonce);

            let mut server_nonce = [0u8; SERVER_NONCE_SIZE];

            buffer.copy_to_slice(&mut server_nonce);

            let mut prev = [0u8; SERVER_NONCE_SIZE];

            buffer.copy_to_slice(&mut prev);

            let mut pending = [0u8; SERVER_NONCE_SIZE];

            buffer.copy_to_slice(&mut pending);

            let mut client_id = [0u8; CLIENT_ID_SIZE];

            buffer.copy_to_slice(&mut client_id);

            let mut token_id = [0u8; TOKEN_ID_SIZE];

            buffer.copy_to_slice(&mut token_id);

            let subscription_expires_at = buffer.get_u64();

            let plan = SubscriptionPlan::try_from(buffer.get_u8()).map_err(|_| "bad plan")?;

            let device_limit = buffer.get_u8();

            let max_mbps = buffer.get_u32();

            sessions.insert(
                id,
                Session {
                    id,
                    ipv4,
                    client_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    link: ClientLink::Detached,
                    capabilities,
                    last_sequence: AtomicU64::new(last_sequence),
                    created_at: now,
                    last_activity: now,
                    last_rekey: now,
                    client_nonce,
                    server_nonce,
                    prev_nonce: nonce_from_bytes(prev),
                    pending_nonce: nonce_from_bytes(pending),
                    client_id,
                    token_id,
                    subscription_expires_at,
                    plan,
                    device_limit,
                    max_mbps,
                    rate: RateLimit::new(max_mbps),
                },
            );
        }

        Ok(Self {
            sessions,
            store_path: None,
        })
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

fn replace_older(slot: &mut Option<(Instant, SessionId)>, activity: Instant, id: SessionId) {
    match slot {
        Some((oldest, _)) if activity >= *oldest => {}

        _ => *slot = Some((activity, id)),
    }
}

fn random_nonce() -> [u8; SERVER_NONCE_SIZE] {
    let mut nonce = [0u8; SERVER_NONCE_SIZE];

    rand::rng().fill_bytes(&mut nonce);

    nonce
}

fn optional_nonce_bytes(nonce: Option<[u8; SERVER_NONCE_SIZE]>) -> [u8; SERVER_NONCE_SIZE] {
    nonce.unwrap_or([0u8; SERVER_NONCE_SIZE])
}

fn nonce_from_bytes(nonce: [u8; SERVER_NONCE_SIZE]) -> Option<[u8; SERVER_NONCE_SIZE]> {
    if nonce.iter().all(|&byte| byte == 0) {
        None
    } else {
        Some(nonce)
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();

    tmp.push(".tmp");

    PathBuf::from(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(client_id: u8, device_limit: u8, max_mbps: u32) -> SubscriptionClaims {
        SubscriptionClaims {
            key_id: 1,
            token_id: [client_id; TOKEN_ID_SIZE],
            client_id: [client_id; CLIENT_ID_SIZE],
            issued_at: 1_000,
            not_before: 1_000,
            expires_at: 9_999_999_999,
            plan: SubscriptionPlan::Basic,
            device_limit,
            max_mbps,
        }
    }

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    #[test]
    fn allocates_distinct_vpn_addresses() {
        let mut manager = SessionManager::new();

        let first = manager
            .create_session(
                dummy_addr(),
                ClientLink::Detached,
                1,
                [1u8; 32],
                0,
                1280,
                &claims(1, 5, 0),
            )
            .unwrap()
            .0;

        let second = manager
            .create_session(
                dummy_addr(),
                ClientLink::Detached,
                1,
                [2u8; 32],
                0,
                1280,
                &claims(2, 5, 0),
            )
            .unwrap()
            .0;

        assert_eq!(first.assigned_ipv4, [10, 77, 0, 2]);

        assert_eq!(second.assigned_ipv4, [10, 77, 0, 3]);
    }

    #[test]
    fn device_limit_kicks_oldest() {
        let mut manager = SessionManager::new();

        let one = claims(7, 1, 100);

        let first = manager
            .create_session(
                dummy_addr(),
                ClientLink::Detached,
                1,
                [1u8; 32],
                0,
                1280,
                &one,
            )
            .unwrap()
            .0;

        let (second, kicked) = manager
            .create_session(
                dummy_addr(),
                ClientLink::Detached,
                1,
                [2u8; 32],
                0,
                1280,
                &one,
            )
            .unwrap();

        assert_eq!(kicked.len(), 1);

        assert_eq!(kicked[0].id, first.session_id);

        assert_eq!(manager.len(), 1);

        assert_eq!(
            manager.get(&second.session_id).unwrap().ipv4,
            second.assigned_ipv4
        );
    }

    #[test]
    fn resume_accepts_pending_nonce() {
        let mut manager = SessionManager::new();

        let all_good = manager
            .create_session(
                dummy_addr(),
                ClientLink::Detached,
                1,
                [1u8; 32],
                0,
                1280,
                &claims(1, 5, 0),
            )
            .unwrap()
            .0;

        let pending = manager
            .rekey_offer(&all_good.session_id, dummy_addr())
            .unwrap();

        let resumed = manager
            .resume_session(
                &all_good.session_id,
                &pending,
                dummy_addr(),
                ClientLink::Detached,
                2,
                1280,
            )
            .unwrap();

        assert_eq!(resumed.assigned_ipv4, all_good.assigned_ipv4);
    }

    #[test]
    fn persist_roundtrip_keeps_resume_token() {
        let dir = std::env::temp_dir().join(format!(
            "payphone-sess-{}-{}",
            std::process::id(),
            unix_ms()
        ));

        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("sessions.bin");

        let session_id;

        let nonce;

        let ipv4;

        {
            let mut manager = SessionManager::with_store(path.clone());

            let all_good = manager
                .create_session(
                    dummy_addr(),
                    ClientLink::Detached,
                    7,
                    [9u8; 32],
                    4,
                    1280,
                    &claims(3, 2, 50),
                )
                .unwrap()
                .0;

            session_id = all_good.session_id;

            nonce = all_good.server_nonce;

            ipv4 = all_good.assigned_ipv4;
        }

        let mut loaded = SessionManager::with_store(path.clone());

        assert_eq!(loaded.len(), 1);

        let resumed = loaded
            .resume_session(
                &session_id,
                &nonce,
                dummy_addr(),
                ClientLink::Detached,
                5,
                1280,
            )
            .unwrap();

        assert_eq!(resumed.assigned_ipv4, ipv4);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rate_limit_blocks_after_burst() {
        let limit = RateLimit::new(1);

        assert!(limit.allow(125_000));

        assert!(!limit.allow(1));
    }

    #[test]
    fn unlimited_rate_never_blocks() {
        let limit = RateLimit::new(0);

        assert!(limit.allow(1_000_000_000));
    }

    #[test]
    fn accept_sequence_allows_reorder_but_drops_old_replays() {
        let last = AtomicU64::new(0);

        assert!(accept_sequence(&last, 2000));
        assert_eq!(last.load(Ordering::Relaxed), 2000);
        assert!(accept_sequence(&last, 1990));
        assert_eq!(last.load(Ordering::Relaxed), 2000);
        assert!(accept_sequence(&last, 2000 - SEQUENCE_REORDER_WINDOW + 1));
        assert!(!accept_sequence(&last, 2000 - SEQUENCE_REORDER_WINDOW));
    }
}
