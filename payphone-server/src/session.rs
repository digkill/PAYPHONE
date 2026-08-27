use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use quinn::Connection;

use payphone_auth::{CLIENT_ID_SIZE, SubscriptionClaims, SubscriptionPlan, TOKEN_ID_SIZE};

use payphone_core::{
    all_good_dude::{AllGoodDude, SESSION_ID_SIZE},
    still_good_dude::StillGoodDude,
};

pub type SessionId = [u8; SESSION_ID_SIZE];

pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct Session {
    pub id: SessionId,

    pub ipv4: [u8; 4],

    pub client_address: SocketAddr,

    //
    // Текущее QUIC connection
    // для этой логической Session.
    //
    pub connection: Connection,

    pub capabilities: u32,

    pub last_sequence: u64,

    pub created_at: Instant,

    pub last_activity: Instant,

    pub client_nonce: [u8; 32],

    pub server_nonce: [u8; 32],

    pub client_id: [u8; CLIENT_ID_SIZE],

    pub token_id: [u8; TOKEN_ID_SIZE],

    pub subscription_expires_at: u64,

    pub plan: SubscriptionPlan,
}

pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,

    next_ipv4_host: u8,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),

            next_ipv4_host: 2,
        }
    }

    pub fn create_session(
        &mut self,

        client_address: SocketAddr,

        connection: Connection,

        capabilities: u32,

        client_nonce: [u8; 32],

        last_sequence: u64,

        mtu: u16,

        subscription: &SubscriptionClaims,
    ) -> AllGoodDude {
        let assigned_ipv4 = [10, 77, 0, self.next_ipv4_host];

        self.next_ipv4_host = self.next_ipv4_host.wrapping_add(1);

        if self.next_ipv4_host < 2 {
            self.next_ipv4_host = 2;
        }

        let response = AllGoodDude::new(assigned_ipv4, mtu, capabilities);

        let now = Instant::now();

        let session = Session {
            id: response.session_id,

            ipv4: assigned_ipv4,

            client_address,

            connection,

            capabilities,

            last_sequence,

            created_at: now,

            last_activity: now,

            client_nonce,

            server_nonce: response.server_nonce,

            client_id: subscription.client_id,

            token_id: subscription.token_id,

            subscription_expires_at: subscription.expires_at,

            plan: subscription.plan,
        };

        self.sessions.insert(session.id, session);

        response
    }

    pub fn resume_session(
        &mut self,

        session_id: &SessionId,

        resume_token: &[u8; 32],

        new_client_address: SocketAddr,

        new_connection: Connection,

        sequence: u64,

        mtu: u16,
    ) -> Option<StillGoodDude> {
        let session = self.sessions.get_mut(session_id)?;

        if &session.server_nonce != resume_token {
            return None;
        }

        session.client_address = new_client_address;

        //
        // Главное для QUIC resume.
        //
        session.connection = new_connection;

        session.last_sequence = sequence;

        session.last_activity = Instant::now();

        Some(StillGoodDude::new(
            session.id,
            session.ipv4,
            mtu,
            session.capabilities,
        ))
    }

    pub fn get(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    pub fn get_mut(&mut self, id: &SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    pub fn remove(&mut self, id: &SessionId) -> Option<Session> {
        self.sessions.remove(id)
    }

    /// Находит Session
    /// по внутреннему VPN IPv4.
    ///
    /// Нужен для:
    ///
    /// Linux TUN
    ///     ↓
    /// destination 10.77.0.2
    ///     ↓
    /// Session
    ///     ↓
    /// QUIC Connection
    pub fn find_by_ipv4(&self, ipv4: [u8; 4]) -> Option<&Session> {
        self.sessions.values().find(|session| session.ipv4 == ipv4)
    }

    pub fn remove_expired(&mut self) -> usize {
        let now = Instant::now();

        let before = self.sessions.len();

        self.sessions
            .retain(|_id, session| now.duration_since(session.last_activity) < SESSION_TIMEOUT);

        before - self.sessions.len()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
