use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use payphone_core::{
    all_good_dude::{AllGoodDude, SESSION_ID_SIZE},
    still_good_dude::StillGoodDude,
};

/// PAYPHONE Session ID.
///
/// Реально это:
///
/// [u8; 16]
///
/// но имя SessionId
/// намного понятнее.
pub type SessionId = [u8; SESSION_ID_SIZE];

/// После этого времени
/// без DATA/PING Session удаляется.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Одна логическая PAYPHONE Session.
#[derive(Debug)]
pub struct Session {
    /// Уникальный Session ID.
    pub id: SessionId,

    /// Внутренний VPN IPv4.
    ///
    /// Например:
    ///
    /// 10.77.0.2
    pub ipv4: [u8; 4],

    /// Текущий физический endpoint клиента.
    ///
    /// При Resume может измениться.
    pub client_address: SocketAddr,

    /// Согласованные capabilities.
    pub capabilities: u32,

    /// Последний PAYPHONE Frame sequence.
    pub last_sequence: u64,

    /// Когда Session была создана.
    pub created_at: Instant,

    /// Когда от клиента последний раз
    /// приходил валидный packet.
    pub last_activity: Instant,

    /// Nonce клиента из WhatsUpDude.
    pub client_nonce: [u8; 32],

    /// Пока это используется
    /// как Resume Token.
    ///
    /// Позже выделим отдельную
    /// криптографическую сущность.
    pub server_nonce: [u8; 32],
}

/// Все активные PAYPHONE Sessions.
pub struct SessionManager {
    /// Таблица:
    ///
    /// Session ID -> Session
    sessions: HashMap<SessionId, Session>,

    /// Последний octet,
    /// который получит следующий клиент.
    ///
    /// Начинаем:
    ///
    /// 10.77.0.2
    pub next_ipv4_host: u8,
}

impl SessionManager {
    /// Создаёт пустой SessionManager.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),

            next_ipv4_host: 2,
        }
    }

    // =========================================================
    // CREATE SESSION
    // =========================================================

    pub fn create_session(
        &mut self,

        client_address: SocketAddr,

        capabilities: u32,

        client_nonce: [u8; 32],

        last_sequence: u64,

        mtu: u16,
    ) -> AllGoodDude {
        //
        // Выдаём:
        //
        // 10.77.0.X
        //
        let assigned_ipv4 = [10, 77, 0, self.next_ipv4_host];

        //
        // Следующая Session
        // получит следующий IP.
        //
        self.next_ipv4_host = self.next_ipv4_host.wrapping_add(1);

        //
        // Если u8 дошёл до 255
        // и завернулся в 0,
        // возвращаемся к .2.
        //
        // Это пока простейший allocator.
        //
        if self.next_ipv4_host < 2 {
            self.next_ipv4_host = 2;
        }

        //
        // AllGoodDude::new()
        // создаёт:
        //
        // random session_id
        // random server_nonce
        //
        let response = AllGoodDude::new(assigned_ipv4, mtu, capabilities);

        let now = Instant::now();

        let session = Session {
            id: response.session_id,

            ipv4: assigned_ipv4,

            client_address,

            capabilities,

            last_sequence,

            created_at: now,

            last_activity: now,

            client_nonce,

            server_nonce: response.server_nonce,
        };

        //
        // HashMap:
        //
        // session ID -> Session.
        //
        self.sessions.insert(session.id, session);

        response
    }

    // =========================================================
    // RESUME SESSION
    // =========================================================

    pub fn resume_session(
        &mut self,

        session_id: &SessionId,

        resume_token: &[u8; 32],

        new_client_address: SocketAddr,

        sequence: u64,

        mtu: u16,
    ) -> Option<StillGoodDude> {
        //
        // get_mut возвращает:
        //
        // Option<&mut Session>
        //
        // ? здесь означает:
        //
        // если None -> сразу return None.
        //
        let session = self.sessions.get_mut(session_id)?;

        //
        // Проверяем секретный token.
        //
        if &session.server_nonce != resume_token {
            return None;
        }

        //
        // Новый QUIC connection
        // может иметь другой UDP endpoint.
        //
        session.client_address = new_client_address;

        session.last_sequence = sequence;

        session.last_activity = Instant::now();

        Some(StillGoodDude::new(
            session.id,
            session.ipv4,
            mtu,
            session.capabilities,
        ))
    }

    // =========================================================
    // GET SESSION
    // =========================================================

    /// Только чтение.
    pub fn get(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Чтение + изменение.
    pub fn get_mut(&mut self, id: &SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    // =========================================================
    // REMOVE EXPIRED
    // =========================================================

    /// Удаляет Session,
    /// которые не проявляли активности
    /// SESSION_TIMEOUT времени.
    ///
    /// Возвращает количество
    /// удалённых Sessions.
    pub fn remove_expired(&mut self) -> usize {
        let now = Instant::now();

        let before = self.sessions.len();

        //
        // retain:
        //
        // true  -> оставить
        // false -> удалить
        //
        self.sessions.retain(|_session_id, session| {
            let inactive_for = now.duration_since(session.last_activity);

            inactive_for < SESSION_TIMEOUT
        });

        let after = self.sessions.len();

        before - after
    }

    // =========================================================
    // INFO
    // =========================================================

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

// =============================================================
// TESTS
// =============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_session() {
        let mut manager = SessionManager::new();

        assert!(manager.is_empty());

        let address: SocketAddr = "127.0.0.1:50000".parse().unwrap();

        let client_nonce = [7u8; 32];

        let response = manager.create_session(address, 13, client_nonce, 1, 1280);

        assert_eq!(manager.len(), 1);

        let session = manager
            .get(&response.session_id)
            .expect("Session not found");

        assert_eq!(session.ipv4, [10, 77, 0, 2]);

        assert_eq!(session.client_address, address);

        assert_eq!(session.capabilities, 13);

        assert_eq!(session.last_sequence, 1);

        assert_eq!(session.client_nonce, client_nonce);

        assert_eq!(session.server_nonce, response.server_nonce);
    }

    #[test]
    fn different_clients_get_different_ip() {
        let mut manager = SessionManager::new();

        let first_address: SocketAddr = "127.0.0.1:50001".parse().unwrap();

        let second_address: SocketAddr = "127.0.0.1:50002".parse().unwrap();

        let first = manager.create_session(first_address, 0, [1u8; 32], 1, 1280);

        let second = manager.create_session(second_address, 0, [2u8; 32], 1, 1280);

        assert_eq!(first.assigned_ipv4, [10, 77, 0, 2]);

        assert_eq!(second.assigned_ipv4, [10, 77, 0, 3]);

        assert_ne!(first.session_id, second.session_id);

        assert_eq!(manager.len(), 2);
    }

    #[test]
    fn resume_session_keeps_same_ip() {
        let mut manager = SessionManager::new();

        let old_address: SocketAddr = "127.0.0.1:50001".parse().unwrap();

        let response = manager.create_session(old_address, 13, [1u8; 32], 1, 1280);

        let new_address: SocketAddr = "127.0.0.1:60000".parse().unwrap();

        let resumed = manager
            .resume_session(
                &response.session_id,
                &response.server_nonce,
                new_address,
                10,
                1280,
            )
            .expect("Resume failed");

        //
        // VPN IP тот же.
        //
        assert_eq!(resumed.assigned_ipv4, [10, 77, 0, 2]);

        //
        // Session ID тот же.
        //
        assert_eq!(resumed.session_id, response.session_id);

        let session = manager.get(&response.session_id).unwrap();

        //
        // А физический endpoint изменился.
        //
        assert_eq!(session.client_address, new_address);

        assert_eq!(session.last_sequence, 10);
    }

    #[test]
    fn resume_with_wrong_token_fails() {
        let mut manager = SessionManager::new();

        let address: SocketAddr = "127.0.0.1:50001".parse().unwrap();

        let response = manager.create_session(address, 13, [1u8; 32], 1, 1280);

        let wrong_token = [99u8; 32];

        let result = manager.resume_session(&response.session_id, &wrong_token, address, 2, 1280);

        assert!(result.is_none());
    }
}
