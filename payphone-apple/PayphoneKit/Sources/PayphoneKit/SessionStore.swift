import Foundation
import Security

// Persists the resume session (session_id + resume token) between runs —
// the Apple-platform equivalent of .payphone-session (Rust) /
// SessionStore.kt (Android).
//
// Unlike both of those, this goes in the Keychain rather than a plain
// file: no ChaCha20-Poly1305-over-a-file dance needed, the OS already
// keeps Keychain items encrypted at rest and access-controlled, and an
// `accessGroup` lets the main app and the Network Extension process (a
// separate process on Apple platforms) share the same item via an App
// Group entitlement.
public protocol SessionStoring: Sendable {
    func load() -> SavedSession?
    func save(_ session: SavedSession)
    func clear()
}

public struct KeychainSessionStore: SessionStoring {
    private static let account = "payphone-resume-session"
    private static let service = "org.payphone.resume-session"

    /// Shared Keychain access group (e.g. "TEAMID.group.org.mediarise.payphone")
    /// so the app and the Network Extension can both read/write the same
    /// item. `nil` uses the caller's default keychain — fine for local
    /// development and unit tests, not for the real app+extension split.
    private let accessGroup: String?

    public init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
    }

    public func load() -> SavedSession? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return Self.decode(data)
    }

    public func save(_ session: SavedSession) {
        let data = Self.encode(session)
        clear()

        var query = baseQuery()
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        SecItemAdd(query as CFDictionary, nil)
    }

    public func clear() {
        SecItemDelete(baseQuery() as CFDictionary)
    }

    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
        ]

        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        return query
    }

    // [4-byte sessionId length][sessionId][resumeToken] — sessionId is
    // always 16 bytes and resumeToken always 32 today, but this stays
    // forward-compatible without hardcoding those sizes into the store.
    private static func encode(_ session: SavedSession) -> Data {
        var bytes = [UInt8]()
        writeU32(&bytes, at: 0, UInt32(session.sessionId.count))
        bytes.append(contentsOf: session.sessionId)
        bytes.append(contentsOf: session.resumeToken)
        return Data(bytes)
    }

    private static func decode(_ data: Data) -> SavedSession? {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else { return nil }

        let sessionIdLen = Int(readU32(bytes, 0))
        guard bytes.count >= 4 + sessionIdLen else { return nil }

        let sessionId = Array(bytes[4..<(4 + sessionIdLen)])
        let resumeToken = Array(bytes[(4 + sessionIdLen)...])

        return SavedSession(sessionId: sessionId, resumeToken: resumeToken)
    }

    private static func writeU32(_ out: inout [UInt8], at offset: Int, _ value: UInt32) {
        out.append(contentsOf: [
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ])
    }
}

/// In-memory fake for tests and previews — never touches the real Keychain.
public final class InMemorySessionStore: SessionStoring, @unchecked Sendable {
    private var stored: SavedSession?
    private let lock = NSLock()

    public init() {}

    public func load() -> SavedSession? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    public func save(_ session: SavedSession) {
        lock.lock()
        defer { lock.unlock() }
        stored = session
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        stored = nil
    }
}
