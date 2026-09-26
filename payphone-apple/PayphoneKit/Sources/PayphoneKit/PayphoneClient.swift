import Foundation

// PAYPHONE session handshake — mirrors payphone-client (Rust) and
// payphone-android/app/.../client/PayphoneClient.kt.

public struct ActiveSession: Sendable {
    public let sessionId: [UInt8]
    public let assignedIpv4: [UInt8]
    public let mtu: UInt16
    public let capabilities: UInt32

    public var assignedIpv4String: String {
        assignedIpv4.map(String.init).joined(separator: ".")
    }
}

public struct SavedSession: Sendable {
    public let sessionId: [UInt8]
    public let resumeToken: [UInt8]

    public init(sessionId: [UInt8], resumeToken: [UInt8]) {
        self.sessionId = sessionId
        self.resumeToken = resumeToken
    }
}

public enum HandshakeResult: Sendable {
    case connected(session: ActiveSession, resumeToken: [UInt8])
    case denied(reason: DenyReason)
    case failed(message: String)
}

public final class PayphoneClient: Sendable {
    private let subscriptionToken: [UInt8]
    private let obfuscationKey: ObfuscationKey

    public init(subscriptionToken: [UInt8], obfuscationKey: ObfuscationKey) throws {
        guard subscriptionToken.count == ProtocolConstants.subscriptionTokenSize else {
            throw PayphoneError.invalidMessageSize(
                "subscription token",
                expected: ProtocolConstants.subscriptionTokenSize,
                actual: subscriptionToken.count
            )
        }

        self.subscriptionToken = subscriptionToken
        self.obfuscationKey = obfuscationKey
    }

    /// Connects over TCP+TLS and runs the handshake (resume if `saved` is
    /// given and the server still recognizes it, otherwise a fresh
    /// `WhatsUpDude`). QUIC is intentionally not wired here yet — see
    /// the project plan for why.
    public func connect(
        server: String,
        tlsTrust: TlsTrustConfig,
        saved: SavedSession?
    ) async throws -> (transport: FrameTransport, result: HandshakeResult) {
        let (host, udpPort) = try resolveServer(server)
        let (_, port) = try tcpPort(forUdpPort: udpPort, explicitTcp: nil)

        let sni = tlsTrust.serverName.isEmpty
            ? (looksLikePublicDNS(host) ? host : "localhost")
            : tlsTrust.serverName

        let trust = TlsTrustConfig(serverName: sni, pinnedCertDER: tlsTrust.pinnedCertDER)
        var channel = try await TlsFrameChannel.connect(host: host, port: port, trust: trust)
        do {
            if let saved {
                do {
                    if let resumed = try await tryResume(channel, saved: saved) {
                        return (channel, resumed)
                    }
                } catch {
                    // A cancelled/partial stream read cannot safely be reused.
                    channel.close()
                    try Task.checkCancellation()
                    channel = try await TlsFrameChannel.connect(host: host, port: port, trust: trust)
                }
            }
            return (channel, try await createNewSession(channel))
        } catch {
            channel.close()
            throw error
        }
    }

    func tryResume(_ transport: FrameTransport, saved: SavedSession) async throws -> HandshakeResult? {
        let message = Messages.BackAgainDude(sessionId: saved.sessionId, resumeToken: saved.resumeToken)
        let frame = Frame(type: .backAgainDude, sequence: 1, payload: try message.encode())
        try await transport.send(frame)

        let response = try await withTimeout(seconds: 2) { try await transport.receive() }
        guard let response else { throw PayphoneError.handshakeTimedOut }

        switch response.type {
        case .stillGoodDude:
            let still = try Messages.StillGoodDude.decode(response.payload)
            guard still.sessionId == saved.sessionId else { return nil }

            let nonce = try await rotateResumeToken(transport, sessionId: still.sessionId)

            return .connected(
                session: ActiveSession(
                    sessionId: still.sessionId,
                    assignedIpv4: still.assignedIpv4,
                    mtu: still.mtu,
                    capabilities: still.capabilities
                ),
                resumeToken: nonce
            )

        case .accessDeniedDude:
            let reason = try Messages.AccessDeniedDude.decode(response.payload).reason
            return reason == .invalidToken ? nil : .denied(reason: reason)

        default:
            return nil
        }
    }

    func createNewSession(_ transport: FrameTransport) async throws -> HandshakeResult {
        let whatsUp = Messages.WhatsUpDude.make(
            clientVersion: ProtocolConstants.clientVersion,
            capabilities: Capabilities.client,
            authToken: subscriptionToken
        )

        try await transport.send(Frame(type: .whatsUpDude, sequence: 1, payload: try whatsUp.encode()))

        guard let response = try await withTimeout(seconds: 5, { try await transport.receive() }) else {
            return .failed(message: PayphoneError.handshakeTimedOut.description)
        }

        switch response.type {
        case .allGoodDude:
            let allGood = try Messages.AllGoodDude.decode(response.payload)
            let nonce = try await rotateResumeToken(transport, sessionId: allGood.sessionId)

            return .connected(
                session: ActiveSession(
                    sessionId: allGood.sessionId,
                    assignedIpv4: allGood.assignedIpv4,
                    mtu: allGood.mtu,
                    capabilities: allGood.capabilities
                ),
                resumeToken: nonce
            )

        case .accessDeniedDude:
            return .denied(reason: try Messages.AccessDeniedDude.decode(response.payload).reason)

        default:
            return .failed(message: PayphoneError.unexpectedFrame(response.type).description)
        }
    }

    private func rotateResumeToken(_ transport: FrameTransport, sessionId: [UInt8]) async throws -> [UInt8] {
        try await transport.send(
            Frame(type: .rekey, sequence: 2, payload: Messages.Rekey.request(sessionId: sessionId).encode())
        )
        guard let frame = try await withTimeout(seconds: 2, { try await transport.receive() }) else {
            throw PayphoneError.handshakeTimedOut
        }
        guard frame.type == .rekey,
              case .token(let tokenSessionId, let nonce) = try Messages.Rekey.decode(frame.payload),
              tokenSessionId == sessionId else {
            throw PayphoneError.unexpectedFrame(frame.type)
        }
        try await transport.send(
            Frame(type: .rekey, sequence: 3, payload: Messages.Rekey.token(sessionId: sessionId, nonce: nonce).encode())
        )
        return nonce
    }

    public func randomPingIntervalMs() -> UInt64 {
        UInt64.random(in: 7_000...14_000)
    }

    public func sendClose(_ transport: FrameTransport, session: ActiveSession) async {
        let close = Messages.Close(sessionId: session.sessionId, reason: .clientShutdown)
        try? await transport.send(Frame(type: .close, sequence: 99, payload: close.encode()))
    }
}

/// Runs `operation`, returning `nil` if it doesn't finish within `seconds`
/// instead of throwing — mirrors Kotlin's `withTimeoutOrNull`.
func withTimeout<T: Sendable>(
    seconds: TimeInterval,
    _ operation: @escaping @Sendable () async throws -> T
) async throws -> T? {
    try await withThrowingTaskGroup(of: T?.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            return nil
        }

        defer { group.cancelAll() }
        guard let first = try await group.next() else { return nil }
        group.cancelAll()
        return first
    }
}
