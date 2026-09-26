import XCTest
@testable import PayphoneKit

private actor ScriptedTransport: FrameTransport {
    var responses: [Frame]
    var sent: [Frame] = []
    init(_ responses: [Frame]) { self.responses = responses }
    func send(_ frame: Frame) { sent.append(frame) }
    func receive() throws -> Frame {
        guard !responses.isEmpty else { throw PayphoneError.streamClosed }
        return responses.removeFirst()
    }
    nonisolated func close() {}
}

final class HandshakeTests: XCTestCase {
    private let id = [UInt8](repeating: 1, count: 16)
    private let nonce = [UInt8](repeating: 2, count: 32)
    private func client() throws -> PayphoneClient {
        try PayphoneClient(subscriptionToken: [UInt8](repeating: 0, count: 135),
                           obfuscationKey: ObfuscationKey(passphrase: "test-passphrase-123456"))
    }
    func testFreshHandshakeReturnsRotatedNonce() async throws {
        let payload: [UInt8] = [1] + id + [10, 77, 0, 2, 4, 76, 0, 0, 0, 1] + [UInt8](repeating: 3, count: 32)
        let transport = ScriptedTransport([
            Frame(type: .allGoodDude, sequence: 1, payload: payload),
            Frame(type: .rekey, sequence: 2, payload: id + nonce)
        ])
        let result = try await client().createNewSession(transport)
        guard case .connected(_, let savedNonce) = result else { return XCTFail("handshake failed") }
        XCTAssertEqual(savedNonce, nonce)
        let sent = await transport.sent
        XCTAssertEqual(sent.last?.payload, id + nonce)
    }
    func testResumeReturnsRotatedNonce() async throws {
        let transport = ScriptedTransport([
            Frame(type: .stillGoodDude, sequence: 1, payload: id + [10, 77, 0, 2, 4, 76, 0, 0, 0, 1]),
            Frame(type: .rekey, sequence: 2, payload: id + nonce)
        ])
        let result = try await client().tryResume(transport, saved: SavedSession(sessionId: id, resumeToken: [UInt8](repeating: 3, count: 32)))
        guard case .connected(_, let savedNonce) = result else { return XCTFail("resume failed") }
        XCTAssertEqual(savedNonce, nonce)
    }
    func testUnknownResumeFallsBackButRevocationIsTerminal() async throws {
        for reason in [DenyReason.invalidToken, .tokenRevoked] {
            let transport = ScriptedTransport([Frame(type: .accessDeniedDude, sequence: 1,
                payload: [reason.rawValue] + [UInt8](repeating: 0, count: 8))])
            let result = try await client().tryResume(transport, saved: SavedSession(sessionId: id, resumeToken: nonce))
            if reason == .invalidToken { XCTAssertNil(result) }
            else {
                guard case .denied(let actual) = result else { return XCTFail("revocation ignored") }
                XCTAssertEqual(actual, reason)
            }
        }
    }
    func testEmptyPinUsesSystemTrust() {
        XCTAssertNil(TlsTrustConfig(serverName: "example.com", pinnedCertDER: []).pinnedCertDER)
    }
    func testTimeoutCancelsPendingOperation() async throws {
        let start = ContinuousClock.now
        let result: Int? = try await withTimeout(seconds: 0.02) {
            try await Task.sleep(nanoseconds: 5_000_000_000)
            return 1
        }
        XCTAssertNil(result)
        XCTAssertLessThan(start.duration(to: .now), .seconds(1))
    }
}
