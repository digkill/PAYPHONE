import XCTest
@testable import PayphoneKit

final class ProtocolTests: XCTestCase {
    func testFrameRoundtrip() throws {
        let payload = Array("hello payphone".utf8)
        let original = Frame(type: .data, sequence: 42, payload: payload)

        let encoded = try original.encode()
        let decoded = try Frame.decode(encoded)

        XCTAssertEqual(original.version, decoded.version)
        XCTAssertEqual(original.type, decoded.type)
        XCTAssertEqual(original.sequence, decoded.sequence)
        XCTAssertEqual(original.payload, decoded.payload)
    }

    func testWhatsUpDudeInsideFrame() throws {
        let token = [UInt8](repeating: 0xAB, count: ProtocolConstants.subscriptionTokenSize)
        let message = Messages.WhatsUpDude.make(
            clientVersion: 1,
            capabilities: Capabilities.client,
            authToken: token
        )

        let frame = Frame(type: .whatsUpDude, sequence: 1, payload: try message.encode())
        let decoded = try Frame.decode(try frame.encode())

        XCTAssertEqual(decoded.type, .whatsUpDude)
        XCTAssertEqual(decoded.payload.count, 41 + ProtocolConstants.subscriptionTokenSize)
    }

    func testAllGoodDudeRoundtrip() throws {
        let sessionId = secureRandomBytes(16)
        let serverNonce = secureRandomBytes(32)
        var payload = [UInt8](repeating: 0, count: 59)
        payload[0] = ProtocolConstants.version
        payload.replaceSubrange(1..<17, with: sessionId)
        payload.replaceSubrange(17..<21, with: [10, 77, 0, 2])
        writeU16(&payload, 21, 1100)
        writeU32(&payload, 23, Capabilities.client)
        payload.replaceSubrange(27..<59, with: serverNonce)

        let decoded = try Messages.AllGoodDude.decode(payload)

        XCTAssertEqual(decoded.sessionId, sessionId)
        XCTAssertEqual(decoded.assignedIpv4, [10, 77, 0, 2])
        XCTAssertEqual(decoded.mtu, 1100)
        XCTAssertEqual(decoded.capabilities, Capabilities.client)
        XCTAssertEqual(decoded.serverNonce, serverNonce)
    }

    func testDataMessageRoundtrip() throws {
        let sessionId = secureRandomBytes(16)
        let ipPacket = Array("not-really-an-ip-packet".utf8)
        let message = Messages.DataMessage(sessionId: sessionId, packetId: 7, ipPacket: ipPacket)

        let decoded = try Messages.DataMessage.decode(message.encode())

        XCTAssertEqual(decoded.sessionId, sessionId)
        XCTAssertEqual(decoded.packetId, 7)
        XCTAssertEqual(decoded.ipPacket, ipPacket)
    }

    func testRekeyRequestAndTokenRoundtrip() throws {
        let sessionId = secureRandomBytes(16)
        let nonce = secureRandomBytes(32)

        let requestDecoded = try Messages.Rekey.decode(Messages.Rekey.request(sessionId: sessionId).encode())
        guard case .request(let decodedSessionId) = requestDecoded else {
            return XCTFail("expected .request")
        }
        XCTAssertEqual(decodedSessionId, sessionId)

        let tokenDecoded = try Messages.Rekey.decode(
            Messages.Rekey.token(sessionId: sessionId, nonce: nonce).encode()
        )
        guard case .token(let decodedSessionId2, let decodedNonce) = tokenDecoded else {
            return XCTFail("expected .token")
        }
        XCTAssertEqual(decodedSessionId2, sessionId)
        XCTAssertEqual(decodedNonce, nonce)
    }

    func testUnknownFrameTypeIsRejected() {
        var bytes = [UInt8](repeating: 0, count: ProtocolConstants.headerSize)
        bytes[0] = ProtocolConstants.version
        bytes[1] = 0xFF // not a valid FrameType

        XCTAssertThrowsError(try Frame.decode(bytes))
    }

    func testUnsupportedVersionIsRejected() {
        var bytes = [UInt8](repeating: 0, count: ProtocolConstants.headerSize)
        bytes[0] = 2 // only version 1 exists
        bytes[1] = FrameType.ping.rawValue

        XCTAssertThrowsError(try Frame.decode(bytes))
    }

    func testTooSmallFrameIsRejected() {
        XCTAssertThrowsError(try Frame.decode([1, 2, 3]))
    }
}
