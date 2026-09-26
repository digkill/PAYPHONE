import Foundation

// Wire protocol PAYPHONE/1. Mirrors payphone-core (Rust) and
// payphone-android/app/.../protocol/Protocol.kt byte-for-byte.
// Frame names are part of the protocol — do not rename them.

public enum ProtocolConstants {
    public static let version: UInt8 = 1
    public static let headerSize = 16
    public static let maxPayloadSize = 64 * 1024
    public static let defaultUDPPort: UInt16 = 40404
    public static let defaultTCPPort: UInt16 = 40443
    public static let clientVersion: UInt16 = 1
    public static let sessionIdSize = 16
    public static let serverNonceSize = 32
    public static let dataHeaderSize = 24
    public static let payphoneMTU = 1100
    public static let subscriptionTokenSize = 135
}

public enum FrameType: UInt8, Sendable {
    case data = 1
    case whatsUpDude = 2
    case allGoodDude = 3
    case ping = 4
    case pong = 5
    case rekey = 6
    case close = 7
    case backAgainDude = 8
    case stillGoodDude = 9
    case accessDeniedDude = 10
}

public enum Capabilities {
    public static let ipv4: UInt32 = 1 << 0
    public static let ipv6: UInt32 = 1 << 1
    public static let dns: UInt32 = 1 << 2
    public static let resume: UInt32 = 1 << 3
    public static let roaming: UInt32 = 1 << 4

    public static let client: UInt32 = ipv4 | ipv6 | dns | resume | roaming
}

public enum DenyReason: UInt8, Sendable {
    case invalidToken = 1
    case subscriptionExpired = 2
    case tokenRevoked = 3
    case subscriptionNotActive = 4
    case unknownSigningKey = 5
    case unsupportedPlan = 6
    case internalAuthError = 7
    case deviceLimitReached = 8
}

public enum CloseReason: UInt8, Sendable {
    case clientShutdown = 0
    case serverShutdown = 1
    case replaced = 2
}

public enum PayphoneError: Error, CustomStringConvertible, Sendable {
    case frameTooSmall
    case unsupportedVersion(UInt8)
    case unknownFrameType(UInt8)
    case payloadTooLarge
    case invalidPayloadLength
    case invalidMessageSize(String, expected: Int, actual: Int)
    case unknownDenyReason(UInt8)
    case invalidRekeyLength(Int)
    case tokenTooLarge
    case streamClosed
    case unexpectedFrame(FrameType)
    case handshakeTimedOut
    case pinMismatch

    public var description: String {
        switch self {
        case .frameTooSmall: return "frame too small"
        case .unsupportedVersion(let v): return "unsupported version \(v)"
        case .unknownFrameType(let t): return "unknown frame type \(t)"
        case .payloadTooLarge: return "payload too large"
        case .invalidPayloadLength: return "invalid payload length"
        case .invalidMessageSize(let name, let expected, let actual):
            return "\(name) must be \(expected) bytes, got \(actual)"
        case .unknownDenyReason(let r): return "unknown deny reason \(r)"
        case .invalidRekeyLength(let n): return "invalid rekey length \(n)"
        case .tokenTooLarge: return "subscription token too large"
        case .streamClosed: return "stream closed"
        case .unexpectedFrame(let t): return "unexpected handshake frame \(t)"
        case .handshakeTimedOut: return "handshake timed out"
        case .pinMismatch: return "server certificate does not match pin"
        }
    }
}

/// One PAYPHONE datagram/record: 16-byte header + payload.
public struct Frame: Sendable {
    public let version: UInt8
    public let type: FrameType
    public let flags: UInt16
    public let sequence: UInt64
    public let payload: [UInt8]

    public init(
        version: UInt8 = ProtocolConstants.version,
        type: FrameType,
        flags: UInt16 = 0,
        sequence: UInt64,
        payload: [UInt8]
    ) {
        self.version = version
        self.type = type
        self.flags = flags
        self.sequence = sequence
        self.payload = payload
    }

    public func encode() throws -> [UInt8] {
        guard payload.count <= ProtocolConstants.maxPayloadSize else {
            throw PayphoneError.payloadTooLarge
        }

        var out = [UInt8](repeating: 0, count: ProtocolConstants.headerSize + payload.count)
        out[0] = version
        out[1] = type.rawValue
        writeU16(&out, 2, flags)
        writeU32(&out, 4, UInt32(payload.count))
        writeU64(&out, 8, sequence)
        out.replaceSubrange(ProtocolConstants.headerSize..., with: payload)
        return out
    }

    public static func decode(_ data: [UInt8]) throws -> Frame {
        guard data.count >= ProtocolConstants.headerSize else {
            throw PayphoneError.frameTooSmall
        }

        let version = data[0]
        guard version == ProtocolConstants.version else {
            throw PayphoneError.unsupportedVersion(version)
        }

        guard let type = FrameType(rawValue: data[1]) else {
            throw PayphoneError.unknownFrameType(data[1])
        }

        let flags = readU16(data, 2)
        let payloadLen = Int(readU32(data, 4))

        guard payloadLen <= ProtocolConstants.maxPayloadSize else {
            throw PayphoneError.payloadTooLarge
        }

        guard data.count == ProtocolConstants.headerSize + payloadLen else {
            throw PayphoneError.invalidPayloadLength
        }

        let sequence = readU64(data, 8)
        let payload = Array(data[ProtocolConstants.headerSize...])

        return Frame(version: version, type: type, flags: flags, sequence: sequence, payload: payload)
    }

    /// Reads just the payload length out of a 16-byte header, so a stream
    /// transport (TCP/TLS) can size its next read before the payload arrives.
    public static func payloadLength(fromHeader header: [UInt8]) throws -> Int {
        guard header.count >= ProtocolConstants.headerSize else {
            throw PayphoneError.frameTooSmall
        }

        guard header[0] == ProtocolConstants.version else {
            throw PayphoneError.unsupportedVersion(header[0])
        }

        let len = Int(readU32(header, 4))

        guard len <= ProtocolConstants.maxPayloadSize else {
            throw PayphoneError.payloadTooLarge
        }

        return len
    }
}

// MARK: - Big-endian integer helpers

func readU16(_ data: [UInt8], _ offset: Int) -> UInt16 {
    (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
}

func readU32(_ data: [UInt8], _ offset: Int) -> UInt32 {
    (UInt32(data[offset]) << 24)
        | (UInt32(data[offset + 1]) << 16)
        | (UInt32(data[offset + 2]) << 8)
        | UInt32(data[offset + 3])
}

func readU64(_ data: [UInt8], _ offset: Int) -> UInt64 {
    var value: UInt64 = 0

    for index in 0..<8 {
        value = (value << 8) | UInt64(data[offset + index])
    }

    return value
}

func writeU16(_ out: inout [UInt8], _ offset: Int, _ value: UInt16) {
    out[offset] = UInt8((value >> 8) & 0xFF)
    out[offset + 1] = UInt8(value & 0xFF)
}

func writeU32(_ out: inout [UInt8], _ offset: Int, _ value: UInt32) {
    out[offset] = UInt8((value >> 24) & 0xFF)
    out[offset + 1] = UInt8((value >> 16) & 0xFF)
    out[offset + 2] = UInt8((value >> 8) & 0xFF)
    out[offset + 3] = UInt8(value & 0xFF)
}

func writeU64(_ out: inout [UInt8], _ offset: Int, _ value: UInt64) {
    for index in 0..<8 {
        let shift = UInt64((7 - index) * 8)
        out[offset + index] = UInt8((value >> shift) & 0xFF)
    }
}

/// Cryptographically random bytes via the platform's `Security` framework
/// (the Swift-side equivalent of `java.security.SecureRandom`).
func secureRandomBytes(_ count: Int) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    precondition(status == errSecSuccess, "SecRandomCopyBytes failed with status \(status)")
    return bytes
}
