import Foundation

// Payload bodies for each FrameType. Mirrors
// payphone-android/app/.../protocol/Messages.kt byte-for-byte.
//
// Namespaced under `Messages` (like the Kotlin `object Messages`) rather
// than top-level types, mainly so `Messages.Data` doesn't fight with
// `Foundation.Data` everywhere PayphoneKit imports Foundation.
public enum Messages {
    public struct WhatsUpDude {
        public let clientVersion: UInt16
        public let capabilities: UInt32
        public let clientNonce: [UInt8]
        public let authToken: [UInt8]

        public init(clientVersion: UInt16, capabilities: UInt32, clientNonce: [UInt8], authToken: [UInt8]) {
            self.clientVersion = clientVersion
            self.capabilities = capabilities
            self.clientNonce = clientNonce
            self.authToken = authToken
        }

        public static func make(clientVersion: UInt16, capabilities: UInt32, authToken: [UInt8]) -> WhatsUpDude {
            WhatsUpDude(
                clientVersion: clientVersion,
                capabilities: capabilities,
                clientNonce: secureRandomBytes(32),
                authToken: authToken
            )
        }

        public func encode() throws -> [UInt8] {
            guard authToken.count <= 2048 else { throw PayphoneError.tokenTooLarge }

            var out = [UInt8](repeating: 0, count: 41 + authToken.count)
            out[0] = ProtocolConstants.version
            writeU16(&out, 1, clientVersion)
            writeU32(&out, 3, capabilities)
            out.replaceSubrange(7..<39, with: clientNonce)
            writeU16(&out, 39, UInt16(authToken.count))
            out.replaceSubrange(41..., with: authToken)
            return out
        }
    }

    public struct AllGoodDude {
        public let sessionId: [UInt8]
        public let assignedIpv4: [UInt8]
        public let mtu: UInt16
        public let capabilities: UInt32
        public let serverNonce: [UInt8]

        public static func decode(_ payload: [UInt8]) throws -> AllGoodDude {
            guard payload.count == 59 else {
                throw PayphoneError.invalidMessageSize("AllGoodDude", expected: 59, actual: payload.count)
            }

            return AllGoodDude(
                sessionId: Array(payload[1..<17]),
                assignedIpv4: Array(payload[17..<21]),
                mtu: readU16(payload, 21),
                capabilities: readU32(payload, 23),
                serverNonce: Array(payload[27..<59])
            )
        }
    }

    public struct StillGoodDude {
        public let sessionId: [UInt8]
        public let assignedIpv4: [UInt8]
        public let mtu: UInt16
        public let capabilities: UInt32

        public static func decode(_ payload: [UInt8]) throws -> StillGoodDude {
            guard payload.count == 26 else {
                throw PayphoneError.invalidMessageSize("StillGoodDude", expected: 26, actual: payload.count)
            }

            return StillGoodDude(
                sessionId: Array(payload[0..<16]),
                assignedIpv4: Array(payload[16..<20]),
                mtu: readU16(payload, 20),
                capabilities: readU32(payload, 22)
            )
        }
    }

    public struct BackAgainDude {
        public let sessionId: [UInt8]
        public let resumeToken: [UInt8]

        public init(sessionId: [UInt8], resumeToken: [UInt8]) {
            self.sessionId = sessionId
            self.resumeToken = resumeToken
        }

        public func encode() throws -> [UInt8] {
            guard sessionId.count == ProtocolConstants.sessionIdSize,
                  resumeToken.count == ProtocolConstants.serverNonceSize
            else {
                throw PayphoneError.invalidMessageSize(
                    "BackAgainDude",
                    expected: ProtocolConstants.sessionIdSize + ProtocolConstants.serverNonceSize,
                    actual: sessionId.count + resumeToken.count
                )
            }

            return sessionId + resumeToken
        }
    }

    public struct AccessDeniedDude {
        public let reason: DenyReason
        public let expiresAt: UInt64

        public static func decode(_ payload: [UInt8]) throws -> AccessDeniedDude {
            guard payload.count == 9 else {
                throw PayphoneError.invalidMessageSize("AccessDeniedDude", expected: 9, actual: payload.count)
            }

            guard let reason = DenyReason(rawValue: payload[0]) else {
                throw PayphoneError.unknownDenyReason(payload[0])
            }

            return AccessDeniedDude(reason: reason, expiresAt: readU64(payload, 1))
        }
    }

    public struct DataMessage {
        public let sessionId: [UInt8]
        public let packetId: UInt64
        public let ipPacket: [UInt8]

        public init(sessionId: [UInt8], packetId: UInt64, ipPacket: [UInt8]) {
            self.sessionId = sessionId
            self.packetId = packetId
            self.ipPacket = ipPacket
        }

        public func encode() -> [UInt8] {
            var out = [UInt8](repeating: 0, count: ProtocolConstants.dataHeaderSize + ipPacket.count)
            out.replaceSubrange(0..<16, with: sessionId)
            writeU64(&out, 16, packetId)
            out.replaceSubrange(ProtocolConstants.dataHeaderSize..., with: ipPacket)
            return out
        }

        public static func decode(_ payload: [UInt8]) throws -> DataMessage {
            guard payload.count >= ProtocolConstants.dataHeaderSize else {
                throw PayphoneError.frameTooSmall
            }

            return DataMessage(
                sessionId: Array(payload[0..<16]),
                packetId: readU64(payload, 16),
                ipPacket: Array(payload[ProtocolConstants.dataHeaderSize...])
            )
        }
    }

    public struct Ping {
        public let sessionId: [UInt8]
        public let pingId: UInt64

        public init(sessionId: [UInt8], pingId: UInt64) {
            self.sessionId = sessionId
            self.pingId = pingId
        }

        public func encode() -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 24)
            out.replaceSubrange(0..<16, with: sessionId)
            writeU64(&out, 16, pingId)
            return out
        }
    }

    public struct Pong {
        public let sessionId: [UInt8]
        public let pingId: UInt64

        public func encode() -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 24)
            out.replaceSubrange(0..<16, with: sessionId)
            writeU64(&out, 16, pingId)
            return out
        }

        public static func decode(_ payload: [UInt8]) throws -> Pong {
            guard payload.count == 24 else {
                throw PayphoneError.invalidMessageSize("Pong", expected: 24, actual: payload.count)
            }

            return Pong(sessionId: Array(payload[0..<16]), pingId: readU64(payload, 16))
        }
    }

    public enum Rekey {
        case request(sessionId: [UInt8])
        case token(sessionId: [UInt8], nonce: [UInt8])

        public func encode() -> [UInt8] {
            switch self {
            case .request(let sessionId):
                return sessionId
            case .token(let sessionId, let nonce):
                return sessionId + nonce
            }
        }

        public static func decode(_ payload: [UInt8]) throws -> Rekey {
            switch payload.count {
            case 16:
                return .request(sessionId: payload)
            case 48:
                return .token(sessionId: Array(payload[0..<16]), nonce: Array(payload[16..<48]))
            default:
                throw PayphoneError.invalidRekeyLength(payload.count)
            }
        }
    }

    public struct Close {
        public let sessionId: [UInt8]
        public let reason: CloseReason

        public init(sessionId: [UInt8], reason: CloseReason) {
            self.sessionId = sessionId
            self.reason = reason
        }

        public func encode() -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 17)
            out.replaceSubrange(0..<16, with: sessionId)
            out[16] = reason.rawValue
            return out
        }
    }
}
