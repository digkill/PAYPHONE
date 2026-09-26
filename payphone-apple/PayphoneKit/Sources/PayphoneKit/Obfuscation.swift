import CryptoKit
import Foundation

// UDP/TCP wire obfuscation matching payphone_transport::obfuscation (Rust)
// and payphone-android/app/.../transport/Obfuscation.kt.
//
// NOT encryption — TLS already provides confidentiality. Its only job is
// to stop PAYPHONE frames from looking like anything recognizable on the
// wire, and to make a wrong-secret probe get silence instead of a real
// protocol error.
//
//   [ 8-byte random salt ][ XOR(
//       tiled SHA256(SHA256(psk) || salt),
//       [2-byte length][payload][0–32 random padding bytes]
//   ) ]
public struct ObfuscationKey: Sendable {
    private static let saltLength = 8
    private static let keyLength = 32
    private static let lengthPrefixLength = 2
    private static let maxPadding = 32
    private static let placeholderPassphrase = "change-me-to-a-real-random-secret"

    private let key: [UInt8]

    public init(passphrase: String) {
        self.key = Array(SHA256.hash(data: Array(passphrase.utf8)))
    }

    /// Anti-footgun check, not a crypto-strength check: rejects the literal
    /// placeholder from .env.example and anything implausibly short.
    public static func validatePassphrase(_ passphrase: String) throws {
        guard passphrase != placeholderPassphrase else {
            throw PayphoneValidationError.placeholderPassphrase
        }

        guard passphrase.count >= 16 else {
            throw PayphoneValidationError.passphraseTooShort
        }
    }

    public func obfuscate(_ payload: [UInt8]) throws -> [UInt8] {
        guard payload.count <= 0xFFFF else { throw PayphoneError.payloadTooLarge }

        let salt = secureRandomBytes(Self.saltLength)
        let stream = keystream(salt: salt)
        let padLength = Int.random(in: 0...Self.maxPadding)

        var plaintext = [UInt8](repeating: 0, count: Self.lengthPrefixLength + payload.count + padLength)
        writeU16(&plaintext, 0, UInt16(payload.count))
        plaintext.replaceSubrange(Self.lengthPrefixLength..<(Self.lengthPrefixLength + payload.count), with: payload)

        if padLength > 0 {
            let padding = secureRandomBytes(padLength)
            plaintext.replaceSubrange((Self.lengthPrefixLength + payload.count)..., with: padding)
        }

        var xored = [UInt8](repeating: 0, count: plaintext.count)
        for index in plaintext.indices {
            xored[index] = plaintext[index] ^ stream[index % Self.keyLength]
        }

        return salt + xored
    }

    /// `nil` if `data` is too short to contain a salt + length prefix, or
    /// the decoded length prefix doesn't fit the remaining bytes — treated
    /// as noise/a probe, never handed further up the stack.
    public func deobfuscate(_ data: [UInt8]) -> [UInt8]? {
        guard data.count >= Self.saltLength + Self.lengthPrefixLength else { return nil }

        let salt = Array(data[0..<Self.saltLength])
        let stream = keystream(salt: salt)
        let body = Array(data[Self.saltLength...])

        var plain = [UInt8](repeating: 0, count: body.count)
        for index in body.indices {
            plain[index] = body[index] ^ stream[index % Self.keyLength]
        }

        let payloadLength = Int(readU16(plain, 0))
        let end = Self.lengthPrefixLength + payloadLength
        guard end <= plain.count else { return nil }

        return Array(plain[Self.lengthPrefixLength..<end])
    }

    private func keystream(salt: [UInt8]) -> [UInt8] {
        var hasher = SHA256()
        hasher.update(data: key)
        hasher.update(data: salt)
        return Array(hasher.finalize())
    }
}

public enum PayphoneValidationError: Error, CustomStringConvertible, Sendable {
    case placeholderPassphrase
    case passphraseTooShort

    public var description: String {
        switch self {
        case .placeholderPassphrase:
            return "PAYPHONE_OBFS_PSK is still the placeholder from .env.example; generate a real secret"
        case .passphraseTooShort:
            return "PAYPHONE_OBFS_PSK must be at least 16 characters"
        }
    }
}
