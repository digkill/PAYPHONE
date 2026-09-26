import XCTest
@testable import PayphoneKit

final class ObfuscationTests: XCTestCase {
    func testRoundtrip() throws {
        let key = ObfuscationKey(passphrase: "test-passphrase")
        let payload = Array("hello quic handshake bytes, more than 32 bytes of them".utf8)

        let wire = try key.obfuscate(payload)
        let plain = key.deobfuscate(wire)

        XCTAssertEqual(plain, payload)
    }

    func testDifferentSaltEachTime() throws {
        let key = ObfuscationKey(passphrase: "test-passphrase")
        let payload = Array("same payload".utf8)

        let first = try key.obfuscate(payload)
        let second = try key.obfuscate(payload)

        XCTAssertNotEqual(first, second)
    }

    func testWrongKeyDoesNotRoundtrip() throws {
        let key = ObfuscationKey(passphrase: "correct-passphrase")
        let other = ObfuscationKey(passphrase: "wrong-passphrase")
        let payload = Array("secret bytes".utf8)

        let wire = try key.obfuscate(payload)

        // Either nil (rejected because the bogus decoded length overruns
        // the buffer) or garbage that isn't the original payload — never
        // an accidental match.
        if let plain = other.deobfuscate(wire) {
            XCTAssertNotEqual(plain, payload)
        }
    }

    func testTooShortIsRejected() {
        let key = ObfuscationKey(passphrase: "test-passphrase")
        XCTAssertNil(key.deobfuscate([1, 2, 3]))
    }

    func testEmptyPayloadRoundtrips() throws {
        let key = ObfuscationKey(passphrase: "test-passphrase")
        let wire = try key.obfuscate([])
        XCTAssertEqual(key.deobfuscate(wire), [])
    }

    func testPlaceholderPassphraseIsRejected() {
        XCTAssertThrowsError(try ObfuscationKey.validatePassphrase("change-me-to-a-real-random-secret"))
    }

    func testShortPassphraseIsRejected() {
        XCTAssertThrowsError(try ObfuscationKey.validatePassphrase("too-short"))
    }

    func testRealPassphraseIsAccepted() throws {
        try ObfuscationKey.validatePassphrase("a-real-32-byte-hex-secret-value")
    }
}
