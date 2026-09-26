import XCTest
@testable import PayphoneKit

final class SessionStoreTests: XCTestCase {
    func testInMemoryStoreRoundtrip() {
        let store = InMemorySessionStore()
        XCTAssertNil(store.load())

        let session = SavedSession(sessionId: secureRandomBytes(16), resumeToken: secureRandomBytes(32))
        store.save(session)

        let loaded = store.load()
        XCTAssertEqual(loaded?.sessionId, session.sessionId)
        XCTAssertEqual(loaded?.resumeToken, session.resumeToken)

        store.clear()
        XCTAssertNil(store.load())
    }

    func testKeychainStoreRoundtrip() {
        // No access group here — exercises the default-keychain path used
        // in local dev/test. The real app+extension split uses a shared
        // App Group access group, wired once the Xcode entitlements exist.
        let store = KeychainSessionStore()
        store.clear()

        let session = SavedSession(sessionId: secureRandomBytes(16), resumeToken: secureRandomBytes(32))
        store.save(session)

        let loaded = store.load()
        XCTAssertEqual(loaded?.sessionId, session.sessionId)
        XCTAssertEqual(loaded?.resumeToken, session.resumeToken)

        store.clear()
        XCTAssertNil(store.load())
    }
}
