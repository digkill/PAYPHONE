import Combine
import Foundation
import NetworkExtension
import PayphoneKit

// App-side control of the Network Extension — mirrors what
// PayphoneVpnService's companion object + MainActivity together do on
// Android (start/stop the service, observe its state), but split across
// two OS processes here: NETunnelProviderManager talks to the extension
// process through NetworkExtension's own IPC, there's no shared memory.
@MainActor
final class VpnManager: ObservableObject {
    @Published var status: NEVPNStatus = .invalid
    @Published var statusLine: String = "Follow the white rabbit."
    @Published var assignedIP: String = ""

    private var manager: NETunnelProviderManager?

    // Combine's AnyCancellable, not a raw NotificationCenter token: its
    // own deinit cancels the subscription when this object deallocates,
    // so there's no hand-written `deinit` here trying (and failing under
    // strict concurrency) to touch a MainActor-isolated property from a
    // nonisolated teardown context.
    private var statusCancellable: AnyCancellable?

    /// Bundle id of the PacketTunnelProvider extension target — set once
    /// the real Xcode target exists (see project.yml).
    static let extensionBundleId = "org.mediarise.payphone.tunnel"

    init() {
        statusCancellable = NotificationCenter.default
            .publisher(for: .NEVPNStatusDidChange)
            .compactMap { ($0.object as? NEVPNConnection)?.status }
            .receive(on: DispatchQueue.main)
            .sink { [weak self] status in
                self?.apply(status: status)
            }
    }

    private func apply(status: NEVPNStatus) {
        self.status = status
        updateStatusLine(for: status)
    }

    func loadOrCreateManager() async throws -> NETunnelProviderManager {
        if let manager { return manager }

        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let existing = managers.first
        let candidate = existing ?? NETunnelProviderManager()

        manager = candidate
        status = candidate.connection.status
        return candidate
    }

    func connect(settings: PayphoneSettings) async throws {
        let manager = try await loadOrCreateManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.extensionBundleId
        proto.serverAddress = settings.server
        proto.providerConfiguration = [
            "server": settings.server,
            "psk": settings.psk,
            "serverName": settings.serverName,
            "token": Data(settings.tokenBytes ?? []),
        ]

        if let pin = settings.pinnedCertBytes, !pin.isEmpty {
            proto.providerConfiguration?["pinnedCert"] = Data(pin)
        }

        manager.protocolConfiguration = proto
        manager.localizedDescription = "PAYPHONE"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        statusLine = "What's up, dude?"
        try manager.connection.startVPNTunnel()
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    private func updateStatusLine(for status: NEVPNStatus) {
        switch status {
        case .connecting: statusLine = "What's up, dude?"
        case .connected: statusLine = "All good, dude."
        case .disconnecting: statusLine = "Unplugging…"
        case .disconnected: statusLine = "Follow the white rabbit."
        case .invalid: statusLine = "Follow the white rabbit."
        case .reasserting: statusLine = "Back again, dude?"
        @unknown default: break
        }
    }
}

/// Persisted, non-secret client settings. Secrets (PSK, token, pinned
/// cert) live in the Keychain via `KeychainSessionStore`'s sibling
/// storage — kept out of this struct so it's safe to log/inspect.
struct PayphoneSettings: Sendable {
    var server: String = ""
    var serverName: String = ""
    var psk: String = ""
    var tokenBytes: [UInt8]?
    var pinnedCertBytes: [UInt8]?
}
