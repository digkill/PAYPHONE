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
        let existing = managers.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionBundleId
        }
        let candidate = existing ?? NETunnelProviderManager()

        manager = candidate
        apply(status: candidate.connection.status)
        return candidate
    }

    func loadSettings() async throws -> PayphoneSettings? {
        let manager = try await loadOrCreateManager()
        guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
              let config = proto.providerConfiguration,
              let server = config["server"] as? String,
              let psk = config["psk"] as? String,
              let token = config["token"] as? Data else { return nil }

        return PayphoneSettings(
            transport: (config["transport"] as? String).flatMap(TransportKind.init(rawValue:)) ?? .tls,
            server: server,
            serverName: config["serverName"] as? String ?? "",
            psk: psk,
            tokenBytes: [UInt8](token),
            pinnedCertBytes: (config["pinnedCert"] as? Data).map { [UInt8]($0) }
        )
    }

    func connect(settings: PayphoneSettings) async throws {
        guard !settings.server.isEmpty, settings.psk.count >= 16,
              settings.tokenBytes?.count == ProtocolConstants.subscriptionTokenSize else {
            throw NSError(domain: "org.mediarise.payphone", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Open Settings and fill in the server, PSK and subscription token. The saved VPN profile has not been changed."
            ])
        }
        let manager = try await loadOrCreateManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.extensionBundleId
        proto.serverAddress = settings.server
        proto.providerConfiguration = [
            "server": settings.server,
            "transport": settings.transport.rawValue,
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

/// In-memory settings restored from this app's saved VPN configuration.
/// Contains credentials; never log or describe the whole value.
struct PayphoneSettings: Sendable {
    var transport: TransportKind = .tls
    var server: String = ""
    var serverName: String = ""
    var psk: String = ""
    var tokenBytes: [UInt8]?
    var pinnedCertBytes: [UInt8]?
}
