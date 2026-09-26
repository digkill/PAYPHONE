import NetworkExtension
import PayphoneKit
import os

// NEPacketTunnelProvider entry point — mirrors
// payphone-android/app/.../vpn/PayphoneVpnService.kt, minus the parts
// Android needed and Apple's NetworkExtension already gives us for free
// (TUN fd lifecycle, routing table application, app-process isolation).
// NetworkExtension predates Swift concurrency and isn't Sendable-annotated.
// The actual safety here comes from NetworkExtension's own design (one
// provider instance, callbacks serialized onto its own queue), not from
// anything the compiler can verify — this is the standard, accepted
// escape hatch for adopting strict concurrency around pre-Sendable
// system frameworks.
extension NEPacketTunnelFlow: @retroactive @unchecked Sendable {}
extension PacketTunnelProvider: @unchecked Sendable {}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var engine: TunnelEngine?
    private var transport: FrameTransport?
    private let sessionStore: SessionStoring = KeychainSessionStore(accessGroup: AppGroup.keychainAccessGroup)
    private let log = Logger(subsystem: "org.mediarise.payphone.tunnel", category: "PacketTunnelProvider")

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping @Sendable (Error?) -> Void) {
        guard let config = TunnelConfig(protocolConfiguration: protocolConfiguration, options: options) else {
            completionHandler(PayphoneConfigError.missingConfiguration)
            return
        }

        Task {
            do {
                try await connect(config: config)
                completionHandler(nil)
            } catch {
                transport?.close()
                transport = nil
                log.error("startTunnel failed: \(String(describing: error), privacy: .public)")
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void) {
        Task {
            await engine?.stop()
            engine = nil
            transport?.close()
            transport = nil
            completionHandler()
        }
    }

    private func connect(config: TunnelConfig) async throws {
        try ObfuscationKey.validatePassphrase(config.psk)

        let obfuscationKey = ObfuscationKey(passphrase: config.psk)
        let client = try PayphoneClient(subscriptionToken: config.token, obfuscationKey: obfuscationKey)

        let saved = sessionStore.load()
        let (host, _) = try resolveServer(config.server)

        let sni = config.serverName.isEmpty
            ? (looksLikePublicDNS(host) ? host : "localhost")
            : config.serverName

        let trust = TlsTrustConfig(serverName: sni, pinnedCertDER: config.pinnedCertDER)

        let (frameTransport, handshake) = try await client.connect(
            server: config.server,
            tlsTrust: trust,
            saved: saved
        )

        transport = frameTransport

        switch handshake {
        case .connected(let session, let resumeToken):
            sessionStore.save(SavedSession(sessionId: session.sessionId, resumeToken: resumeToken))
            try await applyTunnelSettings(session: session, serverHost: host)

            // Capture the Logger value itself (a Sendable struct), not
            // `self` (an NEPacketTunnelProvider, not Sendable) — this
            // closure has to cross into TunnelEngine's actor isolation.
            let log = log
            let engine = TunnelEngine(
                packetFlow: packetFlow,
                session: session,
                transport: frameTransport,
                client: client,
                sessionStore: sessionStore,
                onTerminated: { [weak self] message in
                    self?.cancelTunnelWithError(PayphoneConfigError.handshakeFailed(message))
                },
                onStats: { _, _ in },
                onStatus: { line in log.info("\(line, privacy: .public)") }
            )
            self.engine = engine
            await engine.start()

        case .denied(let reason):
            sessionStore.clear()
            throw PayphoneConfigError.accessDenied(reason)

        case .failed(let message):
            throw PayphoneConfigError.handshakeFailed(message)
        }
    }

    /// Full-tunnel network settings: everything routes through the
    /// tunnel except an explicit host route back to the real PAYPHONE
    /// server, so the TLS connection carrying the tunnel doesn't try to
    /// route itself through itself (the same problem the macOS CLI
    /// client's FullTunnelGuard solves with a host `/32` route).
    private func applyTunnelSettings(session: ActiveSession, serverHost: String) async throws {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverHost)

        let ipv4 = NEIPv4Settings(addresses: [session.assignedIpv4String], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]

        if let serverIP = try? resolvedIPv4(serverHost) {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverIP, subnetMask: "255.255.255.255")]
        }

        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: ["10.77.0.1"])
        settings.mtu = NSNumber(value: min(session.mtu, UInt16(ProtocolConstants.payphoneMTU)))

        try await setTunnelNetworkSettings(settings)
    }

    private func resolvedIPv4(_ host: String) throws -> String {
        // A bare dotted-quad is already what we need; a DNS name would
        // need actual resolution, which full-tunnel client code across
        // this project has generally avoided relying on for the host
        // route (see gotchas.md — resolving through a resolver that's
        // itself about to be re-routed is exactly the kind of loop that
        // has bitten this project before).
        guard host.split(separator: ".").count == 4, host.allSatisfy({ $0.isNumber || $0 == "." }) else {
            throw PayphoneConfigError.missingConfiguration
        }
        return host
    }
}

/// Config handed down from the app via `NETunnelProviderProtocol.providerConfiguration`.
struct TunnelConfig {
    let server: String
    let psk: String
    let serverName: String
    let token: [UInt8]
    let pinnedCertDER: [UInt8]?

    init?(protocolConfiguration: NEVPNProtocol, options: [String: NSObject]?) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let config = proto.providerConfiguration,
              let server = config["server"] as? String,
              let psk = config["psk"] as? String,
              let tokenData = config["token"] as? Data
        else {
            return nil
        }

        self.server = server
        self.psk = psk
        self.serverName = config["serverName"] as? String ?? ""
        self.token = [UInt8](tokenData)
        self.pinnedCertDER = (config["pinnedCert"] as? Data).map { [UInt8]($0) }
    }
}

enum PayphoneConfigError: Error, CustomStringConvertible {
    case missingConfiguration
    case accessDenied(DenyReason)
    case handshakeFailed(String)

    var description: String {
        switch self {
        case .missingConfiguration: return "PAYPHONE tunnel configuration is missing or invalid"
        case .accessDenied(let reason): return "Access denied, dude. (\(reason))"
        case .handshakeFailed(let message): return message
        }
    }
}

/// App Group id shared between the app and this extension — set to the
/// real group once it exists in Xcode's Signing & Capabilities (see the
/// project plan). `nil` here just means "use the default keychain",
/// which is fine until that entitlement is wired up.
enum AppGroup {
    static let keychainAccessGroup: String? = nil
}
