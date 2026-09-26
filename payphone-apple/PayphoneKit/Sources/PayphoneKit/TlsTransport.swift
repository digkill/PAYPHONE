import Foundation
import Network
import Security
import os

// TCP+TLS frame transport — same PAYPHONE frames as the QUIC path, just
// length-prefixed on a TLS stream instead of one-per-UDP-datagram (see
// payphone_transport::https_front and
// payphone-android/app/.../transport/TlsTransport.kt).
//
// Built on Network.framework (NWConnection) rather than URLSession/
// SSLSocket-equivalents — it's the Apple-native way to get raw TLS stream
// I/O with SNI + ALPN + a custom trust/pin callback, no third-party TLS
// library needed.

public enum TransportKind: String, Sendable {
    case quic
    case tls

    /// Mirrors the Rust/Kotlin alias table: quic/udp are the same thing,
    /// tls/https/tcp are the same thing.
    public init?(configValue: String) {
        switch configValue.lowercased() {
        case "quic", "udp": self = .quic
        case "tls", "https", "tcp": self = .tls
        default: return nil
        }
    }
}

public struct TlsTrustConfig: Sendable {
    public let serverName: String
    /// Pin a single leaf certificate (DER bytes). `nil` = system trust store.
    public let pinnedCertDER: [UInt8]?

    public init(serverName: String, pinnedCertDER: [UInt8]? = nil) {
        self.serverName = serverName
        self.pinnedCertDER = pinnedCertDER.flatMap { $0.isEmpty ? nil : $0 }
    }
}

public protocol FrameTransport: Sendable {
    func send(_ frame: Frame) async throws
    func receive() async throws -> Frame
    func close()
}

public enum TlsTransportError: Error, CustomStringConvertible, Sendable {
    case connectionFailed(String)
    case connectTimedOut
    case notReady

    public var description: String {
        switch self {
        case .connectionFailed(let reason): return "TLS connection failed: \(reason)"
        case .connectTimedOut: return "TLS connect timed out"
        case .notReady: return "connection is not ready"
        }
    }
}

public final class TlsFrameChannel: FrameTransport, @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "payphone.tls.channel")

    private init(connection: NWConnection) {
        self.connection = connection
    }

    public static func connect(
        host: String,
        port: UInt16,
        trust: TlsTrustConfig,
        timeout: TimeInterval = 15
    ) async throws -> TlsFrameChannel {
        let tlsOptions = NWProtocolTLS.Options()
        let securityOptions = tlsOptions.securityProtocolOptions

        sec_protocol_options_set_min_tls_protocol_version(securityOptions, .TLSv12)
        sec_protocol_options_set_tls_server_name(securityOptions, trust.serverName)
        sec_protocol_options_add_tls_application_protocol(securityOptions, "http/1.1")

        if let pinnedCertDER = trust.pinnedCertDER {
            sec_protocol_options_set_verify_block(
                securityOptions,
                { _, secTrust, complete in
                    complete(Self.leafMatchesPin(secTrust, pinnedCertDER: pinnedCertDER))
                },
                DispatchQueue(label: "payphone.tls.verify")
            )
        }

        let tcpOptions = NWProtocolTCP.Options()
        let parameters = NWParameters(tls: tlsOptions, tcp: tcpOptions)

        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw TlsTransportError.connectionFailed("invalid port \(port)")
        }

        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        let channel = TlsFrameChannel(connection: connection)

        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                // `stateUpdateHandler` and the timeout's DispatchWorkItem both
                // run on `channel.queue` (a single serial queue), so they can
                // never truly race each other — but a plain captured `var`
                // can't prove that to the Swift 6 concurrency checker. A lock
                // makes the "resume the continuation exactly once" guarantee
                // both correct and Sendable-checkable.
                let resumed = OSAllocatedUnfairLock(initialState: false)

                @Sendable func claim() -> Bool {
                    resumed.withLock { flag in
                        guard !flag else { return false }
                        flag = true
                        return true
                    }
                }

                let timeoutWork = DispatchWorkItem {
                    guard claim() else { return }
                    connection.cancel()
                    continuation.resume(throwing: TlsTransportError.connectTimedOut)
                }

                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        guard claim() else { return }
                        timeoutWork.cancel()
                        continuation.resume()
                    case .failed(let error):
                        guard claim() else { return }
                        timeoutWork.cancel()
                        continuation.resume(throwing: TlsTransportError.connectionFailed(String(describing: error)))
                    case .cancelled:
                        guard claim() else { return }
                        timeoutWork.cancel()
                        continuation.resume(throwing: TlsTransportError.connectionFailed("cancelled"))
                    default:
                        break
                    }
                }

                connection.start(queue: channel.queue)
                channel.queue.asyncAfter(deadline: .now() + timeout, execute: timeoutWork)
            }
        } onCancel: {
            connection.cancel()
        }

        return channel
    }

    public func send(_ frame: Frame) async throws {
        let bytes = try frame.encode()

        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(
                    content: Data(bytes),
                    completion: .contentProcessed { error in
                        if let error {
                            continuation.resume(throwing: TlsTransportError.connectionFailed(String(describing: error)))
                        } else {
                            continuation.resume()
                        }
                    }
                )
            }
        } onCancel: {
            self.close()
        }
    }

    public func receive() async throws -> Frame {
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let header = try await readExactly(ProtocolConstants.headerSize)
            let payloadLen = try Frame.payloadLength(fromHeader: header)
            let payload = payloadLen > 0 ? try await readExactly(payloadLen) : []
            return try Frame.decode(header + payload)
        } onCancel: {
            self.close()
        }
    }

    public func close() {
        connection.cancel()
    }

    private func readExactly(_ count: Int) async throws -> [UInt8] {
        var collected = [UInt8]()
        collected.reserveCapacity(count)

        while collected.count < count {
            let remaining = count - collected.count

            let chunk: [UInt8] = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) { data, _, isComplete, error in
                    if let error {
                        continuation.resume(throwing: TlsTransportError.connectionFailed(String(describing: error)))
                        return
                    }

                    if let data, !data.isEmpty {
                        continuation.resume(returning: [UInt8](data))
                        return
                    }

                    if isComplete {
                        continuation.resume(throwing: PayphoneError.streamClosed)
                        return
                    }

                    continuation.resume(returning: [])
                }
            }

            collected.append(contentsOf: chunk)
        }

        return collected
    }

    private static func leafMatchesPin(_ secTrust: sec_trust_t, pinnedCertDER: [UInt8]) -> Bool {
        let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()

        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first
        else {
            return false
        }

        let leafDER = SecCertificateCopyData(leaf) as Data
        return [UInt8](leafDER) == pinnedCertDER
    }
}

/// Splits "host:port" the same way as payphone-client's config parsing.
/// A bare host with no `:port` defaults to the QUIC/UDP default port —
/// callers pick the actual TCP port separately via `tcpPort(forUdpPort:explicitTcp:)`.
public func resolveServer(_ hostPort: String) throws -> (host: String, port: UInt16) {
    let trimmed = hostPort.trimmingCharacters(in: .whitespaces)

    guard let colonIndex = trimmed.lastIndex(of: ":"), colonIndex != trimmed.index(before: trimmed.endIndex) else {
        return (trimmed, ProtocolConstants.defaultUDPPort)
    }

    let host = String(trimmed[trimmed.startIndex..<colonIndex])
    let portString = String(trimmed[trimmed.index(after: colonIndex)...])

    guard let port = UInt16(portString) else {
        throw TlsTransportError.connectionFailed("invalid port in \(hostPort)")
    }

    return (host, port)
}

/// Mirrors `tcpPortFor` in the Kotlin/Rust clients: if no explicit TCP
/// override is given and the UDP port is the PAYPHONE default (40404),
/// the TCP front is assumed to be at the PAYPHONE default TCP port
/// (40443). Otherwise the UDP port doubles as the TCP port (matches how
/// docker-compose.server.yml exposes both protocols on the same host port).
public func tcpPort(forUdpPort udpPort: UInt16, explicitTcp: String?) throws -> (host: String, port: UInt16) {
    if let explicitTcp {
        return try resolveServer(explicitTcp)
    }

    if udpPort == ProtocolConstants.defaultUDPPort {
        return ("", ProtocolConstants.defaultTCPPort)
    }

    return ("", udpPort)
}

/// Heuristic for choosing SNI/trust mode: a public DNS name gets system
/// trust, a bare IP or "localhost" gets the pinned dev certificate.
public func looksLikePublicDNS(_ host: String) -> Bool {
    if host.caseInsensitiveCompare("localhost") == .orderedSame { return false }
    if host.allSatisfy({ $0.isNumber || $0 == "." }) { return false }
    return host.contains(".")
}
