import Foundation
import NetworkExtension
import PayphoneKit

// Pumps packets between the OS tunnel (packetFlow) and the PAYPHONE wire
// transport, plus keepalive/stats — mirrors
// payphone-android/app/.../vpn/TunnelEngine.kt, with NEPacketTunnelFlow
// standing in for Android's ParcelFileDescriptor-backed TUN streams.
actor TunnelEngine {
    private let packetFlow: NEPacketTunnelFlow
    private let session: ActiveSession
    private let transport: FrameTransport
    private let client: PayphoneClient
    private let onStats: @Sendable (_ rx: UInt64, _ tx: UInt64) -> Void
    private let onStatus: @Sendable (_ line: String) -> Void

    private let sessionStore: SessionStoring
    private let onTerminated: @Sendable (String) -> Void

    private var packetId: UInt64 = 1
    private var frameSequence: UInt64 = 10
    private var pingId: UInt64 = 1
    private var rx: UInt64 = 0
    private var tx: UInt64 = 0
    private var running = false

    init(
        packetFlow: NEPacketTunnelFlow,
        session: ActiveSession,
        transport: FrameTransport,
        client: PayphoneClient,
        sessionStore: SessionStoring,
        onTerminated: @escaping @Sendable (String) -> Void,
        onStats: @escaping @Sendable (_ rx: UInt64, _ tx: UInt64) -> Void,
        onStatus: @escaping @Sendable (_ line: String) -> Void
    ) {
        self.packetFlow = packetFlow
        self.session = session
        self.transport = transport
        self.client = client
        self.sessionStore = sessionStore
        self.onTerminated = onTerminated
        self.onStats = onStats
        self.onStatus = onStatus
    }

    func start() {
        guard !running else { return }
        running = true

        onStatus("All good, dude. TUN is live.")

        Task { await self.pumpTunToWire() }
        Task { await self.pumpWireToTun() }
        Task { await self.keepaliveLoop() }
        Task { await self.statsLoop() }
    }

    func stop() async {
        running = false
        transport.close()
    }

    private func terminate(_ message: String) {
        guard running else { return }
        running = false
        transport.close()
        onTerminated(message)
    }

    private func pumpTunToWire() async {
        while running {
            let packets = await packetFlow.readPacketObjects()

            for packet in packets {
                guard running else { return }

                let bytes = [UInt8](packet.data)
                let message = Messages.DataMessage(sessionId: session.sessionId, packetId: packetId, ipPacket: bytes)
                packetId &+= 1

                let frame = Frame(type: .data, sequence: frameSequence, payload: message.encode())
                frameSequence &+= 1

                do {
                    try await transport.send(frame)
                    tx &+= UInt64(bytes.count)
                } catch {
                    onStatus("Send failed: \(error)")
                    terminate("Send failed: \(error)")
                    return
                }
            }
        }
    }

    private func pumpWireToTun() async {
        while running {
            let frame: Frame
            do {
                frame = try await transport.receive()
            } catch {
                onStatus("Connection lost: \(error)")
                terminate("Connection closed")
                return
            }

            switch frame.type {
            case .data:
                guard let data = try? Messages.DataMessage.decode(frame.payload),
                      data.sessionId == session.sessionId
                else {
                    continue
                }

                let packet = NEPacket(data: Data(data.ipPacket), protocolFamily: sa_family_t(AF_INET))
                packetFlow.writePacketObjects([packet])
                rx &+= UInt64(data.ipPacket.count)

            case .rekey:
                guard let rekey = try? Messages.Rekey.decode(frame.payload),
                      case .token(let id, let nonce) = rekey, id == session.sessionId else { continue }
                sessionStore.save(SavedSession(sessionId: id, resumeToken: nonce))
                let reply = Frame(type: .rekey, sequence: frameSequence, payload: Messages.Rekey.token(sessionId: id, nonce: nonce).encode())
                frameSequence &+= 1
                do { try await transport.send(reply) }
                catch { terminate("Rekey failed: \(error)") }

            case .pong:
                break

            case .accessDeniedDude:
                onStatus("Access denied, dude.")
                terminate("Connection closed")
                return

            case .close:
                onStatus("Server closed the session.")
                terminate("Connection closed")
                return

            default:
                break
            }
        }
    }

    private func keepaliveLoop() async {
        while running {
            let intervalMs = client.randomPingIntervalMs()
            try? await Task.sleep(nanoseconds: intervalMs * 1_000_000)
            guard running else { return }

            let ping = Messages.Ping(sessionId: session.sessionId, pingId: pingId)
            pingId &+= 1

            let frame = Frame(type: .ping, sequence: frameSequence, payload: ping.encode())
            frameSequence &+= 1

            try? await transport.send(frame)
        }
    }

    private func statsLoop() async {
        while running {
            try? await Task.sleep(nanoseconds: 500_000_000)
            onStats(rx, tx)
        }
    }
}
