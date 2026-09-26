package com.payphone.android.client

import com.payphone.android.protocol.Capabilities
import com.payphone.android.protocol.CloseReason
import com.payphone.android.protocol.DenyReason
import com.payphone.android.protocol.Frame
import com.payphone.android.protocol.FrameType
import com.payphone.android.protocol.Messages
import com.payphone.android.protocol.ProtocolConstants
import com.payphone.android.transport.ObfuscationKey
import com.payphone.android.transport.TlsFrameChannel
import com.payphone.android.transport.TlsTrustConfig
import com.payphone.android.transport.TransportKind
import com.payphone.android.transport.looksLikePublicDns
import com.payphone.android.transport.resolveServer
import com.payphone.android.transport.tcpPortFor
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout
import java.net.Socket
import kotlin.random.Random

data class ActiveSession(
    val sessionId: ByteArray,
    val assignedIpv4: ByteArray,
    val mtu: Int,
    val capabilities: Int,
)

sealed class HandshakeResult {
    data class Connected(val session: ActiveSession, val resumeToken: ByteArray) : HandshakeResult()
    data class Denied(val reason: DenyReason) : HandshakeResult()
    data class Error(val message: String) : HandshakeResult()
}

interface FrameTransport : AutoCloseable {
    suspend fun send(frame: Frame)
    suspend fun receive(): Frame
    fun protectSocket(socket: Socket): Boolean = false
}

class TlsFrameTransport(private val channel: TlsFrameChannel) : FrameTransport {
    override suspend fun send(frame: Frame) = channel.sendFrame(frame)
    override suspend fun receive(): Frame = channel.receiveFrame()
    override fun close() = channel.close()
    fun underlyingSocket(): Socket = channel.rawSocket()
}

/**
 * PAYPHONE session handshake — mirrors `payphone-client` Rust flow.
 */
class PayphoneClient(
    private val subscriptionToken: ByteArray,
    private val obfuscationKey: ObfuscationKey,
) {
    suspend fun connect(
        server: String,
        transport: TransportKind,
        tlsTrust: TlsTrustConfig,
        saved: SavedSession?,
        protect: ((Socket) -> Boolean)? = null,
    ): Pair<FrameTransport, HandshakeResult> {
        require(subscriptionToken.size == ProtocolConstants.SUBSCRIPTION_TOKEN_SIZE) {
            "subscription token must be 135 bytes"
        }
        return when (transport) {
            TransportKind.Tls -> connectTls(server, tlsTrust, saved, protect)
            TransportKind.Quic -> error(
                "QUIC (UDP) needs payphone-android/native. Use TLS transport (port 40443) for now.",
            )
        }
    }

    private suspend fun connectTls(
        server: String,
        tlsTrust: TlsTrustConfig,
        saved: SavedSession?,
        protect: ((Socket) -> Boolean)?,
    ): Pair<FrameTransport, HandshakeResult> {
        val (host, udpPort) = resolveServer(server)
        val sni = if (tlsTrust.serverName.isNotBlank()) tlsTrust.serverName else {
            if (looksLikePublicDns(host)) host else "localhost"
        }
        val (_, defaultTcpPort) = tcpPortFor(udpPort, null)
        val tcpPort = if (defaultTcpPort == ProtocolConstants.DEFAULT_TCP_PORT && udpPort != ProtocolConstants.DEFAULT_UDP_PORT) {
            udpPort
        } else {
            defaultTcpPort
        }
        val trust = tlsTrust.copy(serverName = sni)
        var transport: FrameTransport = TlsFrameTransport(TlsFrameChannel.connect(host, tcpPort, trust, protect))
        try {
            if (saved != null) {
                val resumed = try {
                    tryResume(transport, saved)
                } catch (error: Exception) {
                    transport.close()
                    currentCoroutineContext().ensureActive()
                    transport = TlsFrameTransport(TlsFrameChannel.connect(host, tcpPort, trust, protect))
                    null
                }
                if (resumed != null) return transport to resumed
            }
            return transport to createNewSession(transport)
        } catch (error: Throwable) {
            transport.close()
            throw error
        }
    }

    internal suspend fun tryResume(
        transport: FrameTransport,
        saved: SavedSession,
    ): HandshakeResult? {
        val message = Messages.BackAgainDude(saved.sessionId, saved.resumeToken)
        transport.send(
            Frame(
                ProtocolConstants.VERSION,
                FrameType.BackAgainDude,
                0,
                1,
                message.encode(),
            ),
        )
        val frame = withTimeout(2_000) { transport.receive() }
        return when (frame.type) {
            FrameType.StillGoodDude -> {
                val still = Messages.StillGoodDude.decode(frame.payload)
                if (!still.sessionId.contentEquals(saved.sessionId)) return null
                val nonce = rotateResumeToken(transport, still.sessionId)
                HandshakeResult.Connected(
                    ActiveSession(still.sessionId, still.assignedIpv4, still.mtu, still.capabilities),
                    nonce,
                )
            }
            FrameType.AccessDeniedDude -> {
                val reason = Messages.AccessDeniedDude.decode(frame.payload).reason
                if (reason == DenyReason.InvalidToken) null else HandshakeResult.Denied(reason)
            }
            else -> null
        }
    }

    internal suspend fun createNewSession(transport: FrameTransport): HandshakeResult {
        val whatsUp = Messages.WhatsUpDude.new(
            ProtocolConstants.CLIENT_VERSION,
            Capabilities.CLIENT,
            subscriptionToken,
        )
        transport.send(
            Frame(
                ProtocolConstants.VERSION,
                FrameType.WhatsUpDude,
                0,
                1,
                whatsUp.encode(),
            ),
        )
        val response = withTimeout(5_000) { transport.receive() }
        return when (response.type) {
            FrameType.AllGoodDude -> {
                val allGood = Messages.AllGoodDude.decode(response.payload)
                val nonce = rotateResumeToken(transport, allGood.sessionId)
                HandshakeResult.Connected(
                    ActiveSession(
                        allGood.sessionId,
                        allGood.assignedIpv4,
                        allGood.mtu,
                        allGood.capabilities,
                    ),
                    nonce,
                )
            }
            FrameType.AccessDeniedDude -> {
                HandshakeResult.Denied(Messages.AccessDeniedDude.decode(response.payload).reason)
            }
            else -> HandshakeResult.Error("unexpected handshake frame ${response.type}")
        }
    }

    private suspend fun rotateResumeToken(transport: FrameTransport, sessionId: ByteArray): ByteArray {
        transport.send(
            Frame(
                ProtocolConstants.VERSION,
                FrameType.Rekey,
                0,
                2,
                Messages.Rekey.Request(sessionId).encode(),
            ),
        )
        val frame = withTimeout(2_000) { transport.receive() }
        check(frame.type == FrameType.Rekey) { "expected Rekey token" }
        val token = Messages.Rekey.decode(frame.payload) as? Messages.Rekey.Token
            ?: error("expected Rekey token")
        check(token.sessionId.contentEquals(sessionId)) { "Rekey session mismatch" }
        transport.send(
            Frame(
                ProtocolConstants.VERSION,
                FrameType.Rekey,
                0,
                3,
                Messages.Rekey.Token(sessionId, token.nonce).encode(),
            ),
        )
        return token.nonce
    }

    fun randomPingIntervalMs(): Long {
        val jitter = Random.nextInt(0, 7_001)
        return 7_000L + jitter
    }

    suspend fun sendClose(transport: FrameTransport, session: ActiveSession) {
        val close = Messages.Close(session.sessionId, CloseReason.ClientShutdown)
        runCatching {
            transport.send(
                Frame(
                    ProtocolConstants.VERSION,
                    FrameType.Close,
                    0,
                    99,
                    close.encode(),
                ),
            )
        }
    }
}

data class SavedSession(
    val sessionId: ByteArray,
    val resumeToken: ByteArray,
)
