package com.payphone.android.vpn

import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.payphone.android.client.ActiveSession
import com.payphone.android.client.FrameTransport
import com.payphone.android.protocol.Frame
import com.payphone.android.protocol.FrameType
import com.payphone.android.protocol.Messages
import com.payphone.android.protocol.ProtocolConstants
import com.payphone.android.data.SessionStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress

class TunnelEngine(
    private val scope: CoroutineScope,
    private val vpnService: VpnService,
    private val session: ActiveSession,
    private val serverHost: String,
    private val transport: FrameTransport,
    private val sessionStore: SessionStore,
    private val onTerminated: (String) -> Unit,
    private val onStats: (rx: Long, tx: Long) -> Unit,
    private val onStatus: (String) -> Unit,
) {
    private var tunFd: ParcelFileDescriptor? = null
    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null
    private var jobs: List<Job> = emptyList()

    private var packetId = 1L
    private val frameSequence = AtomicLong(10L)
    private var pingId = 1L
    private var rx = 0L
    private var tx = 0L

    fun start(): Boolean {
        val builder = vpnService.Builder()
            .setSession("PAYPHONE")
            .setMtu(session.mtu.coerceAtMost(ProtocolConstants.PAYPHONE_MTU))
            .addAddress(bytesToInet(session.assignedIpv4), 24)
            .addRoute("0.0.0.0", 1)
            .addRoute("128.0.0.0", 1)
            .addDnsServer("10.77.0.1")
            .setBlocking(true)

        runCatching {
            val serverAddr = InetAddress.getByName(serverHost)
            builder.addDisallowedApplication(vpnService.packageName)
            builder.addRoute(serverAddr, 32)
        }

        tunFd = builder.establish() ?: return false
        val fd = tunFd!!
        tunIn = FileInputStream(fd.fileDescriptor)
        tunOut = FileOutputStream(fd.fileDescriptor)

        onStatus("All good, dude. TUN is live.")
        jobs = listOf(
            launchPump { tunToWire() },
            launchPump { wireToTun() },
            launchPump { keepaliveLoop() },
            launchPump { statsLoop() },
        )
        return true
    }

    private fun launchPump(block: suspend () -> Unit): Job = scope.launch {
        try {
            block()
        } catch (cancelled: CancellationException) {
            if (currentCoroutineContext().isActive) {
                onTerminated("Connection timed out")
                stop()
            }
            throw cancelled
        } catch (error: Exception) {
            onTerminated(error.message ?: "Connection lost")
            stop()
        }
    }

    fun stop() {
        jobs.forEach { it.cancel() }
        jobs = emptyList()
        runCatching { tunIn?.close() }
        runCatching { tunOut?.close() }
        runCatching { tunFd?.close() }
        tunIn = null
        tunOut = null
        tunFd = null
        runCatching { transport.close() }
    }

    private suspend fun tunToWire() {
        val input = tunIn ?: return
        val buffer = ByteArray(65535)
        while (currentCoroutineContext().isActive) {
            val size = runCatching { input.read(buffer) }.getOrDefault(-1)
            if (size <= 0) {
                delay(5)
                continue
            }
            val data = Messages.Data(
                session.sessionId,
                packetId++,
                buffer.copyOf(size),
            )
            val frame = Frame(
                ProtocolConstants.VERSION,
                FrameType.Data,
                0,
                frameSequence.getAndIncrement(),
                data.encode(),
            )
            transport.send(frame)
            tx += size
        }
    }

    private suspend fun wireToTun() {
        val output = tunOut ?: return
        while (currentCoroutineContext().isActive) {
            val frame = kotlinx.coroutines.withTimeout(30_000) { transport.receive() }
            when (frame.type) {
                FrameType.Data -> {
                    val data = Messages.Data.decode(frame.payload)
                    if (!data.sessionId.contentEquals(session.sessionId)) continue
                    output.write(data.ipPacket)
                    output.flush()
                    rx += data.ipPacket.size
                }
                FrameType.Rekey -> {
                    val token = Messages.Rekey.decode(frame.payload) as? Messages.Rekey.Token ?: continue
                    if (!token.sessionId.contentEquals(session.sessionId)) continue
                    sessionStore.save(session.sessionId, token.nonce)
                    transport.send(Frame(ProtocolConstants.VERSION, FrameType.Rekey, 0,
                        frameSequence.getAndIncrement(), token.encode()))
                }
                FrameType.Pong -> Unit
                FrameType.AccessDeniedDude -> {
                    onStatus("Access denied, dude.")
                    error("Access denied")
                }
                FrameType.Close -> error("Server closed the session")
                else -> Unit
            }
        }
    }

    private suspend fun keepaliveLoop() {
        while (currentCoroutineContext().isActive) {
            val interval = 7_000L + (0..7_000L).random()
            delay(interval)
            val ping = Messages.Ping(session.sessionId, pingId++)
            transport.send(
                Frame(
                    ProtocolConstants.VERSION,
                    FrameType.Ping,
                    0,
                    frameSequence.getAndIncrement(),
                    ping.encode(),
                ),
            )
        }
    }

    private suspend fun statsLoop() {
        while (currentCoroutineContext().isActive) {
            delay(500)
            onStats(rx, tx)
        }
    }

    private fun bytesToInet(bytes: ByteArray): InetAddress {
        require(bytes.size == 4)
        return InetAddress.getByAddress(bytes)
    }
}
