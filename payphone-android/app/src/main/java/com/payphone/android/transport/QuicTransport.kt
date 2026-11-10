package com.payphone.android.transport

import com.payphone.android.client.FrameTransport
import com.payphone.android.protocol.Frame
import com.payphone.android.protocol.FrameType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.EmptyCoroutineContext
import java.util.concurrent.atomic.AtomicLong

internal object NativeQuic {
    val available = runCatching { System.loadLibrary("payphone_jni") }.isSuccess
    external fun open(key: ByteArray, pin: ByteArray?): Long
    external fun socketFd(handle: Long): Int
    external fun connect(handle: Long, address: ByteArray, sni: ByteArray): Int
    external fun send(handle: Long, data: ByteArray): Int
    external fun receive(handle: Long, out: ByteArray): Int
    external fun close(handle: Long)
}

class QuicFrameTransport private constructor(handle: Long) : FrameTransport {
    private val handle = AtomicLong(handle)
    private val receiveMutex = Mutex()
    private val receiveBuffer = ByteArray(65535)

    override suspend fun send(frame: Frame) {
        currentCoroutineContext().ensureActive()
        val result = NativeQuic.send(handle.get(), frame.encode())
        check(result >= 0) { "QUIC connection closed" }
        // DATA loss is allowed; a control frame that did not fit must fail promptly.
        check(result != 0 || frame.type == FrameType.Data) { "QUIC control frame exceeds MTU" }
    }

    override suspend fun receive(): Frame = withContext(Dispatchers.IO) {
        receiveMutex.withLock {
            while (true) {
                currentCoroutineContext().ensureActive()
                val size = NativeQuic.receive(handle.get(), receiveBuffer)
                check(size >= 0) { "QUIC connection closed" }
                if (size > 0) return@withLock Frame.decode(receiveBuffer.copyOf(size))
            }
            @Suppress("UNREACHABLE_CODE") error("unreachable")
        }
    }

    override fun close() {
        val old = handle.getAndSet(0)
        if (old != 0L) NativeQuic.close(old)
    }

    companion object {
        suspend fun connect(
            host: String, port: Int, trust: TlsTrustConfig, key: ByteArray,
            protectFd: ((Int) -> Boolean)?,
        ): QuicFrameTransport {
            check(NativeQuic.available) { "QUIC is unavailable in this build. Select TLS or install a build with QUIC support." }
            return suspendCancellableCoroutine { continuation ->
                val pending = AtomicLong(0)
                continuation.invokeOnCancellation { NativeQuic.close(pending.getAndSet(0)) }
                Dispatchers.IO.dispatch(EmptyCoroutineContext, Runnable {
                    if (!continuation.isActive) return@Runnable
                    val result = runCatching {
                        val native = NativeQuic.open(key, trust.pinnedCert)
                        check(native != 0L) { "Cannot create QUIC endpoint (check certificate)" }
                        pending.set(native)
                        if (!continuation.isActive) {
                            NativeQuic.close(pending.getAndSet(0))
                            error("QUIC connection cancelled")
                        }
                        if (protectFd != null) check(protectFd(NativeQuic.socketFd(native))) { "Cannot protect QUIC socket" }
                        check(NativeQuic.connect(native, "$host:$port".toByteArray(), trust.serverName.toByteArray()) == 1) {
                            "QUIC handshake failed (address, PSK, certificate or timeout)"
                        }
                        QuicFrameTransport(native)
                    }
                    if (result.isFailure) NativeQuic.close(pending.getAndSet(0))
                    continuation.resumeWith(result)
                })
            }
        }
    }
}
