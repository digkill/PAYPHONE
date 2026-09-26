package com.payphone.android.transport

import com.payphone.android.protocol.Frame
import com.payphone.android.protocol.ProtocolConstants
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.EmptyCoroutineContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

enum class TransportKind {
    Quic,
    Tls,
}

data class TlsTrustConfig(
    val serverName: String,
    /** Pin a single leaf (DER/PEM bytes). Null = system CAs. */
    val pinnedCert: ByteArray? = null,
)

/**
 * TCP TLS transport — same PAYPHONE frames as QUIC, length-prefixed on the wire
 * after TLS (see `payphone_transport::https_front`).
 */
class TlsFrameChannel private constructor(
    private val socket: SSLSocket,
    private val input: BufferedInputStream,
    private val output: BufferedOutputStream,
) : AutoCloseable {
    suspend fun sendFrame(frame: Frame) = socketIo(socket) {
        val bytes = frame.encode()
        synchronized(output) {
            output.write(bytes)
            output.flush()
        }
    }

    suspend fun receiveFrame(): Frame = socketIo(socket) {
        val header = ByteArray(ProtocolConstants.HEADER_SIZE)
        readFully(header)
        val payloadLen = Frame.payloadLenFromHeader(header)
        val body = ByteArray(payloadLen)
        if (payloadLen > 0) {
            readFully(body)
        }
        Frame.decode(header + body)
    }

    fun rawSocket(): Socket = socket

    override fun close() {
        runCatching { socket.close() }
    }

    private fun readFully(target: ByteArray) {
        var offset = 0
        while (offset < target.size) {
            val read = input.read(target, offset, target.size - offset)
            if (read < 0) error("TLS stream closed")
            offset += read
        }
    }

    companion object {
        suspend fun connect(
            host: String,
            port: Int,
            trust: TlsTrustConfig,
            protect: ((Socket) -> Boolean)? = null,
        ): TlsFrameChannel {
            val context = buildSslContext(trust)
            val factory = context.socketFactory
            val plain = Socket()
            return socketIo(plain) {
                check(protect?.invoke(plain) != false) { "VPN socket protection failed" }
                plain.connect(InetSocketAddress(host, port), 15_000)
                val ssl = (factory.createSocket(plain, trust.serverName, port, true) as SSLSocket).apply {
                    enabledProtocols = supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
                    val params: SSLParameters = sslParameters
                    if (Build.VERSION.SDK_INT >= 29) params.applicationProtocols = arrayOf("http/1.1")
                    if (trust.pinnedCert == null) params.endpointIdentificationAlgorithm = "HTTPS"
                    if (looksLikePublicDns(trust.serverName) || trust.serverName == "localhost") {
                        params.serverNames = listOf(SNIHostName(trust.serverName))
                    }
                    sslParameters = params
                }
                ssl.soTimeout = 15_000
                ssl.startHandshake()
                ssl.soTimeout = 0
                TlsFrameChannel(
                    ssl,
                    BufferedInputStream(ssl.inputStream),
                    BufferedOutputStream(ssl.outputStream),
                )
            }
        }

        private fun buildSslContext(trust: TlsTrustConfig): SSLContext {
            val trustManagers = if (trust.pinnedCert != null) {
                arrayOf(PinTrustManager(trust.pinnedCert))
            } else {
                val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                tmf.init(null as KeyStore?)
                tmf.trustManagers
            }
            return SSLContext.getInstance("TLS").apply {
                init(null, trustManagers, null)
            }
        }
    }
}

private class PinTrustManager(pinDer: ByteArray) : X509TrustManager {
    private val expected: X509Certificate = CertificateFactory.getInstance("X.509")
        .generateCertificate(pinDer.inputStream()) as X509Certificate

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        throw UnsupportedOperationException()

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        require(chain.isNotEmpty()) { "empty certificate chain" }
        require(chain[0].encoded.contentEquals(expected.encoded)) {
            "server certificate does not match pin"
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf(expected)
}

fun resolveServer(hostPort: String): Pair<String, Int> {
    val trimmed = hostPort.trim()
    val colon = trimmed.lastIndexOf(':')
    if (colon <= 0 || colon == trimmed.length - 1) {
        return trimmed to ProtocolConstants.DEFAULT_UDP_PORT
    }
    val host = trimmed.substring(0, colon)
    val port = trimmed.substring(colon + 1).toIntOrNull()
        ?: error("invalid port in $hostPort")
    return host to port
}

fun tcpPortFor(udpPort: Int, explicitTcp: String?): Pair<String, Int> {
    if (explicitTcp != null) {
        return resolveServer(explicitTcp)
    }
    return if (udpPort == ProtocolConstants.DEFAULT_UDP_PORT) {
        "" to ProtocolConstants.DEFAULT_TCP_PORT
    } else {
        "" to udpPort
    }
}

fun looksLikePublicDns(host: String): Boolean {
    if (host.equals("localhost", ignoreCase = true)) return false
    if (host.all { it.isDigit() || it == '.' }) return false
    return host.contains('.')
}

// Closing the socket is required: coroutine cancellation alone does not
// interrupt java.net blocking reads or a TLS handshake.
private suspend fun <T> socketIo(socket: Socket, block: () -> T): T =
    suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { runCatching { socket.close() } }
        Dispatchers.IO.dispatch(EmptyCoroutineContext, Runnable {
            if (continuation.isActive) {
                val result = runCatching(block)
                if (result.isFailure) runCatching { socket.close() }
                continuation.resumeWith(result)
            }
        })
    }
