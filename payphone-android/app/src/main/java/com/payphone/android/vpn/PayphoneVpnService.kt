package com.payphone.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Parcelable
import androidx.core.app.NotificationCompat
import com.payphone.android.MainActivity
import com.payphone.android.R
import com.payphone.android.client.ActiveSession
import com.payphone.android.client.FrameTransport
import com.payphone.android.client.HandshakeResult
import com.payphone.android.client.PayphoneClient
import com.payphone.android.data.PayphoneSettings
import com.payphone.android.data.SessionStore
import com.payphone.android.data.pinnedCertBytes
import com.payphone.android.data.tokenBytes
import com.payphone.android.transport.ObfuscationKey
import com.payphone.android.transport.TlsTrustConfig
import com.payphone.android.transport.looksLikePublicDns
import com.payphone.android.transport.resolveServer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.parcelize.Parcelize

class PayphoneVpnService : VpnService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var engine: TunnelEngine? = null
    private var transport: FrameTransport? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val settings = (if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(EXTRA_SETTINGS, PayphoneVpnConfig::class.java)
                    else @Suppress("DEPRECATION") (intent.getParcelableExtra(EXTRA_SETTINGS) as? PayphoneVpnConfig))
                    ?: return START_NOT_STICKY
                startForeground(NOTIFICATION_ID, buildNotification("Jack in…"))
                serviceScope.launch { connect(settings) }
            }
            ACTION_DISCONNECT -> disconnect()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        disconnect()
        serviceScope.cancel()
        instance = null
        super.onDestroy()
    }

    override fun onRevoke() {
        disconnect()
        super.onRevoke()
    }

    private suspend fun connect(config: PayphoneVpnConfig) {
        _state.value = VpnUiState(statusLine = "What's up, dude?")
        try {
            ObfuscationKey.validatePassphrase(config.psk)
            val token = config.token
            require(token.size == 135) { "subscription token must be 135 bytes" }
            val sessionStore = SessionStore(this)
            val saved = sessionStore.load()
            val obfs = ObfuscationKey(config.psk)
            val client = PayphoneClient(token, obfs)
            val (host, _) = resolveServer(config.server)
            val sni = config.serverName.ifBlank {
                if (looksLikePublicDns(host)) host else "localhost"
            }
            val trust = TlsTrustConfig(
                serverName = sni,
                pinnedCert = config.pinnedCert,
            )
            val (frameTransport, handshake) = client.connect(
                server = config.server,
                transport = config.transport,
                tlsTrust = trust,
                saved = saved,
                protect = { socket -> protect(socket) },
            )
            transport = frameTransport
            when (handshake) {
                is HandshakeResult.Connected -> {
                    sessionStore.save(handshake.session.sessionId, handshake.resumeToken)
                    _state.value = _state.value.copy(
                        statusLine = "Still good, dude.",
                        assignedIp = formatIp(handshake.session.assignedIpv4),
                    )
                    val tunnel = TunnelEngine(
                        scope = serviceScope,
                        vpnService = this,
                        session = handshake.session,
                        serverHost = host,
                        transport = frameTransport,
                        sessionStore = sessionStore,
                        onTerminated = { line ->
                            _state.value = _state.value.copy(connected = false, statusLine = line)
                            stopSelf()
                        },
                        onStats = { rx, tx ->
                            _state.value = _state.value.copy(rxBytes = rx, txBytes = tx)
                        },
                        onStatus = { line ->
                            _state.value = _state.value.copy(statusLine = line)
                        },
                    )
                    engine = tunnel
                    if (!tunnel.start()) {
                        _state.value = _state.value.copy(
                            connected = false,
                            statusLine = "TUN failed — need VPN permission?",
                        )
                        stopSelf()
                        return
                    }
                    _state.value = _state.value.copy(connected = true)
                    startForeground(NOTIFICATION_ID, buildNotification("Tunnel up · ${formatIp(handshake.session.assignedIpv4)}"))
                }
                is HandshakeResult.Denied -> {
                    sessionStore.clear()
                    _state.value = _state.value.copy(
                        connected = false,
                        statusLine = "Access denied, dude. (${handshake.reason})",
                    )
                    stopSelf()
                }
                is HandshakeResult.Error -> {
                    _state.value = _state.value.copy(
                        connected = false,
                        statusLine = handshake.message,
                    )
                    stopSelf()
                }
            }
        } catch (error: Throwable) {
            _state.value = _state.value.copy(
                connected = false,
                statusLine = error.message ?: "Connection failed",
            )
            stopSelf()
        }
    }

    private fun disconnect() {
        engine?.stop()
        engine = null
        transport?.close()
        transport = null
        _state.value = VpnUiState(statusLine = "Unplugged.")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun buildNotification(text: String): Notification {
        val pending = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pending)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "PAYPHONE VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.vpn_notification_text)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun formatIp(bytes: ByteArray): String =
        bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }

    companion object {
        const val ACTION_CONNECT = "com.payphone.android.CONNECT"
        const val ACTION_DISCONNECT = "com.payphone.android.DISCONNECT"
        const val EXTRA_SETTINGS = "settings"

        private const val CHANNEL_ID = "payphone_vpn"
        private const val NOTIFICATION_ID = 40404

        private val _state = MutableStateFlow(VpnUiState())
        val state: StateFlow<VpnUiState> = _state.asStateFlow()

        @Volatile
        var instance: PayphoneVpnService? = null

        fun disconnectFromUi(context: Context) {
            context.startService(
                Intent(context, PayphoneVpnService::class.java).apply {
                    action = ACTION_DISCONNECT
                },
            )
        }
    }
}

data class VpnUiState(
    val connected: Boolean = false,
    val statusLine: String = "Follow the white rabbit.",
    val assignedIp: String = "",
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
)

/** Parcelable config for service intent — keep small. */
@Parcelize
data class PayphoneVpnConfig(
    val server: String,
    val psk: String,
    val transport: com.payphone.android.transport.TransportKind,
    val serverName: String,
    val token: ByteArray,
    val pinnedCert: ByteArray?,
) : Parcelable {
    companion object {
        fun from(settings: PayphoneSettings): PayphoneVpnConfig {
            val token = settings.tokenBytes()
                ?: error("subscription token missing")
            return PayphoneVpnConfig(
                server = settings.server,
                psk = settings.psk,
                transport = settings.transport,
                serverName = settings.serverName,
                token = token,
                pinnedCert = settings.pinnedCertBytes(),
            )
        }
    }
}
