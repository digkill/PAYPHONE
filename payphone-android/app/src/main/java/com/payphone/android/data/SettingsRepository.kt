package com.payphone.android.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.payphone.android.transport.TransportKind
import com.payphone.android.BuildConfig
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.util.Base64

private val Context.settingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "payphone_settings",
)

data class PayphoneSettings(
    val server: String = BuildConfig.DEFAULT_SERVER,
    val psk: String = BuildConfig.DEFAULT_PSK,
    val transport: TransportKind = TransportKind.Quic,
    val serverName: String = BuildConfig.DEFAULT_SERVER_NAME,
    val pinnedCertBase64: String = "",
    val tokenBase64: String = BuildConfig.DEFAULT_TOKEN_BASE64,
)

class SettingsRepository(private val context: Context) {
    private val dataStore = context.settingsDataStore

    private val defaults by lazy {
        PayphoneSettings(
            server = BuildConfig.DEFAULT_SERVER,
            psk = BuildConfig.DEFAULT_PSK,
            transport = TransportKind.Quic,
            serverName = BuildConfig.DEFAULT_SERVER_NAME,
            pinnedCertBase64 = Base64.getEncoder().encodeToString(
                context.resources.openRawResource(com.payphone.android.R.raw.payphone_server_cert)
                    .use { it.readBytes() },
            ),
            tokenBase64 = BuildConfig.DEFAULT_TOKEN_BASE64,
        )
    }

    val settings: Flow<PayphoneSettings> = dataStore.data.map { prefs ->
        PayphoneSettings(
            server = prefs[Keys.SERVER] ?: defaults.server,
            psk = prefs[Keys.PSK] ?: defaults.psk,
            transport = runCatching {
                TransportKind.valueOf(prefs[Keys.TRANSPORT] ?: defaults.transport.name)
            }.getOrDefault(defaults.transport),
            serverName = prefs[Keys.SNI] ?: defaults.serverName,
            pinnedCertBase64 = prefs[Keys.PIN] ?: defaults.pinnedCertBase64,
            tokenBase64 = prefs[Keys.TOKEN] ?: defaults.tokenBase64,
        )
    }

    suspend fun update(transform: (PayphoneSettings) -> PayphoneSettings) {
        dataStore.edit { prefs ->
            val current = PayphoneSettings(
                server = prefs[Keys.SERVER] ?: defaults.server,
                psk = prefs[Keys.PSK] ?: defaults.psk,
                transport = runCatching {
                    TransportKind.valueOf(prefs[Keys.TRANSPORT] ?: defaults.transport.name)
                }.getOrDefault(defaults.transport),
                serverName = prefs[Keys.SNI] ?: defaults.serverName,
                pinnedCertBase64 = prefs[Keys.PIN] ?: defaults.pinnedCertBase64,
                tokenBase64 = prefs[Keys.TOKEN] ?: defaults.tokenBase64,
            )
            val next = transform(current)
            prefs[Keys.SERVER] = next.server
            prefs[Keys.PSK] = next.psk
            prefs[Keys.TRANSPORT] = next.transport.name
            prefs[Keys.SNI] = next.serverName
            prefs[Keys.PIN] = next.pinnedCertBase64
            prefs[Keys.TOKEN] = next.tokenBase64
        }
    }

    private object Keys {
        val SERVER = stringPreferencesKey("server")
        val PSK = stringPreferencesKey("psk")
        val TRANSPORT = stringPreferencesKey("transport")
        val SNI = stringPreferencesKey("sni")
        val PIN = stringPreferencesKey("pin")
        val TOKEN = stringPreferencesKey("token")
    }
}

fun PayphoneSettings.tokenBytes(): ByteArray? {
    if (tokenBase64.isBlank()) return null
    return runCatching { Base64.getDecoder().decode(tokenBase64.trim()) }.getOrNull()
}

fun PayphoneSettings.pinnedCertBytes(): ByteArray? {
    if (pinnedCertBase64.isBlank()) return null
    return runCatching { Base64.getDecoder().decode(pinnedCertBase64.trim()) }.getOrNull()
}
