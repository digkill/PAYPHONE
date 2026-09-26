package com.payphone.android.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.payphone.android.transport.TransportKind
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.util.Base64

private val Context.settingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "payphone_settings",
)

data class PayphoneSettings(
    val server: String = "127.0.0.1:40404",
    val psk: String = "",
    val transport: TransportKind = TransportKind.Tls,
    val serverName: String = "",
    val pinnedCertBase64: String = "",
    val tokenBase64: String = "",
)

class SettingsRepository(private val context: Context) {
    private val dataStore = context.settingsDataStore

    val settings: Flow<PayphoneSettings> = dataStore.data.map { prefs ->
        PayphoneSettings(
            server = prefs[Keys.SERVER] ?: "127.0.0.1:40404",
            psk = prefs[Keys.PSK] ?: "",
            transport = runCatching {
                TransportKind.valueOf(prefs[Keys.TRANSPORT] ?: TransportKind.Tls.name)
            }.getOrDefault(TransportKind.Tls),
            serverName = prefs[Keys.SNI] ?: "",
            pinnedCertBase64 = prefs[Keys.PIN] ?: "",
            tokenBase64 = prefs[Keys.TOKEN] ?: "",
        )
    }

    suspend fun update(transform: (PayphoneSettings) -> PayphoneSettings) {
        dataStore.edit { prefs ->
            val current = PayphoneSettings(
                server = prefs[Keys.SERVER] ?: "127.0.0.1:40404",
                psk = prefs[Keys.PSK] ?: "",
                transport = runCatching {
                    TransportKind.valueOf(prefs[Keys.TRANSPORT] ?: TransportKind.Tls.name)
                }.getOrDefault(TransportKind.Tls),
                serverName = prefs[Keys.SNI] ?: "",
                pinnedCertBase64 = prefs[Keys.PIN] ?: "",
                tokenBase64 = prefs[Keys.TOKEN] ?: "",
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
