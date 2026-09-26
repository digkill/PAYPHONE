package com.payphone.android.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.payphone.android.client.SavedSession
import com.payphone.android.protocol.ProtocolConstants
import java.security.MessageDigest
import java.util.Base64

class SessionStore(context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun load(): SavedSession? {
        val session = prefs.getString(KEY_SESSION, null) ?: return null
        val resume = prefs.getString(KEY_RESUME, null) ?: return null
        val sessionBytes = Base64.getDecoder().decode(session)
        val resumeBytes = Base64.getDecoder().decode(resume)
        if (sessionBytes.size != ProtocolConstants.SESSION_ID_SIZE ||
            resumeBytes.size != ProtocolConstants.SERVER_NONCE_SIZE
        ) {
            clear()
            return null
        }
        return SavedSession(sessionBytes, resumeBytes)
    }

    fun save(sessionId: ByteArray, resumeToken: ByteArray) {
        prefs.edit()
            .putString(KEY_SESSION, Base64.getEncoder().encodeToString(sessionId))
            .putString(KEY_RESUME, Base64.getEncoder().encodeToString(resumeToken))
            .apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val PREFS_NAME = "payphone_session"
        private const val KEY_SESSION = "session_id"
        private const val KEY_RESUME = "resume_token"

        fun deriveLegacyKey(psk: String): ByteArray =
            MessageDigest.getInstance("SHA-256")
                .digest("payphone-session-v1".toByteArray() + psk.toByteArray())
    }
}
