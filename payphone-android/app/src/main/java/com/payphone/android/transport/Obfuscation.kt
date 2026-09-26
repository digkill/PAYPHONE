package com.payphone.android.transport

import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.random.Random

/**
 * UDP obfuscation layer matching `payphone_transport::obfuscation`.
 * Not encryption — QUIC/TLS already protect confidentiality.
 */
class ObfuscationKey(passphrase: String) {
    private val key: ByteArray = MessageDigest.getInstance("SHA-256")
        .digest(passphrase.toByteArray(Charsets.UTF_8))

    fun obfuscate(payload: ByteArray): ByteArray {
        val padLen = Random.nextInt(0, MAX_PADDING + 1)
        val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        val stream = keystream(salt)
        val payloadLen = payload.size
        require(payloadLen <= 0xFFFF)
        val plaintext = ByteArray(LENGTH_PREFIX + payloadLen + padLen)
        plaintext[0] = ((payloadLen shr 8) and 0xFF).toByte()
        plaintext[1] = (payloadLen and 0xFF).toByte()
        payload.copyInto(plaintext, LENGTH_PREFIX)
        if (padLen > 0) {
            val pad = ByteArray(padLen).also { SecureRandom().nextBytes(it) }
            pad.copyInto(plaintext, LENGTH_PREFIX + payloadLen)
        }
        val xored = ByteArray(plaintext.size)
        for (index in plaintext.indices) {
            xored[index] = (plaintext[index].toInt() xor stream[index % KEY_LEN].toInt()).toByte()
        }
        return salt + xored
    }

    fun deobfuscate(data: ByteArray): ByteArray? {
        if (data.size < SALT_LEN + LENGTH_PREFIX) return null
        val salt = data.copyOfRange(0, SALT_LEN)
        val stream = keystream(salt)
        val body = data.copyOfRange(SALT_LEN, data.size)
        val plain = ByteArray(body.size)
        for (index in body.indices) {
            plain[index] = (body[index].toInt() xor stream[index % KEY_LEN].toInt()).toByte()
        }
        val payloadLen = ((plain[0].toInt() and 0xFF) shl 8) or (plain[1].toInt() and 0xFF)
        val end = LENGTH_PREFIX + payloadLen
        if (end > plain.size) return null
        return plain.copyOfRange(LENGTH_PREFIX, end)
    }

    private fun keystream(salt: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(key)
        digest.update(salt)
        return digest.digest()
    }

    companion object {
        private const val SALT_LEN = 8
        private const val KEY_LEN = 32
        private const val LENGTH_PREFIX = 2
        private const val MAX_PADDING = 32
        private const val PLACEHOLDER = "change-me-to-a-real-random-secret"

        fun validatePassphrase(passphrase: String) {
            require(passphrase != PLACEHOLDER) {
                "PAYPHONE_OBFS_PSK is still the placeholder from .env.example"
            }
            require(passphrase.length >= 16) {
                "PAYPHONE_OBFS_PSK must be at least 16 characters"
            }
        }
    }
}
