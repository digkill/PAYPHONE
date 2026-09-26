package com.payphone.android.protocol

object ProtocolConstants {
    const val VERSION: Int = 1
    const val HEADER_SIZE: Int = 16
    const val MAX_PAYLOAD_SIZE: Int = 64 * 1024
    const val DEFAULT_UDP_PORT: Int = 40404
    const val DEFAULT_TCP_PORT: Int = 40443
    const val CLIENT_VERSION: Int = 1
    const val SESSION_ID_SIZE: Int = 16
    const val SERVER_NONCE_SIZE: Int = 32
    const val DATA_HEADER_SIZE: Int = 24
    const val PAYPHONE_MTU: Int = 1100
    const val SUBSCRIPTION_TOKEN_SIZE: Int = 135
}

enum class FrameType(val wire: Int) {
    Data(1),
    WhatsUpDude(2),
    AllGoodDude(3),
    Ping(4),
    Pong(5),
    Rekey(6),
    Close(7),
    BackAgainDude(8),
    StillGoodDude(9),
    AccessDeniedDude(10);

    companion object {
        fun fromWire(value: Int): FrameType? = entries.find { it.wire == value }
    }
}

object Capabilities {
    const val IPV4: Int = 1 shl 0
    const val IPV6: Int = 1 shl 1
    const val DNS: Int = 1 shl 2
    const val RESUME: Int = 1 shl 3
    const val ROAMING: Int = 1 shl 4

    val CLIENT: Int = IPV4 or IPV6 or DNS or RESUME or ROAMING
}

enum class DenyReason(val wire: Int) {
    InvalidToken(1),
    SubscriptionExpired(2),
    TokenRevoked(3),
    SubscriptionNotActive(4),
    UnknownSigningKey(5),
    UnsupportedPlan(6),
    InternalAuthError(7),
    DeviceLimitReached(8);

    companion object {
        fun fromWire(value: Int): DenyReason? = entries.find { it.wire == value }
    }
}

enum class CloseReason(val wire: Int) {
    ClientShutdown(0),
    ServerShutdown(1),
    Replaced(2);

    companion object {
        fun fromWire(value: Int): CloseReason? = entries.find { it.wire == value }
    }
}

data class Frame(
    val version: Int,
    val type: FrameType,
    val flags: Int,
    val sequence: Long,
    val payload: ByteArray,
) {
    fun encode(): ByteArray {
        require(payload.size <= ProtocolConstants.MAX_PAYLOAD_SIZE)
        val out = ByteArray(ProtocolConstants.HEADER_SIZE + payload.size)
        out[0] = version.toByte()
        out[1] = type.wire.toByte()
        writeU16(out, 2, flags)
        writeU32(out, 4, payload.size)
        writeU64(out, 8, sequence)
        payload.copyInto(out, ProtocolConstants.HEADER_SIZE)
        return out
    }

    companion object {
        fun decode(data: ByteArray): Frame {
            require(data.size >= ProtocolConstants.HEADER_SIZE) { "frame too small" }
            val version = data[0].toInt() and 0xFF
            require(version == ProtocolConstants.VERSION) { "unsupported version $version" }
            val type = FrameType.fromWire(data[1].toInt() and 0xFF)
                ?: error("unknown frame type ${data[1]}")
            val flags = readU16(data, 2)
            val payloadLen = readU32(data, 4)
            require(payloadLen <= ProtocolConstants.MAX_PAYLOAD_SIZE) { "payload too large" }
            require(data.size == ProtocolConstants.HEADER_SIZE + payloadLen) {
                "invalid payload length"
            }
            val sequence = readU64(data, 8)
            val payload = data.copyOfRange(ProtocolConstants.HEADER_SIZE, data.size)
            return Frame(version, type, flags, sequence, payload)
        }

        fun payloadLenFromHeader(header: ByteArray): Int {
            require(header.size >= ProtocolConstants.HEADER_SIZE)
            require(header[0].toInt() and 0xFF == ProtocolConstants.VERSION)
            val len = readU32(header, 4)
            require(len <= ProtocolConstants.MAX_PAYLOAD_SIZE)
            return len
        }
    }
}

internal fun readU16(data: ByteArray, offset: Int): Int =
    ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

internal fun readU32(data: ByteArray, offset: Int): Int =
    ((data[offset].toInt() and 0xFF) shl 24) or
        ((data[offset + 1].toInt() and 0xFF) shl 16) or
        ((data[offset + 2].toInt() and 0xFF) shl 8) or
        (data[offset + 3].toInt() and 0xFF)

internal fun readU64(data: ByteArray, offset: Int): Long {
    var value = 0L
    for (index in 0 until 8) {
        value = (value shl 8) or (data[offset + index].toLong() and 0xFF)
    }
    return value
}

internal fun writeU16(out: ByteArray, offset: Int, value: Int) {
    out[offset] = ((value shr 8) and 0xFF).toByte()
    out[offset + 1] = (value and 0xFF).toByte()
}

internal fun writeU32(out: ByteArray, offset: Int, value: Int) {
    out[offset] = ((value shr 24) and 0xFF).toByte()
    out[offset + 1] = ((value shr 16) and 0xFF).toByte()
    out[offset + 2] = ((value shr 8) and 0xFF).toByte()
    out[offset + 3] = (value and 0xFF).toByte()
}

internal fun writeU64(out: ByteArray, offset: Int, value: Long) {
    for (index in 7 downTo 0) {
        out[offset + index] = ((value shr ((7 - index) * 8)) and 0xFF).toByte()
    }
}
