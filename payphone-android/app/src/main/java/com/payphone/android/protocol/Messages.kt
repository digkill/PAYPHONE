package com.payphone.android.protocol

import java.security.SecureRandom

object Messages {
    data class WhatsUpDude(
        val clientVersion: Int,
        val capabilities: Int,
        val clientNonce: ByteArray,
        val authToken: ByteArray,
    ) {
        fun encode(): ByteArray {
            require(authToken.size <= 2048)
            val out = ByteArray(41 + authToken.size)
            out[0] = ProtocolConstants.VERSION.toByte()
            writeU16(out, 1, clientVersion)
            writeU32(out, 3, capabilities)
            clientNonce.copyInto(out, 7)
            writeU16(out, 39, authToken.size)
            authToken.copyInto(out, 41)
            return out
        }

        companion object {
            fun new(clientVersion: Int, capabilities: Int, authToken: ByteArray): WhatsUpDude {
                val nonce = ByteArray(32)
                SecureRandom().nextBytes(nonce)
                return WhatsUpDude(clientVersion, capabilities, nonce, authToken)
            }
        }
    }

    data class AllGoodDude(
        val sessionId: ByteArray,
        val assignedIpv4: ByteArray,
        val mtu: Int,
        val capabilities: Int,
        val serverNonce: ByteArray,
    ) {
        companion object {
            fun decode(payload: ByteArray): AllGoodDude {
                require(payload.size == 59)
                return AllGoodDude(
                    sessionId = payload.copyOfRange(1, 17),
                    assignedIpv4 = payload.copyOfRange(17, 21),
                    mtu = readU16(payload, 21),
                    capabilities = readU32(payload, 23),
                    serverNonce = payload.copyOfRange(27, 59),
                )
            }
        }
    }

    data class StillGoodDude(
        val sessionId: ByteArray,
        val assignedIpv4: ByteArray,
        val mtu: Int,
        val capabilities: Int,
    ) {
        companion object {
            fun decode(payload: ByteArray): StillGoodDude {
                require(payload.size == 26)
                return StillGoodDude(
                    sessionId = payload.copyOfRange(0, 16),
                    assignedIpv4 = payload.copyOfRange(16, 20),
                    mtu = readU16(payload, 20),
                    capabilities = readU32(payload, 22),
                )
            }
        }
    }

    data class BackAgainDude(val sessionId: ByteArray, val resumeToken: ByteArray) {
        fun encode(): ByteArray {
            require(sessionId.size == 16 && resumeToken.size == 32)
            return sessionId + resumeToken
        }
    }

    data class AccessDeniedDude(val reason: DenyReason, val expiresAt: Long) {
        companion object {
            fun decode(payload: ByteArray): AccessDeniedDude {
                require(payload.size == 9)
                val reason = DenyReason.fromWire(payload[0].toInt() and 0xFF)
                    ?: error("unknown deny reason")
                val expiresAt = readU64(payload, 1)
                return AccessDeniedDude(reason, expiresAt)
            }
        }
    }

    data class Data(val sessionId: ByteArray, val packetId: Long, val ipPacket: ByteArray) {
        fun encode(): ByteArray {
            val out = ByteArray(ProtocolConstants.DATA_HEADER_SIZE + ipPacket.size)
            sessionId.copyInto(out, 0)
            writeU64(out, 16, packetId)
            ipPacket.copyInto(out, ProtocolConstants.DATA_HEADER_SIZE)
            return out
        }

        companion object {
            fun decode(payload: ByteArray): Data {
                require(payload.size >= ProtocolConstants.DATA_HEADER_SIZE)
                return Data(
                    sessionId = payload.copyOfRange(0, 16),
                    packetId = readU64(payload, 16),
                    ipPacket = payload.copyOfRange(ProtocolConstants.DATA_HEADER_SIZE, payload.size),
                )
            }
        }
    }

    data class Ping(val sessionId: ByteArray, val pingId: Long) {
        fun encode(): ByteArray {
            val out = ByteArray(24)
            sessionId.copyInto(out, 0)
            writeU64(out, 16, pingId)
            return out
        }
    }

    data class Pong(val sessionId: ByteArray, val pingId: Long) {
        fun encode(): ByteArray {
            val out = ByteArray(24)
            sessionId.copyInto(out, 0)
            writeU64(out, 16, pingId)
            return out
        }

        companion object {
            fun decode(payload: ByteArray): Pong {
                require(payload.size == 24)
                return Pong(payload.copyOfRange(0, 16), readU64(payload, 16))
            }
        }
    }

    sealed class Rekey {
        data class Request(val sessionId: ByteArray) : Rekey() {
            fun encode(): ByteArray = sessionId.copyOf()
        }

        data class Token(val sessionId: ByteArray, val nonce: ByteArray) : Rekey() {
            fun encode(): ByteArray = sessionId + nonce
        }

        companion object {
            fun decode(payload: ByteArray): Rekey = when (payload.size) {
                16 -> Request(payload.copyOf())
                48 -> Token(payload.copyOfRange(0, 16), payload.copyOfRange(16, 48))
                else -> error("invalid rekey length")
            }
        }
    }

    data class Close(val sessionId: ByteArray, val reason: CloseReason) {
        fun encode(): ByteArray {
            val out = ByteArray(17)
            sessionId.copyInto(out, 0)
            out[16] = reason.wire.toByte()
            return out
        }
    }
}
