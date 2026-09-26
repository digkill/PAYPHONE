package com.payphone.android.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class FrameTest {
    @Test
    fun frameRoundtrip() {
        val payload = "hello payphone".toByteArray()
        val original = Frame(
            version = ProtocolConstants.VERSION,
            type = FrameType.Data,
            flags = 0,
            sequence = 42,
            payload = payload,
        )
        val encoded = original.encode()
        val decoded = Frame.decode(encoded)
        assertEquals(original.version, decoded.version)
        assertEquals(original.type, decoded.type)
        assertEquals(original.sequence, decoded.sequence)
        assertArrayEquals(original.payload, decoded.payload)
    }

    @Test
    fun whatsUpDudeInsideFrame() {
        val token = ByteArray(135) { 0xAB.toByte() }
        val message = Messages.WhatsUpDude.new(1, Capabilities.CLIENT, token)
        val frame = Frame(
            ProtocolConstants.VERSION,
            FrameType.WhatsUpDude,
            0,
            1,
            message.encode(),
        )
        val decoded = Frame.decode(frame.encode())
        assertEquals(FrameType.WhatsUpDude, decoded.type)
        assertEquals(41 + 135, decoded.payload.size)
    }
}
