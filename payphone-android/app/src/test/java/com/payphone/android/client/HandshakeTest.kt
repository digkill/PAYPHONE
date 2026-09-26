package com.payphone.android.client

import com.payphone.android.protocol.*
import com.payphone.android.transport.ObfuscationKey
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class HandshakeTest {
    private val id = ByteArray(16) { 1 }
    private val nonce = ByteArray(32) { 2 }
    private val client = PayphoneClient(ByteArray(135), ObfuscationKey("test-passphrase-123456"))
    private class Scripted(vararg frames: Frame) : FrameTransport {
        val responses = ArrayDeque(frames.toList())
        val sent = mutableListOf<Frame>()
        override suspend fun send(frame: Frame) { sent += frame }
        override suspend fun receive(): Frame = responses.removeFirst()
        override fun close() {}
    }
    private fun frame(type: FrameType, payload: ByteArray) = Frame(1, type, 0, 1, payload)
    @Test fun freshSessionSavesRotatedNonce() = runTest {
        val transport = Scripted(
            frame(FrameType.AllGoodDude, byteArrayOf(1) + id + byteArrayOf(10,77,0,2,4,76,0,0,0,1) + ByteArray(32) { 3 }),
            frame(FrameType.Rekey, id + nonce),
        )
        val result = client.createNewSession(transport) as HandshakeResult.Connected
        assertArrayEquals(nonce, result.resumeToken)
        assertArrayEquals(id + nonce, transport.sent.last().payload)
    }
    @Test fun resumeSavesRotatedNonce() = runTest {
        val transport = Scripted(
            frame(FrameType.StillGoodDude, id + byteArrayOf(10,77,0,2,4,76,0,0,0,1)),
            frame(FrameType.Rekey, id + nonce),
        )
        val result = client.tryResume(transport, SavedSession(id, ByteArray(32) { 3 })) as HandshakeResult.Connected
        assertArrayEquals(nonce, result.resumeToken)
    }
    @Test fun unknownSessionFallsBackButRevocationIsTerminal() = runTest {
        val saved = SavedSession(id, nonce)
        assertNull(client.tryResume(Scripted(frame(FrameType.AccessDeniedDude, byteArrayOf(1) + ByteArray(8))), saved))
        val result = client.tryResume(Scripted(frame(FrameType.AccessDeniedDude, byteArrayOf(3) + ByteArray(8))), saved)
        assertEquals(DenyReason.TokenRevoked, (result as HandshakeResult.Denied).reason)
    }
}
