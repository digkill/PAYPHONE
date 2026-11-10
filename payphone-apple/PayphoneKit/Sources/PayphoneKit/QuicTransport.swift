import Foundation
#if canImport(CPayphoneNative)
import CPayphoneNative
#endif

public enum QuicTransportError: Error, CustomStringConvertible, Sendable {
    case nativeLibraryMissing
    case connectionFailed
    case controlFrameTooLarge

    public var description: String {
        switch self {
        case .nativeLibraryMissing: return "QUIC is unavailable in this build. Select TLS or install a build with QUIC support."
        case .connectionFailed: return "QUIC connection failed. Check the server settings and network."
        case .controlFrameTooLarge: return "The QUIC connection cannot carry a session control message."
        }
    }
}

/// QUIC datagrams + PAYPHONE obfuscation from the same Rust crate as the desktop client.
public final class QuicFrameChannel: FrameTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let receiveQueue = DispatchQueue(label: "payphone.quic.receive", qos: .userInitiated)
    private var receiveBuffer = [UInt8](repeating: 0, count: 65535)
    private var handle: UInt64
    private init(handle: UInt64) { self.handle = handle }
    private func currentHandle() -> UInt64 { lock.withLock { handle } }

    public var remoteIPv4: String? {
        #if canImport(CPayphoneNative)
        let ip = pp_remote_ipv4(currentHandle())
        guard ip != 0 else { return nil }
        return [24, 16, 8, 0].map { String((ip >> $0) & 255) }.joined(separator: ".")
        #else
        return nil
        #endif
    }

    public static func connect(host: String, port: UInt16, trust: TlsTrustConfig, key: ObfuscationKey) async throws -> QuicFrameChannel {
        #if canImport(CPayphoneNative)
        let bytes = key.derivedBytes
        let pin = trust.pinnedCertDER ?? []
        let handle = bytes.withUnsafeBufferPointer { k in
            pin.withUnsafeBufferPointer { p in pp_open(k.baseAddress, p.baseAddress, p.count) }
        }
        guard handle != 0 else { throw QuicTransportError.connectionFailed }
        let channel = QuicFrameChannel(handle: handle)
        do {
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    DispatchQueue.global(qos: .userInitiated).async {
                        let address = Array("\(host):\(port)".utf8)
                        let sni = Array(trust.serverName.utf8)
                        let result = address.withUnsafeBufferPointer { a in
                            sni.withUnsafeBufferPointer { s in pp_connect(handle, a.baseAddress, a.count, s.baseAddress, s.count) }
                        }
                        if result == 1 { continuation.resume(returning: channel) }
                        else { continuation.resume(throwing: QuicTransportError.connectionFailed) }
                    }
                }
            } onCancel: { channel.close() }
        } catch { channel.close(); throw error }
        #else
        throw QuicTransportError.nativeLibraryMissing
        #endif
    }

    public func send(_ frame: Frame) async throws {
        try Task.checkCancellation()
        #if canImport(CPayphoneNative)
        let bytes = try frame.encode()
        let result = bytes.withUnsafeBufferPointer { b in pp_send(currentHandle(), b.baseAddress, b.count) }
        guard result >= 0 else { throw PayphoneError.streamClosed }
        if result == 0 && frame.type != .data { throw QuicTransportError.controlFrameTooLarge }
        #else
        throw QuicTransportError.nativeLibraryMissing
        #endif
    }

    public func receive() async throws -> Frame {
        #if canImport(CPayphoneNative)
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                receiveQueue.async {
                    while true {
                        let size = self.receiveBuffer.withUnsafeMutableBufferPointer { b in pp_receive(self.currentHandle(), b.baseAddress, b.count) }
                        if size < 0 { continuation.resume(throwing: PayphoneError.streamClosed); return }
                        if size > 0 {
                            do { continuation.resume(returning: try Frame.decode(Array(self.receiveBuffer.prefix(Int(size))))) }
                            catch { continuation.resume(throwing: error) }
                            return
                        }
                    }
                }
            }
        } onCancel: { self.close() }
        #else
        throw QuicTransportError.nativeLibraryMissing
        #endif
    }

    public func close() {
        #if canImport(CPayphoneNative)
        let old = lock.withLock { let old = handle; handle = 0; return old }
        if old != 0 { pp_close(old) }
        #endif
    }
    deinit { close() }
}
