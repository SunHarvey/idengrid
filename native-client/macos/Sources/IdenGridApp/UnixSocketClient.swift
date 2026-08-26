import Darwin
import Foundation

enum UnixSocketClient {
    private static let maximumResponseBytes = 1_048_576

    static func request(path: String, payload: String) throws -> Data {
        let pathBytes = Array(path.utf8CString)
        var address = sockaddr_un()
        guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw UnixSocketError.pathTooLong
        }

        let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw posixError() }
        defer { Darwin.close(descriptor) }

        var noSignal: Int32 = 1
        guard setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &noSignal,
            socklen_t(MemoryLayout<Int32>.size)
        ) == 0 else { throw posixError() }

        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        guard setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        ) == 0 else { throw posixError() }

        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            pathBytes.withUnsafeBytes { source in
                destination.copyBytes(from: source)
            }
        }

        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(
                    descriptor,
                    $0,
                    socklen_t(MemoryLayout<sockaddr_un>.size)
                )
            }
        }
        guard connected == 0 else { throw posixError() }

        try sendAll(Data(payload.utf8), to: descriptor)
        return try readLine(from: descriptor)
    }

    private static func sendAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var sent = 0
            while sent < rawBuffer.count {
                let count = Darwin.send(
                    descriptor,
                    base.advanced(by: sent),
                    rawBuffer.count - sent,
                    0
                )
                if count > 0 {
                    sent += count
                } else if count < 0, errno == EINTR {
                    continue
                } else {
                    throw posixError()
                }
            }
        }
    }

    private static func readLine(from descriptor: Int32) throws -> Data {
        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while response.count < maximumResponseBytes {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count > 0 {
                response.append(contentsOf: buffer.prefix(count))
                if let newline = response.firstIndex(of: 0x0A) {
                    return Data(response.prefix(upTo: newline))
                }
            } else if count < 0, errno == EINTR {
                continue
            } else if count == 0 {
                throw UnixSocketError.closedBeforeResponse
            } else {
                throw posixError()
            }
        }
        throw UnixSocketError.responseTooLarge
    }

    private static func posixError() -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
}

enum UnixSocketError: LocalizedError, Sendable {
    case pathTooLong
    case closedBeforeResponse
    case responseTooLarge

    var errorDescription: String? {
        switch self {
        case .pathTooLong: return "Agent Socket路径过长"
        case .closedBeforeResponse: return "Agent未返回完整状态"
        case .responseTooLarge: return "Agent状态响应过大"
        }
    }
}
