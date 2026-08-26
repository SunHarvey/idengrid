import Foundation

@main
struct UnixSocketContractMain {
    private static func require(
        _ condition: @autoclosure () -> Bool,
        _ message: String
    ) {
        guard condition() else {
            FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
            exit(1)
        }
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            FileHandle.standardError.write(Data("FAIL: socket path required\n".utf8))
            exit(2)
        }

        let started = Date()
        let data = try UnixSocketClient.request(
            path: CommandLine.arguments[1],
            payload: "{\"capability\":\"test-capability\",\"command\":\"status\"}\n"
        )
        let elapsed = Date().timeIntervalSince(started)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        require(object?["status"] as? String == "connected", "status response")
        require(object?["socks_port"] as? Int == 55_233, "SOCKS port response")
        require(elapsed < 1.0, "client waited for EOF instead of newline")
        print("Swift Unix Socket contract test passed")
    }
}
