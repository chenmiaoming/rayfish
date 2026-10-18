import Foundation
import NetworkExtension

enum TunnelState: Equatable {
    case off, connecting, on, disconnecting

    var isTransitioning: Bool { self == .connecting || self == .disconnecting }
}

/// Where the node runs, and how the app reaches it.
@MainActor
protocol Tunnel: AnyObject {
    var state: TunnelState { get }
    var onChange: (() -> Void)? { get set }
    /// The node in this process. Unstarted on a device: it answers from the
    /// saved config, and backs up or restores the identity while the tunnel is off.
    var local: NodeHost { get }
    func load() async
    func connect() async throws
    func disconnect() async
    func send(_ command: Command) async throws -> Reply
}

enum TunnelError: LocalizedError {
    case timedOut, noResponse
    case node(String)

    var errorDescription: String? {
        switch self {
        case .timedOut: "Rayfish did not answer in time"
        case .noResponse: "Rayfish returned no response"
        case .node(let message): message
        }
    }
}

extension NodeHost {
    /// Run a command off the main thread, with the core's errors in words.
    func run(_ command: Command) async throws -> Reply {
        try await Task.detached(priority: .userInitiated) {
            do {
                return try self.handle(command)
            } catch let error as RayError {
                throw TunnelError.node(userMessage(error))
            }
        }.value
    }
}

/// The real thing: the node lives in the packet tunnel extension and the app
/// talks to it with provider messages while the VPN is connected.
@MainActor
final class DeviceTunnel: Tunnel {
    private(set) var state = TunnelState.off
    var onChange: (() -> Void)?
    let local: NodeHost
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    init(local: NodeHost) {
        self.local = local
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.update() }
        }
    }

    func load() async {
        do {
            manager = try await NETunnelProviderManager.loadAllFromPreferences().first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == AppGroup.tunnelBundleIdentifier
            }
        } catch {
            RayfishLog.app.error("Loading VPN preferences failed: \(error.localizedDescription, privacy: .public)")
        }
        update()
    }

    /// Connecting also turns on-demand on, so iOS brings the tunnel back after
    /// a reboot or when it stops the extension, like an always-on VPN.
    func connect() async throws {
        let manager = try await configuredManager(onDemand: true)
        try manager.connection.startVPNTunnel()
        update()
    }

    /// On-demand goes off first: otherwise iOS restarts the tunnel right away.
    func disconnect() async {
        if let manager, manager.isOnDemandEnabled {
            do {
                _ = try await configuredManager(onDemand: false)
            } catch {
                RayfishLog.app.error("Turning off on-demand failed: \(error.localizedDescription, privacy: .public)")
            }
        }
        manager?.connection.stopVPNTunnel()
        update()
    }

    func send(_ command: Command) async throws -> Reply {
        guard state == .on, let session = manager?.connection as? NETunnelProviderSession else {
            return try await local.run(command)
        }
        let data = try JSONEncoder().encode(command)
        let reply = try await ProviderMessage.send(data, timeout: command.timeout) { data, handler in
            try session.sendProviderMessage(data, responseHandler: handler)
        }
        let decoded = try JSONDecoder().decode(Reply.self, from: reply)
        if let error = decoded.error { throw TunnelError.node(error) }
        return decoded
    }

    /// Install the VPN configuration on first use. iOS asks the person to allow it.
    private func configuredManager(onDemand: Bool) async throws -> NETunnelProviderManager {
        let manager = manager ?? NETunnelProviderManager()
        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppGroup.tunnelBundleIdentifier
        proto.serverAddress = "Rayfish mesh"
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Rayfish"
        manager.isEnabled = true
        manager.onDemandRules = [NEOnDemandRuleConnect()]
        manager.isOnDemandEnabled = onDemand
        try await manager.saveToPreferences()
        // A freshly saved configuration cannot start until it is reloaded.
        try await manager.loadFromPreferences()
        self.manager = manager
        return manager
    }

    private func update() {
        let next: TunnelState = switch manager?.connection.status {
        case .connected: .on
        case .connecting, .reasserting: .connecting
        case .disconnecting: .disconnecting
        default: .off
        }
        guard next != state else { return }
        state = next
        onChange?()
    }
}

/// The simulator cannot run packet tunnels, so it starts the node in the app.
/// Everything but the data plane works: networks, peers, files, pairing.
@MainActor
final class SimulatorTunnel: Tunnel {
    private(set) var state = TunnelState.off
    var onChange: (() -> Void)?
    let local: NodeHost

    init(local: NodeHost) {
        self.local = local
        local.onReceived = { name in RayfishLog.app.info("Received \(name, privacy: .public)") }
    }

    func load() async {}

    func connect() async throws {
        set(.connecting)
        do {
            try await Task.detached { [local] in try local.start() }.value
            set(.on)
        } catch {
            Telemetry.captureStartFailure(error, node: local.node)
            set(.off)
            throw error
        }
    }

    func disconnect() async {
        set(.disconnecting)
        await Task.detached { [local] in local.stop() }.value
        set(.off)
    }

    func send(_ command: Command) async throws -> Reply {
        let reply = try await local.run(command)
        if case .acceptFile = command {} else { local.autoAcceptOwnDevices() }
        return reply
    }

    private func set(_ next: TunnelState) {
        state = next
        onChange?()
    }
}

enum ProviderMessage {
    /// Send one provider message and wait for its reply, failing after `timeout`.
    @MainActor
    static func send(
        _ data: Data,
        timeout: TimeInterval,
        using sendMessage: @MainActor (Data, @escaping (Data?) -> Void) throws -> Void
    ) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let pending = PendingReply(continuation)
            let timer = DispatchWorkItem { pending.finish(.failure(TunnelError.timedOut)) }
            pending.setTimer(timer)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
            do {
                try sendMessage(data) { reply in
                    pending.finish(reply.map { .success($0) } ?? .failure(TunnelError.noResponse))
                }
            } catch {
                pending.finish(.failure(error))
            }
        }
    }
}

/// Resumes once, with the reply or the timeout, and cancels the timeout so a
/// fast reply does not leave it pending for the full wait.
private final class PendingReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var timer: DispatchWorkItem?

    init(_ continuation: CheckedContinuation<Data, Error>) {
        self.continuation = continuation
    }

    func setTimer(_ timer: DispatchWorkItem) {
        lock.withLock {
            if continuation == nil { timer.cancel() } else { self.timer = timer }
        }
    }

    func finish(_ result: Result<Data, Error>) {
        let (continuation, timer) = lock.withLock {
            defer {
                self.continuation = nil
                self.timer = nil
            }
            return (self.continuation, self.timer)
        }
        timer?.cancel()
        continuation?.resume(with: result)
    }
}
