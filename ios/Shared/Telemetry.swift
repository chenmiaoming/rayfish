import Foundation
import Sentry

/// Sentry crash reporting, gated by the user's opt-out toggle in the You tab.
///
/// The app and the tunnel each run their own client. Both read the toggle from
/// the app group: the tunnel at start, and again when the app forwards a
/// change with `Command.setCrashReporting`.
enum Telemetry {
    /// Start or stop the client to match the toggle.
    static func apply() {
        if Preferences.crashReporting { enable() } else { disable() }
    }

    /// No-op when the build carries no DSN.
    static func enable() {
        guard !SentrySDK.isEnabled, let dsn = info("RayfishSentryDSN"), !dsn.isEmpty else { return }
        SentrySDK.start { options in
            options.dsn = dsn
            options.releaseName = "rayfish-ios@\(info("CFBundleShortVersionString") ?? "unknown")"
            // The commit the build came from, so a report can be placed against
            // a fix. Empty for builds made outside the just recipes.
            if let sha = info("RayfishGitSHA"), !sha.isEmpty { options.dist = sha }
            #if DEBUG
            options.environment = "dev"
            #else
            options.environment = "production"
            #endif
            options.sendDefaultPii = false
            // Crashes and explicit reports only. Tracing, hang detection and
            // swizzling cost memory the tunnel's 50 MB limit cannot spare.
            options.tracesSampleRate = 0
            options.enableAutoPerformanceTracing = false
            options.enableAppHangTracking = false
            options.enableSwizzling = false
        }
    }

    static func disable() {
        guard SentrySDK.isEnabled else { return }
        SentrySDK.close()
    }

    /// A node that will not start leaves the device offline with nothing on
    /// screen saying why, so it is reported without waiting for the user.
    /// At most once per half hour: every connect attempt retries the start.
    static func captureStartFailure(_ error: Error, node: Node) {
        guard SentrySDK.isEnabled, failureThrottle.allow() else { return }
        let logs = node.logSnapshot()
        SentrySDK.capture(error: error) { scope in
            scope.setTag(value: Preferences.installId, key: "install_id")
            // The Swift error says the start failed; the core's log says why.
            if !logs.isEmpty {
                scope.addAttachment(Attachment(data: Data(logs.utf8), filename: "rayfish-logs.txt",
                                               contentType: "text/plain"))
            }
        }
    }

    /// The core's log and health as one report. Returns the event id, or nil
    /// when reporting is off.
    static func sendDiagnostics(node: Node) -> String? {
        guard SentrySDK.isEnabled else { return nil }
        let logs = node.logSnapshot()
        let health = node.healthSnapshot()
        let id = SentrySDK.capture(message: "rayfish diagnostics") { scope in
            scope.setLevel(.info)
            scope.setTag(value: Preferences.installId, key: "install_id")
            scope.setContext(value: [
                "running": health.running,
                "networks": health.networkCount,
                "peers_online": health.peersOnline,
            ], key: "rayfish")
            if !logs.isEmpty {
                scope.addAttachment(Attachment(data: Data(logs.utf8), filename: "rayfish-logs.txt",
                                               contentType: "text/plain"))
            }
        }
        return id.sentryIdString
    }

    private static let failureThrottle = Throttle(interval: 30 * 60)

    private static func info(_ key: String) -> String? {
        Bundle.main.object(forInfoDictionaryKey: key) as? String
    }
}

private final class Throttle: @unchecked Sendable {
    private let lock = NSLock()
    private let interval: TimeInterval
    private var last: Date?

    init(interval: TimeInterval) { self.interval = interval }

    func allow() -> Bool {
        lock.withLock {
            let now = Date()
            if let last, now.timeIntervalSince(last) < interval { return false }
            last = now
            return true
        }
    }
}
