import Foundation
public struct FileIdentity: Codable, Hashable {
    public let device: UInt64
    public let inode: UInt64
    public init(device: UInt64, inode: UInt64) { self.device = device; self.inode = inode }
}
public struct Reader: Codable {
    public let pid: Int32
    public let version: UInt32
    public let uid: UInt32
    public let executable: String
    public let signingID: String
    public let teamID: String
    public let codeFlags: UInt32
    public let platform: Bool
    public init(pid: Int32, version: UInt32, uid: UInt32, executable: String, signingID: String = "", teamID: String = "", codeFlags: UInt32 = 0, platform: Bool = false) {
        self.pid = pid; self.version = version; self.uid = uid; self.executable = executable
        self.signingID = signingID; self.teamID = teamID; self.codeFlags = codeFlags; self.platform = platform
    }
}
public struct Verdict: Codable, Equatable {
    public let severity: String
    public let reason: String
    public let deny: Bool
}
public final class Policy {
    private struct ProcessKey: Hashable { let pid: Int32; let version: UInt32 }
    private struct Sweep { var categories: [String: TimeInterval]; var last: TimeInterval }
    private var history: [ProcessKey: Sweep] = [:]
    private let lock = NSLock()
    private let clock: () -> TimeInterval
    public init(clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) { self.clock = clock }
    public func evaluate(_ reader: Reader, category: String, enforce: Bool) -> Verdict {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        history = history.filter { now - $0.value.last < 120 }
        let key = ProcessKey(pid: reader.pid, version: reader.version)
        var sweep = history[key] ?? Sweep(categories: [:], last: now)
        sweep.categories = sweep.categories.filter { now - $0.value < 120 }
        sweep.categories[category] = now; sweep.last = now
        // Bound memory even if an adversary generates many process identities.
        if history.count >= 4096 && history[key] == nil { history.removeAll(keepingCapacity: true) }
        history[key] = sweep
        if sweep.categories.count >= 2 { return Verdict(severity: "critical", reason: "read decoys from multiple categories within 120 seconds", deny: enforce) }
        let name = URL(fileURLWithPath: reader.executable).lastPathComponent.lowercased()
        let runtimes = ["sh", "bash", "zsh", "osascript", "python", "python3", "node", "ruby", "perl", "java", "swift"]
        if runtimes.contains(name) || name.hasPrefix("python3.") {
            return Verdict(severity: "critical", reason: "scripting runtime opened a credential decoy", deny: enforce)
        }
        // CS_VALID = 1, CS_ADHOC = 2. An ad-hoc signature establishes no publisher identity.
        if reader.codeFlags & 1 == 0 || reader.codeFlags & 2 != 0 {
            return Verdict(severity: "critical", reason: "unsigned, invalidly signed, or ad-hoc process opened a credential decoy", deny: enforce)
        }
        return Verdict(severity: "warn", reason: "signed process opened a credential decoy; signature alone does not establish intent", deny: false)
    }
}
