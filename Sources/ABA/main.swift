import Foundation
import Darwin
import ABACore
import CEndpoint

struct Alert: Encodable {
    let time: String
    let reader: Reader
    let bait: Bait
    let verdict: Verdict
    let responseResult: Int32
    let accessDenied: Bool
}
final class Monitor {
    let policy = Policy()
    let baits: [FileIdentity: Bait]
    let enforce: Bool
    let output = DispatchQueue(label: "aba.alerts")
    let outputSlots = DispatchSemaphore(value: 256)
    var warnedAboutDrops = false
    // ES invokes a client's handler serially. This stores only the current event's verdict.
    var pending: Verdict?
    init(baits: [Bait], enforce: Bool) {
        self.baits = Dictionary(uniqueKeysWithValues: baits.map { ($0.identity, $0) }); self.enforce = enforce
    }
    func reader(_ event: aba_event) -> Reader {
        Reader(pid: event.pid, version: event.pid_version, uid: event.uid,
            executable: String(cString: event.executable), signingID: String(cString: event.signing_id),
            teamID: String(cString: event.team_id), codeFlags: event.code_flags, platform: event.platform_binary)
    }
    func decide(_ event: aba_event) -> Bool {
        let id = FileIdentity(device: event.device, inode: event.inode)
        guard let bait = baits[id] else { pending = nil; return false }
        let verdict = policy.evaluate(reader(event), category: bait.category, enforce: enforce)
        pending = verdict
        return verdict.deny
    }
    func report(_ event: aba_event, denied: Bool, response: Int32) {
        let id = FileIdentity(device: event.device, inode: event.inode)
        guard let bait = baits[id], let verdict = pending else { return }
        let alert = Alert(time: ISO8601DateFormatter().string(from: Date()), reader: reader(event), bait: bait,
            verdict: verdict, responseResult: response, accessDenied: denied && response == 0)
        guard outputSlots.wait(timeout: .now()) == .success else {
            if !warnedAboutDrops {
                fputs("aba: alert output is overloaded; some alerts will be dropped. Authorization decisions continue.\n", stderr)
                warnedAboutDrops = true
            }
            return
        }
        output.async {
            defer { self.outputSlots.signal() }
            do {
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
                var data = try encoder.encode(alert); data.append(0x0a)
                try FileHandle.standardOutput.write(contentsOf: data)
            } catch { fputs("aba: could not write alert: \(error)\n", stderr) }
        }
    }
}
func value(_ option: String, in args: [String]) throws -> String {
    guard let i = args.firstIndex(of: option), i + 1 < args.count, !args[i + 1].hasPrefix("--") else {
        throw ABAError.message("\(option) requires a path")
    }
    let url = URL(fileURLWithPath: (args[i + 1] as NSString).expandingTildeInPath).standardizedFileURL
    guard url.path != "/" else { throw ABAError.message("Use a dedicated decoy directory") }
    return url.path
}
func run() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    guard let command = args.first, command != "--help", command != "help" else {
        print("""
        ABA for macOS — credential tripwire prototype
        aba init --directory PATH       create three decoys in a NEW private directory
        aba doctor --directory PATH     verify decoys; does not imply monitoring is active
        aba monitor --directory PATH [--enforce]
                                       stream JSON alerts; --enforce denies critical bait opens
        Endpoint Security monitoring requires root, Full Disk Access, and an Apple-approved
        com.apple.developer.endpoint-security.client signing entitlement.
        No process suspension, network isolation, or background installation in this prototype.
        """); return
    }
    guard ["init", "doctor", "monitor"].contains(command) else { throw ABAError.message("Unknown command: \(command)") }
    let validOptions = command == "monitor" ? ["--directory", "--enforce"] : ["--directory"]
    var i = 1
    while i < args.count {
        guard validOptions.contains(args[i]) else { throw ABAError.message("Unknown argument: \(args[i])") }
        i += args[i] == "--directory" ? 2 : 1
    }
    let directory = try value("--directory", in: args)
    if command == "init" {
        let baits = try BaitStore.create(directory: directory)
        print("Created \(baits.count) decoys in \(directory). Monitoring is NOT running.")
        return
    }
    let baits = try BaitStore.inspect(directory: directory)
    if command == "doctor" {
        for bait in baits { print("OK \(bait.name) device=\(bait.identity.device) inode=\(bait.identity.inode)") }
        print("Decoys verified. Monitor status and signing entitlement were not checked.")
        return
    }
    guard geteuid() == 0 else { throw ABAError.message("Monitoring requires root plus the Endpoint Security signing entitlement and Full Disk Access") }
    let monitor = Monitor(baits: baits, enforce: args.contains("--enforce"))
    let context = Unmanaged.passUnretained(monitor).toOpaque()
    let identities = baits.map { aba_file(device: $0.identity.device, inode: $0.identity.inode) }
    let result = identities.withUnsafeBufferPointer { buffer in
        aba_start(buffer.baseAddress, UInt32(buffer.count), { event, context in
            Unmanaged<Monitor>.fromOpaque(context!).takeUnretainedValue().decide(event!.pointee)
        }, { event, deny, response, context in
            Unmanaged<Monitor>.fromOpaque(context!).takeUnretainedValue().report(event!.pointee, denied: deny, response: response)
        }, context)
    }
    guard result == 0 else {
        let reasons: [Int32: String] = [103: "missing Apple-approved Endpoint Security signing entitlement", 104: "Full Disk Access was not granted", 105: "root privileges are required"]
        throw ABAError.message("Endpoint Security startup failed (\(result)): \(reasons[result] ?? "see es_new_client_result_t in the SDK"). Monitoring is NOT running.")
    }
    fputs("Monitoring \(baits.count) decoys; mode=\(monitor.enforce ? "deny critical bait access" : "alert only"). Ctrl-C stops monitoring.\n", stderr)
    signal(SIGINT, SIG_IGN); signal(SIGTERM, SIG_IGN)
    let stop: @convention(block) () -> Void = {
        // Process exit disconnects ES. Avoid deleting the client concurrently with its handler.
        monitor.output.sync {}
        exit(0)
    }
    let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    let terminate = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    interrupt.setEventHandler(handler: stop); terminate.setEventHandler(handler: stop)
    interrupt.resume(); terminate.resume()
    withExtendedLifetime((monitor, interrupt, terminate)) { dispatchMain() }
}
do { try run() } catch { fputs("aba: \(error)\n", stderr); exit(1) }
