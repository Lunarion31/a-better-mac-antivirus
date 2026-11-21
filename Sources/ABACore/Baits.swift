import Foundation
import Darwin
public struct Bait: Codable {
    public let name: String
    public let category: String
    public let identity: FileIdentity
    public let path: String
}
public enum ABAError: Error, CustomStringConvertible {
    case message(String)
    public var description: String { switch self { case .message(let s): return s } }
}
public enum BaitStore {
    public static let catalog: [(name: String, category: String, content: String)] = [
        ("passwords.txt", "passwords", "Personal accounts\nemail: backup@example.invalid\npassword: ABA-FAKE-DO-NOT-USE\n"),
        ("wallet-recovery.txt", "wallet", "Wallet backup\nABA DECOY — intentionally invalid recovery phrase; no wallet or funds exist.\n"),
        ("backup-codes.txt", "recovery", "Account recovery codes\nABA-FAKE-0001\nABA-FAKE-0002\n")
    ]
    private static func failure(_ message: String) -> ABAError { .message("\(message): \(String(cString: strerror(errno)))") }
    private static func openDirectory(_ path: String) throws -> Int32 {
        // Resolve parent components once, then use dirfd-relative operations. Refuse a symlink as the final component.
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw failure("Cannot open decoy directory") }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & 0o077 == 0 else {
            close(fd); throw ABAError.message("Decoy directory must have mode 0700")
        }
        return fd
    }
    public static func create(directory: String) throws -> [Bait] {
        guard geteuid() != 0 else { throw ABAError.message("Create decoys as your regular user, not root") }
        guard mkdir(directory, 0o700) == 0 else { throw failure("Refusing to reuse an existing directory; choose a new one") }
        let fd = try openDirectory(directory); defer { close(fd) }
        for spec in catalog {
            let file = openat(fd, spec.name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard file >= 0 else { throw failure("Cannot exclusively create \(spec.name)") }
            let data = Array(spec.content.utf8)
            let wrote: Bool = data.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let result = write(file, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                    if result < 0 && errno == EINTR { continue }
                    if result <= 0 { return false }
                    offset += result
                }
                return fsync(file) == 0
            }
            close(file)
            guard wrote else { throw failure("Cannot write \(spec.name); partial decoy directory retained") }
        }
        return try inspect(directory: directory)
    }
    public static func inspect(directory: String) throws -> [Bait] {
        let fd = try openDirectory(directory); defer { close(fd) }
        var parent = stat(); guard fstat(fd, &parent) == 0 else { throw failure("Cannot stat directory") }
        guard parent.st_uid != 0 else { throw ABAError.message("Decoys must belong to a regular user") }
        if geteuid() != 0 && parent.st_uid != geteuid() { throw ABAError.message("Decoy directory belongs to another user") }
        return try catalog.map { spec in
            var info = stat()
            guard fstatat(fd, spec.name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw failure("Missing decoy \(spec.name)") }
            guard info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
                  info.st_uid == parent.st_uid, info.st_mode & 0o077 == 0 else {
                throw ABAError.message("Unsafe decoy \(spec.name): expected a private regular file, same owner, no hard links")
            }
            return Bait(name: spec.name, category: spec.category,
                identity: FileIdentity(device: UInt64(UInt32(bitPattern: info.st_dev)), inode: info.st_ino),
                path: URL(fileURLWithPath: directory).appendingPathComponent(spec.name).path)
        }
    }
}
