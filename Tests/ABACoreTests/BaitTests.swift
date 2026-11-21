import XCTest
import Darwin
@testable import ABACore
final class BaitTests: XCTestCase {
    func temporaryDirectory() -> String { FileManager.default.temporaryDirectory.appendingPathComponent("aba-tests-\(UUID())").path }
    func testCreatesPrivateDecoysAndNeverOverwrites() throws {
        let path = temporaryDirectory(); defer { try? FileManager.default.removeItem(atPath: path) }
        let baits = try BaitStore.create(directory: path)
        XCTAssertEqual(baits.count, 3)
        let original = try Data(contentsOf: URL(fileURLWithPath: baits[0].path))
        XCTAssertThrowsError(try BaitStore.create(directory: path))
        XCTAssertEqual(original, try Data(contentsOf: URL(fileURLWithPath: baits[0].path)))
        XCTAssertEqual(Set(baits.map(\.identity)).count, 3)
    }
    func testRejectsSymlinkedBaitAndDirectory() throws {
        let path = temporaryDirectory(), link = temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: link); try? FileManager.default.removeItem(atPath: path) }
        let baits = try BaitStore.create(directory: path)
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: path)
        XCTAssertThrowsError(try BaitStore.inspect(directory: link))
        try FileManager.default.removeItem(atPath: baits[0].path)
        try FileManager.default.createSymbolicLink(atPath: baits[0].path, withDestinationPath: baits[1].path)
        XCTAssertThrowsError(try BaitStore.inspect(directory: path))
    }
    func testRejectsHardlinksAndPublicDirectory() throws {
        let path = temporaryDirectory(); defer { try? FileManager.default.removeItem(atPath: path) }
        let baits = try BaitStore.create(directory: path)
        let extra = path + "/extra"
        XCTAssertEqual(link(baits[0].path, extra), 0)
        XCTAssertThrowsError(try BaitStore.inspect(directory: path))
        try FileManager.default.removeItem(atPath: extra)
        XCTAssertEqual(chmod(path, 0o755), 0)
        XCTAssertThrowsError(try BaitStore.inspect(directory: path))
    }
}
