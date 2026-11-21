import XCTest
@testable import ABACore
final class PolicyTests: XCTestCase {
    func testUnsignedAndAdhocAreDeniedOnlyInEnforcementMode() {
        let reader = Reader(pid: 12, version: 1, uid: 501, executable: "/tmp/game")
        XCTAssertFalse(Policy().evaluate(reader, category: "passwords", enforce: false).deny)
        XCTAssertTrue(Policy().evaluate(reader, category: "passwords", enforce: true).deny)
        let adhoc = Reader(pid: 12, version: 1, uid: 501, executable: "/Applications/Game.app/game", codeFlags: 3)
        XCTAssertTrue(Policy().evaluate(adhoc, category: "passwords", enforce: true).deny)
    }
    func testSignedRuntimeDoesNotGainTrustFromSignature() {
        let reader = Reader(pid: 20, version: 2, uid: 501, executable: "/bin/zsh", codeFlags: 1, platform: true)
        XCTAssertTrue(Policy().evaluate(reader, category: "wallet", enforce: true).deny)
    }
    func testSignedAppSweepEscalatesButPidReuseDoesNotInheritHistory() {
        let policy = Policy()
        let reader = Reader(pid: 22, version: 1, uid: 501, executable: "/Applications/App.app/app", codeFlags: 1)
        XCTAssertFalse(policy.evaluate(reader, category: "passwords", enforce: true).deny)
        XCTAssertFalse(policy.evaluate(reader, category: "passwords", enforce: true).deny)
        XCTAssertTrue(policy.evaluate(reader, category: "wallet", enforce: true).deny)
        let reused = Reader(pid: 22, version: 2, uid: 501, executable: reader.executable, codeFlags: 1)
        XCTAssertFalse(policy.evaluate(reused, category: "wallet", enforce: true).deny)
    }
    func testSweepExpires() {
        var now = 1000.0
        let policy = Policy(clock: { now })
        let reader = Reader(pid: 22, version: 1, uid: 501, executable: "/Applications/App.app/app", codeFlags: 1)
        _ = policy.evaluate(reader, category: "passwords", enforce: true)
        now += 121
        XCTAssertFalse(policy.evaluate(reader, category: "wallet", enforce: true).deny)
    }
    func testIndividualCategoryExpiresDespiteOtherRecentReads() {
        var now = 1000.0
        let policy = Policy(clock: { now })
        let reader = Reader(pid: 22, version: 1, uid: 501, executable: "/Applications/App.app/app", codeFlags: 1)
        _ = policy.evaluate(reader, category: "wallet", enforce: true)
        now += 100
        _ = policy.evaluate(reader, category: "passwords", enforce: true)
        now += 30
        XCTAssertFalse(policy.evaluate(reader, category: "passwords", enforce: true).deny)
    }

}
