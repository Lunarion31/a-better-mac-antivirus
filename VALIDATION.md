# Validation results

Validated November 20, 2026 (America/New_York) on an Apple Silicon Mac using Swift 6.4.2 and the installed macOS SDK.

- Debug Swift/C build: passed.
- Eight XCTest unit tests: passed, zero failures. Covers unsigned/ad-hoc classification, signed script hosts, cross-category sweeps, PID reuse, category expiry, exclusive creation, private permissions, and symlink/hardlink rejection.
- Seven CLI smoke checks: passed. Help, initialization, doctor, refusal to reuse a directory, refusal to monitor without root, unknown flags, and missing option values. All created decoys were in a temporary directory and removed.
- Entitlement plist syntax: passed `plutil -lint`.
- Optimized ARM64 and Intel x86_64 builds: passed using SwiftPM's native build system.
- Universal binary: combined using `lipo`; both architectures confirmed. Included as `bin/aba`; help command executed successfully on ARM64. Intel runtime execution was not tested.

The default Xcode-based release build reached linking but its dSYM generation was blocked by the workspace's filesystem permissions. The successful release builds used `--build-system native`, which this Swift toolchain deprecates. No sandbox permissions were expanded.

Live Endpoint Security interception, real denial behavior, deadline handling under load, and deployment signing/provisioning have NOT been validated. No root monitor was started. No existing credentials, application profiles, system settings, firewall rules, or background services were modified.

The bundled binary has no approved Endpoint Security provisioning and is not notarized. It can run help/init/doctor; it cannot provide live protection until appropriately signed, approved for Full Disk Access, and launched with root privileges. It does not suspend processes or isolate networking.
