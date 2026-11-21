# a-better-mac-antivirus

Literally a fork of vulvinix's av, except this one fell from a tree

A native Swift/C prototype of the credential tripwire idea from [A Better Antivirus](https://github.com/vulnix0x4/a-better-antivirus). This is a separate implementation, not a source-compatible port of its Windows service. macOS 13 or later. No third-party dependencies.

## Implemented

- Three fake credential documents in a dedicated directory you explicitly choose.
- Exclusive creation: refuses an existing directory and never overwrites your files.
- Private permissions, symlink/hardlink checks, and device/inode-based tracking.
- Native Endpoint Security `AUTH_OPEN` interception with process identity supplied by the kernel, including PID version, executable, code-signing flags, signing identifier, and team identifier.
- Alert-only mode by default. Optional enforcement denies **critical decoy opens**, with no cached authorization decisions.
- Critical classifications for unsigned/invalid/ad-hoc readers, common scripting runtimes, and processes opening two decoy categories within two minutes. A signed application initially produces a warning; signatures are not an exemption from sweep detection.
- JSON Lines alerts on stdout. The alert includes the authorization response status; a requested denial is recorded as successful only when Endpoint Security accepts the response.
- Bounded process history and alert output queue. Overloaded output drops alerts with a stderr warning while authorization decisions continue.

## Build and test

Install Apple's command line developer tools, then:

```sh
swift build -c release
swift test
.build/release/aba --help
```

Apple Silicon and Intel builds use the same sources. To build a universal binary:

```sh
swift build -c release --arch arm64 --arch x86_64
```

The archive also includes `bin/aba`, a universal ARM64/Intel prototype build. It is not notarized or provisioned for Endpoint Security; see `VALIDATION.md`. You can run `bin/aba --help` without building.

## Create decoys

Run as your normal user, with a **new** directory whose parent already exists:

```sh
.build/release/aba init --directory "$HOME/Documents/ABA-Decoys"
.build/release/aba doctor --directory "$HOME/Documents/ABA-Decoys"
```

This creates `passwords.txt`, `wallet-recovery.txt`, and `backup-codes.txt`. All contents are fake; there are no usable credentials or funded wallets. The directory is mode 0700 and files are mode 0600. Creating decoys does **not** start monitoring. These standalone documents do not imitate browser databases or messaging application profiles.

## Enable native monitoring

Apple requires all of the following for an Endpoint Security client:

1. The restricted `com.apple.developer.endpoint-security.client` entitlement, approved for your Apple developer team, with appropriate signing/provisioning.
2. Full Disk Access granted in System Settings for the executable or its responsible application as required by macOS.
3. Root privileges.

`Resources/aba.entitlements` supplies the entitlement declaration; the file itself does not grant Apple's approval. Ad-hoc signing or running an ordinary unsigned build with sudo does not satisfy that requirement. Do not disable SIP to use this prototype. See [Apple's Endpoint Security documentation](https://developer.apple.com/documentation/endpointsecurity) and [the entitlement reference](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client).

After signing and provisioning an approved build:

```sh
sudo /absolute/path/to/signed/aba monitor --directory "/Users/YOUR_USER/Documents/ABA-Decoys"
# Opt-in: deny critical decoy opens.
sudo /absolute/path/to/signed/aba monitor --directory "/Users/YOUR_USER/Documents/ABA-Decoys" --enforce
```

Use an explicit absolute directory when switching to root. The process writes JSON alerts to stdout and diagnostics to stderr. Ctrl-C or SIGTERM stops it and removes its ES subscription. There is no persistent service installation.

To exercise an **already running, entitled** monitor, read a decoy from another terminal as your regular user:

```sh
cat "$HOME/Documents/ABA-Decoys/passwords.txt"
```

An ordinary signed `cat` initially produces a warning. Reading another category with a **different** process does not count as the same process sweeping. A common scripting runtime reading a decoy is classified critical; in enforcement mode the open should fail. Live validation must check actual failure and the JSON `responseResult`/`accessDenied` fields. Unit tests do not prove the native interception works on a deployed system.

## Scope and limitations

This is an initial native backend and CLI, **not a finished antivirus or feature-equivalent Windows release**.

- Denying access to a fake credential file does not stop that process or prevent it reading/exfiltrating real credentials elsewhere. Process-tree suspension, network filtering, isolation, and incident recovery are not implemented.
- No app-profile decoys, trust rules, learning mode, GUI/desktop notifications, phone alerts, launch daemon, signed updater, or installer yet.
- The directory and inode snapshot is loaded at startup. Existing monitored inodes remain recognized after rename/hardlink access. Replacing/deleting a bait does not rearm its replacement. Stop, inspect with `doctor`, and restart after changes. There is no continuous integrity health check.
- `doctor` checks filesystem safety, not monitor liveness or entitlement availability. It is not a “protected” indicator.
- Endpoint Security has deadlines and can drop events. This prototype does not track event-sequence gaps or expose a protection-health dashboard. The response path does no disk/network I/O before replying; logging happens afterward. Resource-allocation failure allows the open. Performance under hostile event load has not been established.
- Heuristics can flag legitimate tools (backup, indexing, shells, developer tools). Start in alert-only mode. There are no broad platform or vendor allowlists.
- Monitoring a dedicated decoy directory is narrower coverage than planting realistic app data at stealer discovery paths. A stealer that never opens a decoy will not trigger anything.

Remove these decoys manually when finished; this prototype deliberately has no recursive cleanup command.

## Validation in this workspace

Native compilation, policy tests, filesystem safety tests, and CLI smoke checks are exercised without requiring an entitlement or touching real credential stores. Live ES authorization is not validated because this workspace has no approved signing entitlement configured. See `VALIDATION.md` for the final results.

## Attribution

Inspired by vulnix0x4's A Better Antivirus. The upstream MIT license is retained in `LICENSE`. The macOS implementation is provided under the same license.
