# Dependency security

Review date: 2026-09-21

The review used cargo-audit 0.22.2, the locked dependency graph in `Cargo.lock`,
and the local RustSec advisory database at commit
`bd8037e5cbb8d8cc687c68cdd42ca53d742503fb`. The audit reports one vulnerability
and one denied warning. Both are recorded below.

`anyhow` is pinned to 1.0.103. This includes the fix for RUSTSEC-2026-0190.

`rsa` 0.9.10 has no fixed release for RUSTSEC-2023-0071. The advisory concerns
timing leakage during private-key operations. This module asks an external SSH
agent to perform signing and verifies the returned signature locally with the
public key. The affected private-key operation is outside this process.

`spin` 0.9.8 is reported as yanked and unmaintained. It is transitive through
`num-bigint-dig` and `rsa`, which are required by `ssh-key`. The dependency is
retained under review because the current SSH key implementation requires this
graph.

Waiver and trigger:

- Keep the current `rsa` and `spin` versions locked.
- Review the waiver when `ssh-key` offers a supported graph without the affected
  advisories, or when the RustSec status changes.
- Re-run the dependency review before each release and after an SSH key or
  cryptography dependency update.
