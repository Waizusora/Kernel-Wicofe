# Kernel-Wicofe

Kernel-Wicofe is an independent modular-monolithic operating-system kernel project written in Rust with architecture-specific assembly.

## Initial project targets

- Architectures: x86_64 and AArch64.
- Boot path: Wicofe Bootloader (WBL), developed as a project-owned bootloader.
- Firmware interface: UEFI.
- Kernel design: modular monolithic.
- Userspace compatibility objective: POSIX.1-2024 (Issue 8), implemented natively rather than through a GNU/BSD compatibility foundation.
- License: Mozilla Public License 2.0 (MPL-2.0).

Wlibc remains a separate userspace project. Its integration will use a documented and versioned syscall ABI; it is not part of the kernel workspace at this stage.

## Repository status

This repository contains the initial Rust workspace, shared boot handoff definitions, architecture crate boundaries, and CI checks. It is a foundation only: it does not yet boot on hardware or an emulator and does not claim POSIX conformance.

## Workspace layout

- `bootloader/common`: firmware-independent boot protocol types.
- `bootloader/uefi`: UEFI-facing WBL component boundary.
- `kernel/core`: architecture-independent kernel foundation.
- `kernel/arch/x86_64` and `kernel/arch/aarch64`: architecture-specific boundaries.
- `docs/`: architecture and implementation notes.

## Development

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

CI checks x86_64-unknown-none, aarch64-unknown-none, x86_64-unknown-uefi, and aarch64-unknown-uefi.

See [docs/roadmap.md](docs/roadmap.md) before starting implementation work.
