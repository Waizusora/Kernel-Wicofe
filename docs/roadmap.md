# Development roadmap

## Milestone 0 — repository foundation

- [x] MPL-2.0 license.
- [x] Rust workspace and stable toolchain configuration.
- [x] Initial WBL/kernel handoff data structures.
- [x] x86_64 and AArch64 crate boundaries.
- [x] CI format, host test, lint, and four-target compile checks.

Completion requires all GitHub Actions jobs for the milestone commit to pass.

## Milestone 1 — boot protocol specification

- Define the kernel image format and load-address policy.
- Specify the complete versioned boot information ABI.
- Specify memory-map ownership and UEFI ExitBootServices retry behavior.
- Define architecture-specific entry state for x86_64 and AArch64.
- Add host-side tests for malformed and unsupported handoff data.

## Milestone 2 — UEFI WBL execution path

- Add architecture-specific UEFI entry points.
- Enumerate firmware protocols and load a kernel image from a defined filesystem.
- Validate ELF headers and segments before loading.
- Capture the final memory map and transfer control.
- Add QEMU/OVMF boot tests before claiming boot support.

## Milestone 3 — kernel entry and early architecture setup

- Establish CPU execution state and exception/interrupt vectors.
- Initialize physical memory management.
- Add serial/early-console diagnostics for both architectures.

## Later milestones

- Virtual memory, scheduler, process model, IPC, VFS, drivers, and syscall ABI.
- Define POSIX.1-2024 coverage and conformance tests incrementally.
- Integrate the separate Wlibc project only after the syscall ABI is versioned.

Milestones are sequential: do not begin the next milestone until the current
milestone's CI and stated acceptance checks pass.
