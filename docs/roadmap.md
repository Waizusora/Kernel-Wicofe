# Development roadmap

## Milestone 0 — repository foundation

- [x] MPL-2.0 license.
- [x] Rust workspace and stable toolchain configuration.
- [x] Initial WBL/kernel handoff data structures.
- [x] x86_64 and AArch64 crate boundaries.
- [x] CI format, host test, lint, and four-target compile checks.

## Milestone 1 — boot protocol specification

- [x] Define ELF64 ET_EXEC format, architecture IDs, and fixed load-address policy.
- [x] Specify versioned BootInfo ABI v2 and canonical memory-map types.
- [x] Specify memory ownership and UEFI ExitBootServices retry behavior.
- [x] Define x86-64 and AArch64 entry register, stack, paging, and interrupt state.
- [x] Add host-side ABI layout and malformed-handoff validation tests.

## Milestone 2 — UEFI WBL execution path

- [x] Add architecture-neutral UEFI application entry point and PE/COFF build targets.
- [ ] Enumerate firmware protocols and load a kernel image from a defined filesystem.
- [x] Implement bounds-checked ELF64 ET_EXEC validation for x86-64 and AArch64.
- [ ] Allocate and load ELF PT_LOAD segments with architecture-correct mappings.
- [ ] Capture the final memory map and transfer control.
- [ ] Add QEMU/OVMF boot tests for both architectures before claiming boot support.

## Milestone 3 — kernel entry and early architecture setup

- [ ] Establish CPU execution state and exception/interrupt vectors.
- [ ] Initialize physical memory management.
- [ ] Add serial/early-console diagnostics for both architectures.

## Later milestones

- Virtual memory, scheduler, process model, IPC, VFS, drivers, and syscall ABI.
- Define POSIX.1-2024 coverage and conformance tests incrementally.
- Integrate the separate Wlibc project only after the syscall ABI is versioned.

Milestones are sequential: do not begin the next milestone until the current
milestone's CI and stated acceptance checks pass.
