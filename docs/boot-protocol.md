# WBL boot handoff (initial contract)

Wicofe Bootloader (WBL) is the project-owned bootloader. The first firmware
implementation targets UEFI on x86_64 and AArch64.

## Initial division of responsibility

WBL is expected to:

1. Enter through the architecture's UEFI application entry point.
2. Discover required firmware protocols and storage.
3. Load and validate a Kernel-Wicofe ELF image.
4. Collect the final UEFI memory map and required platform tables.
5. Exit boot services and transfer control using a versioned handoff.

Kernel-Wicofe is expected to validate the handoff before initializing its own
page tables, exception/interrupt handling, memory management, and scheduler.

## Version 1 data layout

The Rust definitions live in bootloader/common and are shared by the UEFI
loader and kernel. BootInfo uses fixed-width integer fields and repr(C);
physical addresses are encoded as u64 values, not Rust pointers.

The memory-map entry format is project-defined and is not a direct exposure of
UEFI's EFI_MEMORY_DESCRIPTOR. WBL must translate firmware descriptors into
the stable MemoryRegion representation before handing control to the kernel.

This contract is provisional until alignment, ownership, cacheability, reserved
regions, framebuffer data, ACPI tables, and version-negotiation rules are
specified and tested. No bootable loader is implemented in this milestone.
