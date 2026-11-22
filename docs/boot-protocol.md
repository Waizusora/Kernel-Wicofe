# WBL boot protocol — ABI v2

Status: normative design contract for Milestone 1 and the implementation
baseline for Milestone 2. The UEFI execution path is not yet complete.
MUST, MUST NOT, SHOULD, and MAY describe requirements for WBL and the kernel.

## 1. Supported execution targets

- Firmware interface: UEFI 2.x, x86-64 and AArch64.
- Kernel image: ELF64, little-endian, ET_EXEC.
- x86-64 machine: EM_X86_64 (62).
- AArch64 machine: EM_AARCH64 (183).
- Kernel page size and loader allocation granularity: 4 KiB.
- Kernel physical allocation base and linked virtual base: 2 MiB aligned.
- WBL MUST reject an ELF class, byte order, machine, type, or program-header
  layout that does not match the active architecture.

Fixed linked virtual bases:

| Architecture | Kernel virtual base |
| --- | --- |
| x86-64 | 0xffffffff80000000 |
| AArch64 | 0xffff000000000000 |

The first PT_LOAD segment MUST begin at the architecture's fixed kernel
virtual base. The image span is the interval from that base to the highest
byte covered by PT_LOAD segments. WBL allocates one contiguous physical span,
zeroes it, and copies each loadable segment to the offset corresponding to
p_vaddr relative to the fixed base. p_paddr is ignored. WBL MUST reject
segments outside the image span, arithmetic overflow, invalid alignment,
overlapping load segments, writable-executable segments, and an entry point
not contained in an executable PT_LOAD segment. p_filesz MUST NOT exceed
p_memsz; the zero-filled tail represents BSS.

WBL MUST validate ELF headers and all program-header bounds before allocating
or copying. It MUST NOT interpret section headers as load instructions.
Dynamic linking, ET_DYN, relocations, kernel modules, and compressed images
are out of scope for ABI v2.

## 2. BootInfo ABI v2

Canonical definitions are in bootloader/common/src/lib.rs.

- Magic: 0x5749434f46454249.
- Version: 2.
- BootInfo size: 88 bytes; alignment: 8 bytes.
- MemoryRegion size: 24 bytes; alignment: 8 bytes.
- All fields are fixed-width integers. Addresses are integer addresses, never
  Rust pointers, usize, Rust enums, or bool.
- struct_size MUST equal 88 for version 2. Unknown versions are rejected.
- flags and reserved MUST be zero.
- memory_map_entry_size MUST equal 24. The array MUST contain at least one
  entry; its address MUST be nonzero and 8-byte aligned; its count MUST match.
- The map MUST be sorted by ascending physical address, page aligned,
  non-empty, non-overlapping, and free of address arithmetic overflow.
- Unknown memory kinds or attribute bits MUST be rejected by an ABI v2 kernel.

BootInfo fields:

| Field | Meaning |
| --- | --- |
| magic, version, struct_size | Identify and size the ABI |
| architecture | 1 x86-64, 2 AArch64 |
| flags, reserved | Must be zero in v2 |
| memory_map_address | Physical address of canonical region array |
| memory_map_entries | Number of regions |
| memory_map_entry_size | Bytes per region |
| kernel_physical_base | Physical base of contiguous kernel image |
| kernel_virtual_base | Fixed linked virtual base |
| kernel_image_size | Span of loaded image |
| kernel_entry | Virtual ELF entry point |
| acpi_rsdp_address | Physical ACPI RSDP address, or zero |

MemoryRegion fields are physical_start (u64), length (u64), kind (u32),
and attributes (u32). Kinds are project-defined: 1 usable, 2 reserved,
3 ACPI reclaim, 4 ACPI NVS, 5 MMIO, 6 framebuffer, 7 bootloader reclaim,
8 kernel, 9 boot information, and 10 firmware runtime. They are not numeric
aliases for UEFI EFI_MEMORY_TYPE values.

Attribute bits: write-back (bit 0), write-through (bit 1), write-combining
(bit 2), uncached (bit 3), and firmware-runtime (bit 4). Cacheability bits
are mutually exclusive. Runtime is independent and requires the region to
remain reserved. WBL translates UEFI attributes into this canonical
vocabulary; it MUST NOT copy an EFI_MEMORY_DESCRIPTOR into the ABI array.

## 3. Ownership and lifetime

Before ExitBootServices, WBL owns every allocation it makes. After a
successful ExitBootServices:

- Firmware boot services are unavailable; WBL MUST NOT call boot services.
- The kernel owns the loaded image, initial page tables, BootInfo, and
  canonical memory-map allocation.
- The kernel MUST treat USABLE as the only immediately allocatable kind.
- BOOTLOADER_RECLAIM becomes reusable only after the kernel has copied and
  validated all handoff data and no longer needs loader-owned data.
- ACPI_RECLAIM becomes reusable only after the kernel has parsed and retained
  required ACPI structures.
- ACPI_NVS, MMIO, FRAMEBUFFER, FIRMWARE_RUNTIME, and RESERVED remain
  unavailable to the general physical allocator.
- KERNEL and BOOT_INFO remain reserved for their live objects.
- The kernel MUST validate addresses and lengths before dereferencing them.

WBL MUST classify every physical range exactly once. Adjacent regions with
identical kind and attributes SHOULD be coalesced. Any overlap or unclassified
range is a loader error; WBL MUST fail closed rather than mark uncertain
memory as usable.

## 4. UEFI memory map and ExitBootServices

WBL obtains the final map using GetMemoryMap and passes a translated,
project-defined MemoryRegion array to the kernel.

1. WBL obtains the required map size and descriptor size.
2. It allocates a map buffer with additional capacity for at least eight
   descriptors, then calls GetMemoryMap again.
3. It records MapKey and immediately calls ExitBootServices(ImageHandle,
   MapKey). No allocation, protocol call, firmware logging, or other
   boot-service operation may occur between successful GetMemoryMap and
   ExitBootServices calls.
4. If ExitBootServices returns EFI_INVALID_PARAMETER, the map key is stale.
   WBL MUST reacquire the map and retry. It MUST NOT reuse the stale key.
5. If the map no longer fits, WBL allocates a larger buffer and repeats the
   complete map acquisition sequence.
6. Retries are bounded to eight attempts. Exhaustion or any other error
   terminates boot; there is no unsafe fallback.
7. After ExitBootServices succeeds, WBL MUST make no further boot-service
   calls. Runtime services are outside this ABI's initial scope.

All memory needed for the final handoff—including translated map, BootInfo,
kernel image, and page tables—MUST be allocated before final map acquisition.
The final map must describe those allocations with their correct reserved
kinds. Map-buffer growth must not require firmware services after exit.

## 5. Common handoff invariants

- CPU is executing at the kernel's linked virtual entry address.
- Kernel image and handoff data are mapped and accessible.
- A 4 KiB translation granule and 48-bit virtual address regime are used.
- Kernel entry is executable; data mappings are non-executable where supported.
- Initial page tables remain valid until the kernel explicitly replaces them.
- Handoff is non-returning. Returning from kernel entry is undefined.
- Interrupts are masked at entry. Kernel installs its own exception and
  interrupt handling before unmasking them.
- Kernel MUST NOT assume firmware console or device protocols remain usable.

## 6. x86-64 entry state

WBL enters in 64-bit long mode at CPL 0:

- RIP: kernel_entry.
- RDI: virtual address of BootInfo.
- RSP: 16-byte aligned, pointing to a reserved mapped bootstrap stack.
- RFLAGS.IF = 0 and RFLAGS.DF = 0.
- CR0.PG = 1, CR0.WP = 1, CR4.PAE = 1, and EFER.LME = 1.
- CR3 references WBL-owned initial page tables using four-level paging.
- Kernel image, bootstrap stack, BootInfo, and memory map are mapped.
- Segment selectors describe flat 64-bit kernel code and data segments.
- No general-purpose register other than RDI carries ABI data.

Kernel MUST establish its own GDT, IDT, and page-table policy before relying
on firmware-created descriptor state. The initial stack is temporary and
must be replaced during early initialization.

## 7. AArch64 entry state

WBL enters at EL1 in AArch64 state:

- PC: kernel_entry.
- x0: virtual address of BootInfo.
- SP: 16-byte aligned bootstrap stack.
- PSTATE.DAIF: all four exception classes masked.
- SCTLR_EL1.M = 1; translation uses 4 KiB granules and a 48-bit VA regime.
- TTBR0_EL1, TTBR1_EL1, TCR_EL1, and MAIR_EL1 describe WBL-owned initial
  page tables and memory attributes.
- Kernel image, bootstrap stack, BootInfo, and memory map are mapped.
- No general-purpose register other than x0 carries ABI data.

WBL performs required data-cache clean and instruction-cache synchronization
for the loaded image before branching. Kernel installs its own exception
vectors and establishes its memory-attribute and translation policy before
relying on initial tables. Entry at EL2 is not supported by ABI v2; WBL must
transition to EL1 or fail.

## 8. Validation and failure policy

Kernel validates magic, version, exact structure size, architecture, reserved
fields, map metadata, map ordering and ranges, kernel image bounds, entry
bounds, and optional ACPI pointer alignment before using the data. The
host-side validator checks metadata and an already-accessible map slice; it
does not make an arbitrary physical address safe to dereference.

Malformed or unsupported handoff data is a fatal boot error. Kernel MUST NOT
continue with guessed addresses, partially accepted maps, or assumed
architecture.

## 9. Explicitly out of scope

ABI v2 does not standardize framebuffer geometry, SMP topology, entropy,
SMBIOS, device-tree handoff, runtime-service access, IOMMU state, hibernation,
secure-boot policy, or kernel command-line encoding. These require separate
versioned extensions and must not be placed in reserved fields.

## 10. UEFI application artifact status

The WBL UEFI application locates the filesystem on the same device from
which the firmware loaded the application, opens \EFI\WICOFE\KERNEL.ELF,
and reads it into a bounded UEFI pool allocation. The file size must be
nonzero and no larger than 64 MiB. WBL validates the ELF64 ET_EXEC headers
and PT_LOAD layout for the active architecture using the shared no_std ELF
parser.

WBL then allocates a contiguous physical span with a 2 MiB-aligned base,
bounded to 512 MiB plus alignment slack. The span is zeroed before PT_LOAD
file bytes are copied to their virtual-address-relative offsets; the zeroed
remainder of each segment supplies BSS. Unused prefix and suffix pages are
released when possible. The temporary file buffer and file handles are
released after the copy.

WBL now allocates a separate UEFI page-table pool and invokes the
architecture-specific four-level builder for the kernel PT_LOAD mappings.
The pool is retained on success, and its root physical address and used
table count are recorded internally. The tables remain inactive: WBL does
not load CR3, program AArch64 MAIR/TCR/TTBR state, or establish identity
mappings for its own code, stack, firmware tables, and handoff buffers.
Consequently, this does not yet make the kernel image accessible at its
linked virtual base. WBL also does not create the bootstrap stack, capture
the final memory map, call ExitBootServices, or transfer control to the
kernel. A successful CI build proves PE/COFF compilation
only; it does not prove execution on firmware or QEMU.
