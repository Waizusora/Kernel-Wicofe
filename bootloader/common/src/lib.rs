#![no_std]

//! Stable, firmware-independent data structures for the WBL-to-kernel handoff.

pub const BOOT_INFO_MAGIC: u64 = 0x5749_434F_4645_4249;
pub const BOOT_INFO_VERSION: u32 = 2;
pub const KERNEL_IMAGE_ALIGNMENT: u64 = 2 * 1024 * 1024;
pub const BOOTSTRAP_STACK_PAGE_SIZE: u64 = 4096;
pub const BOOTSTRAP_STACK_GUARD_SIZE: u64 = BOOTSTRAP_STACK_PAGE_SIZE;
pub const BOOTSTRAP_STACK_SIZE: u64 = 64 * 1024;
pub const BOOTSTRAP_STACK_ALIGNMENT: u64 = 16;

/// Fixed physical allocation layout for the initial kernel stack.
///
/// The first page is deliberately excluded from the usable stack and remains
/// unmapped as a guard. The stack grows down from the allocation end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapStackLayout {
    pub guard_size: u64,
    pub stack_size: u64,
    pub allocation_size: u64,
}

pub const BOOTSTRAP_STACK_LAYOUT: BootstrapStackLayout = BootstrapStackLayout {
    guard_size: BOOTSTRAP_STACK_GUARD_SIZE,
    stack_size: BOOTSTRAP_STACK_SIZE,
    allocation_size: BOOTSTRAP_STACK_GUARD_SIZE + BOOTSTRAP_STACK_SIZE,
};

/// Return the initial stack pointer for a page-aligned stack allocation.
///
/// The guard occupies the first page. The returned top is exclusive and is
/// suitable for an initially empty downward-growing stack.
pub const fn bootstrap_stack_top(allocation_base: u64) -> Option<u64> {
    if allocation_base == 0 || allocation_base % BOOTSTRAP_STACK_PAGE_SIZE != 0 {
        return None;
    }
    allocation_base.checked_add(BOOTSTRAP_STACK_LAYOUT.allocation_size)
}

pub mod architecture {
    pub const X86_64: u32 = 1;
    pub const AARCH64: u32 = 2;
}

pub mod memory_kind {
    pub const USABLE: u32 = 1;
    pub const RESERVED: u32 = 2;
    pub const ACPI_RECLAIM: u32 = 3;
    pub const ACPI_NVS: u32 = 4;
    pub const MMIO: u32 = 5;
    pub const FRAMEBUFFER: u32 = 6;
    pub const BOOTLOADER_RECLAIM: u32 = 7;
    pub const KERNEL: u32 = 8;
    pub const BOOT_INFO: u32 = 9;
    pub const FIRMWARE_RUNTIME: u32 = 10;
}

pub mod memory_attribute {
    pub const CACHE_WRITE_BACK: u32 = 1 << 0;
    pub const CACHE_WRITE_THROUGH: u32 = 1 << 1;
    pub const CACHE_WRITE_COMBINING: u32 = 1 << 2;
    pub const CACHE_UNCACHED: u32 = 1 << 3;
    pub const RUNTIME: u32 = 1 << 4;
    pub const CACHE_MASK: u32 =
        CACHE_WRITE_BACK | CACHE_WRITE_THROUGH | CACHE_WRITE_COMBINING | CACHE_UNCACHED;
    pub const VALID_MASK: u32 = CACHE_MASK | RUNTIME;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryRegion {
    pub physical_start: u64,
    pub length: u64,
    pub kind: u32,
    pub attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    pub struct_size: u32,
    pub architecture: u32,
    pub flags: u32,
    pub memory_map_address: u64,
    pub memory_map_entries: u64,
    pub memory_map_entry_size: u32,
    pub reserved: u32,
    pub kernel_physical_base: u64,
    pub kernel_virtual_base: u64,
    pub kernel_image_size: u64,
    pub kernel_entry: u64,
    pub acpi_rsdp_address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootInfoError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidStructureSize,
    UnsupportedArchitecture,
    NonZeroReservedField,
    InvalidMemoryMap,
    InvalidMemoryRegion,
    InvalidMemoryAttributes,
    OverlappingMemoryRegions,
    InvalidKernelImage,
    InvalidAcpiPointer,
}

/// Validate ABI metadata and an already-accessible canonical memory map.
///
/// The caller must map and bounds-check the physical array before constructing
/// the slice. This function does not make an arbitrary physical address safe.
pub fn validate_boot_info(
    info: &BootInfo,
    memory_map: &[MemoryRegion],
) -> Result<(), BootInfoError> {
    if info.magic != BOOT_INFO_MAGIC {
        return Err(BootInfoError::InvalidMagic);
    }
    if info.version != BOOT_INFO_VERSION {
        return Err(BootInfoError::UnsupportedVersion);
    }
    if info.struct_size as usize != core::mem::size_of::<BootInfo>() {
        return Err(BootInfoError::InvalidStructureSize);
    }
    if info.architecture != architecture::X86_64 && info.architecture != architecture::AARCH64 {
        return Err(BootInfoError::UnsupportedArchitecture);
    }
    if info.flags != 0 || info.reserved != 0 {
        return Err(BootInfoError::NonZeroReservedField);
    }
    if info.memory_map_entries == 0
        || info.memory_map_entries != memory_map.len() as u64
        || info.memory_map_address == 0
        || info.memory_map_address % 8 != 0
        || info.memory_map_entry_size as usize != core::mem::size_of::<MemoryRegion>()
    {
        return Err(BootInfoError::InvalidMemoryMap);
    }

    let mut previous_end = 0_u64;
    for (index, region) in memory_map.iter().enumerate() {
        let end = region
            .physical_start
            .checked_add(region.length)
            .ok_or(BootInfoError::InvalidMemoryRegion)?;
        if region.length == 0
            || region.physical_start % 4096 != 0
            || region.length % 4096 != 0
            || !is_valid_memory_kind(region.kind)
        {
            return Err(BootInfoError::InvalidMemoryRegion);
        }
        if region.attributes & !memory_attribute::VALID_MASK != 0 {
            return Err(BootInfoError::InvalidMemoryAttributes);
        }
        if (region.attributes & memory_attribute::CACHE_MASK).count_ones() > 1 {
            return Err(BootInfoError::InvalidMemoryAttributes);
        }
        if index != 0 && region.physical_start < previous_end {
            return Err(BootInfoError::OverlappingMemoryRegions);
        }
        previous_end = end;
    }

    let expected_virtual_base = match info.architecture {
        architecture::X86_64 => 0xffff_ffff_8000_0000,
        architecture::AARCH64 => 0xffff_0000_0000_0000,
        _ => return Err(BootInfoError::UnsupportedArchitecture),
    };
    let kernel_virtual_end = info
        .kernel_virtual_base
        .checked_add(info.kernel_image_size)
        .ok_or(BootInfoError::InvalidKernelImage)?;
    if info.kernel_physical_base == 0
        || info.kernel_physical_base % KERNEL_IMAGE_ALIGNMENT != 0
        || info.kernel_virtual_base != expected_virtual_base
        || info.kernel_virtual_base % KERNEL_IMAGE_ALIGNMENT != 0
        || info.kernel_image_size == 0
        || info.kernel_entry < info.kernel_virtual_base
        || info.kernel_entry >= kernel_virtual_end
        || info
            .kernel_physical_base
            .checked_add(info.kernel_image_size)
            .is_none()
    {
        return Err(BootInfoError::InvalidKernelImage);
    }

    if info.acpi_rsdp_address != 0 && info.acpi_rsdp_address % 8 != 0 {
        return Err(BootInfoError::InvalidAcpiPointer);
    }
    Ok(())
}

const fn is_valid_memory_kind(kind: u32) -> bool {
    matches!(
        kind,
        memory_kind::USABLE
            | memory_kind::RESERVED
            | memory_kind::ACPI_RECLAIM
            | memory_kind::ACPI_NVS
            | memory_kind::MMIO
            | memory_kind::FRAMEBUFFER
            | memory_kind::BOOTLOADER_RECLAIM
            | memory_kind::KERNEL
            | memory_kind::BOOT_INFO
            | memory_kind::FIRMWARE_RUNTIME
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_map() -> [MemoryRegion; 2] {
        [
            MemoryRegion {
                physical_start: 0x0010_0000,
                length: 0x0010_0000,
                kind: memory_kind::RESERVED,
                attributes: 0,
            },
            MemoryRegion {
                physical_start: 0x0020_0000,
                length: 0x0040_0000,
                kind: memory_kind::USABLE,
                attributes: memory_attribute::CACHE_WRITE_BACK,
            },
        ]
    }

    fn valid_info() -> BootInfo {
        BootInfo {
            magic: BOOT_INFO_MAGIC,
            version: BOOT_INFO_VERSION,
            struct_size: core::mem::size_of::<BootInfo>() as u32,
            architecture: architecture::X86_64,
            flags: 0,
            memory_map_address: 0x8000,
            memory_map_entries: 2,
            memory_map_entry_size: core::mem::size_of::<MemoryRegion>() as u32,
            reserved: 0,
            kernel_physical_base: 0x20_0000,
            kernel_virtual_base: 0xffff_ffff_8000_0000,
            kernel_image_size: 0x20_0000,
            kernel_entry: 0xffff_ffff_8000_1000,
            acpi_rsdp_address: 0x7e000,
        }
    }

    #[test]
    fn bootstrap_stack_layout_reserves_guard_and_aligned_stack() {
        assert_eq!(BOOTSTRAP_STACK_LAYOUT.guard_size, 4096);
        assert_eq!(BOOTSTRAP_STACK_LAYOUT.stack_size, 64 * 1024);
        assert_eq!(BOOTSTRAP_STACK_LAYOUT.allocation_size, 68 * 1024);
        let base = 0x20_0000;
        let top = bootstrap_stack_top(base).unwrap();
        assert_eq!(top - base, BOOTSTRAP_STACK_LAYOUT.allocation_size);
        assert_eq!(top % BOOTSTRAP_STACK_ALIGNMENT, 0);
    }

    #[test]
    fn bootstrap_stack_top_rejects_invalid_base_and_overflow() {
        assert_eq!(bootstrap_stack_top(0), None);
        assert_eq!(bootstrap_stack_top(0x1001), None);
        assert_eq!(
            bootstrap_stack_top(u64::MAX & !(BOOTSTRAP_STACK_PAGE_SIZE - 1)),
            None
        );
    }
    #[test]
    fn boot_info_has_stable_v2_layout() {
        assert_eq!(core::mem::size_of::<BootInfo>(), 88);
        assert_eq!(core::mem::align_of::<BootInfo>(), 8);
        assert_eq!(core::mem::offset_of!(BootInfo, memory_map_address), 24);
        assert_eq!(core::mem::offset_of!(BootInfo, kernel_physical_base), 48);
        assert_eq!(core::mem::offset_of!(BootInfo, kernel_entry), 72);
        assert_eq!(BOOT_INFO_VERSION, 2);
    }

    #[test]
    fn memory_region_has_stable_layout() {
        assert_eq!(core::mem::size_of::<MemoryRegion>(), 24);
        assert_eq!(core::mem::align_of::<MemoryRegion>(), 8);
    }

    #[test]
    fn accepts_valid_x86_64_handoff() {
        assert_eq!(validate_boot_info(&valid_info(), &valid_map()), Ok(()));
    }

    #[test]
    fn accepts_valid_aarch64_handoff() {
        let mut info = valid_info();
        info.architecture = architecture::AARCH64;
        info.kernel_virtual_base = 0xffff_0000_0000_0000;
        info.kernel_entry = info.kernel_virtual_base + 0x1000;
        assert_eq!(validate_boot_info(&info, &valid_map()), Ok(()));
    }

    #[test]
    fn rejects_bad_magic_and_version() {
        let map = valid_map();
        let mut info = valid_info();
        info.magic = 0;
        assert_eq!(
            validate_boot_info(&info, &map),
            Err(BootInfoError::InvalidMagic)
        );
        info = valid_info();
        info.version += 1;
        assert_eq!(
            validate_boot_info(&info, &map),
            Err(BootInfoError::UnsupportedVersion)
        );
    }

    #[test]
    fn rejects_bad_map_metadata_and_overlap() {
        let mut info = valid_info();
        let map = valid_map();
        info.memory_map_entry_size = 8;
        assert_eq!(
            validate_boot_info(&info, &map),
            Err(BootInfoError::InvalidMemoryMap)
        );
        info = valid_info();
        let mut overlapping = map;
        overlapping[1].physical_start = 0x0018_0000;
        assert_eq!(
            validate_boot_info(&info, &overlapping),
            Err(BootInfoError::OverlappingMemoryRegions)
        );
    }

    #[test]
    fn rejects_overflow_and_misaligned_regions() {
        let info = valid_info();
        let mut map = valid_map();
        map[1].physical_start = u64::MAX - 0xfff;
        map[1].length = 0x2000;
        assert_eq!(
            validate_boot_info(&info, &map),
            Err(BootInfoError::InvalidMemoryRegion)
        );
        map = valid_map();
        map[0].physical_start += 1;
        assert_eq!(
            validate_boot_info(&info, &map),
            Err(BootInfoError::InvalidMemoryRegion)
        );
    }

    #[test]
    fn rejects_kernel_entry_outside_image_and_reserved_flags() {
        let map = valid_map();
        let mut info = valid_info();
        info.kernel_entry = info.kernel_virtual_base + info.kernel_image_size;
        assert_eq!(
            validate_boot_info(&info, &map),
            Err(BootInfoError::InvalidKernelImage)
        );
        info = valid_info();
        info.flags = 1;
        assert_eq!(
            validate_boot_info(&info, &map),
            Err(BootInfoError::NonZeroReservedField)
        );
    }

    #[test]
    fn rejects_conflicting_cache_attributes() {
        let info = valid_info();
        let mut map = valid_map();
        map[1].attributes = memory_attribute::CACHE_WRITE_BACK | memory_attribute::CACHE_UNCACHED;
        assert_eq!(
            validate_boot_info(&info, &map),
            Err(BootInfoError::InvalidMemoryAttributes)
        );
    }
}
