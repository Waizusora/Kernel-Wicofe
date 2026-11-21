#![no_std]

//! Stable, firmware-independent data structures for the WBL-to-kernel handoff.

/// Version of the boot information structure understood by this workspace.
pub const BOOT_INFO_VERSION: u32 = 1;

/// Architecture identifiers carried across the boot boundary.
pub mod architecture {
    /// x86-64 architecture identifier.
    pub const X86_64: u32 = 1;
    /// 64-bit Arm architecture identifier.
    pub const AARCH64: u32 = 2;
}

/// Memory region description passed by WBL.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryRegion {
    /// Physical start address of the region.
    pub physical_start: u64,
    /// Length of the region in bytes.
    pub length: u64,
    /// Firmware-independent memory type assigned by WBL.
    pub kind: u32,
    /// Reserved for ABI-compatible extension; must be zero in version 1.
    pub reserved: u32,
}

/// Initial boot information shared by WBL and Kernel-Wicofe.
///
/// Fixed-width integer addresses keep this structure layout stable on both
/// supported 64-bit architectures.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BootInfo {
    /// Structure version; currently version 1.
    pub version: u32,
    /// Value from the architecture module.
    pub architecture: u32,
    /// Physical address of the memory-region array.
    pub memory_map_address: u64,
    /// Number of entries in the memory-region array.
    pub memory_map_entries: u64,
    /// Size in bytes of each memory-region entry.
    pub memory_map_entry_size: u64,
    /// Physical address where the kernel image was loaded.
    pub kernel_physical_base: u64,
    /// Virtual base expected by the kernel image.
    pub kernel_virtual_base: u64,
    /// Physical address of the ACPI RSDP, or zero when unavailable.
    pub acpi_rsdp_address: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_info_has_stable_v1_layout() {
        assert_eq!(core::mem::size_of::<BootInfo>(), 56);
        assert_eq!(core::mem::align_of::<BootInfo>(), 8);
        assert_eq!(BOOT_INFO_VERSION, 1);
    }

    #[test]
    fn memory_region_has_stable_layout() {
        assert_eq!(core::mem::size_of::<MemoryRegion>(), 24);
        assert_eq!(core::mem::align_of::<MemoryRegion>(), 8);
    }
}
