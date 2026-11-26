//! Kernel-side validation of the WBL boot handoff.
//!
//! This module accepts only an already mapped and bounds-checked memory-map
//! slice. Mapping arbitrary physical addresses is the responsibility of the
//! architecture entry code and must happen before this API is called.

use crate::memory::{BitmapAllocatorError, BitmapFrameAllocator, FrameAllocator, PhysicalRange};
use wicofe_bootloader_common::{
    BootInfo, BootInfoError, MemoryRegion, architecture, validate_boot_info,
};

/// Failure while validating the boot contract for this kernel image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelBootError {
    InvalidBootInfo(BootInfoError),
    ArchitectureMismatch { expected: u32, actual: u32 },
    KernelImageNotReserved,
}

/// A boot handoff whose ABI, architecture, and memory-map metadata were checked.
///
/// The references remain borrowed from the caller. The memory map must already
/// be mapped, bounds-checked, canonical, and must classify all live loader,
/// kernel, page-table, stack, and handoff allocations as non-usable.
pub struct ValidatedBootHandoff<'a> {
    info: &'a BootInfo,
    memory_map: &'a [MemoryRegion],
}

impl<'a> ValidatedBootHandoff<'a> {
    /// Validate ABI v2 metadata and ensure the handoff targets this architecture.
    ///
    /// `expected_architecture` must be one of
    /// `wicofe_bootloader_common::architecture::{X86_64, AARCH64}`.
    /// The supplied memory map must already be safely accessible.
    pub fn new(
        expected_architecture: u32,
        info: &'a BootInfo,
        memory_map: &'a [MemoryRegion],
    ) -> Result<Self, KernelBootError> {
        validate_boot_info(info, memory_map).map_err(KernelBootError::InvalidBootInfo)?;

        if expected_architecture != architecture::X86_64
            && expected_architecture != architecture::AARCH64
        {
            return Err(KernelBootError::ArchitectureMismatch {
                expected: expected_architecture,
                actual: info.architecture,
            });
        }

        if info.architecture != expected_architecture {
            return Err(KernelBootError::ArchitectureMismatch {
                expected: expected_architecture,
                actual: info.architecture,
            });
        }

        let kernel_image_end = info
            .kernel_physical_base
            .checked_add(info.kernel_image_size)
            .ok_or(KernelBootError::KernelImageNotReserved)?;
        if !range_is_covered_by_kind(
            memory_map,
            info.kernel_physical_base,
            kernel_image_end,
            wicofe_bootloader_common::memory_kind::KERNEL,
        ) {
            return Err(KernelBootError::KernelImageNotReserved);
        }

        Ok(Self { info, memory_map })
    }

    /// Return the validated boot metadata.
    pub const fn info(&self) -> &'a BootInfo {
        self.info
    }

    /// Return the validated canonical memory map.
    pub const fn memory_map(&self) -> &'a [MemoryRegion] {
        self.memory_map
    }

    /// Create a bitmap allocator from this validated memory map.
    ///
    /// The caller supplies storage for the bitmap and any additional physical
    /// reservations. The bitmap storage itself must already be backed by memory
    /// that is not available to the allocator (normally reserved by the WBL map).
    pub fn bitmap_frame_allocator<'b>(
        &'b self,
        reservations: &'b [PhysicalRange],
        bitmap: &'b mut [u64],
    ) -> Result<BitmapFrameAllocator<'b>, BitmapAllocatorError>
    where
        'a: 'b,
    {
        BitmapFrameAllocator::new(self.memory_map, reservations, bitmap)
    }

    /// Create the early allocator over regions marked USABLE by the handoff.
    ///
    /// This does not independently reserve live allocations: the WBL memory
    /// map must already mark every such range as non-usable before validation.
    pub const fn frame_allocator(&self) -> FrameAllocator<'a> {
        FrameAllocator::new(self.memory_map)
    }
}

/// Validate ABI v2 metadata and ensure the handoff targets this architecture.
///
/// Prefer [`ValidatedBootHandoff::new`] when subsequent kernel initialization
/// needs to retain the validated references and construct memory services.
pub fn validate_boot_handoff(
    expected_architecture: u32,
    info: &BootInfo,
    memory_map: &[MemoryRegion],
) -> Result<(), KernelBootError> {
    ValidatedBootHandoff::new(expected_architecture, info, memory_map).map(|_| ())
}

/// Check that a half-open physical range is continuously classified as one
/// memory kind. The input map has already passed ordering and overlap checks.
fn range_is_covered_by_kind(
    memory_map: &[MemoryRegion],
    start: u64,
    end: u64,
    expected_kind: u32,
) -> bool {
    if start >= end {
        return false;
    }

    let mut cursor = start;
    for region in memory_map {
        let region_end = match region.physical_start.checked_add(region.length) {
            Some(value) => value,
            None => return false,
        };
        if region_end <= cursor {
            continue;
        }
        if region.physical_start > cursor || region.kind != expected_kind {
            return false;
        }
        cursor = region_end.min(end);
        if cursor == end {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicofe_bootloader_common::{
        BOOT_INFO_MAGIC, BOOT_INFO_VERSION, memory_attribute, memory_kind,
    };

    fn valid_map() -> [MemoryRegion; 3] {
        [
            MemoryRegion {
                physical_start: 0x0010_0000,
                length: 0x0010_0000,
                kind: memory_kind::RESERVED,
                attributes: 0,
            },
            MemoryRegion {
                physical_start: 0x0020_0000,
                length: 0x0020_0000,
                kind: memory_kind::KERNEL,
                attributes: memory_attribute::CACHE_WRITE_BACK,
            },
            MemoryRegion {
                physical_start: 0x0040_0000,
                length: 0x0040_0000,
                kind: memory_kind::USABLE,
                attributes: memory_attribute::CACHE_WRITE_BACK,
            },
        ]
    }

    fn valid_info(architecture_id: u32) -> BootInfo {
        let virtual_base = match architecture_id {
            architecture::X86_64 => 0xffff_ffff_8000_0000,
            architecture::AARCH64 => 0xffff_0000_0000_0000,
            _ => 0,
        };
        BootInfo {
            magic: BOOT_INFO_MAGIC,
            version: BOOT_INFO_VERSION,
            struct_size: core::mem::size_of::<BootInfo>() as u32,
            architecture: architecture_id,
            flags: 0,
            memory_map_address: 0x8000,
            memory_map_entries: 3,
            memory_map_entry_size: core::mem::size_of::<MemoryRegion>() as u32,
            reserved: 0,
            kernel_physical_base: 0x20_0000,
            kernel_virtual_base: virtual_base,
            kernel_image_size: 0x20_0000,
            kernel_entry: virtual_base + 0x1000,
            acpi_rsdp_address: 0x7e000,
        }
    }

    #[test]
    fn accepts_matching_x86_64_handoff() {
        assert_eq!(
            validate_boot_handoff(
                architecture::X86_64,
                &valid_info(architecture::X86_64),
                &valid_map(),
            ),
            Ok(())
        );
    }

    #[test]
    fn accepts_matching_aarch64_handoff() {
        assert_eq!(
            validate_boot_handoff(
                architecture::AARCH64,
                &valid_info(architecture::AARCH64),
                &valid_map(),
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_cross_architecture_handoff() {
        assert_eq!(
            validate_boot_handoff(
                architecture::X86_64,
                &valid_info(architecture::AARCH64),
                &valid_map(),
            ),
            Err(KernelBootError::ArchitectureMismatch {
                expected: architecture::X86_64,
                actual: architecture::AARCH64,
            })
        );
    }

    #[test]
    fn rejects_kernel_image_marked_as_usable_memory() {
        let info = valid_info(architecture::X86_64);
        let mut map = valid_map();
        map[1].kind = memory_kind::USABLE;
        assert_eq!(
            validate_boot_handoff(architecture::X86_64, &info, &map),
            Err(KernelBootError::KernelImageNotReserved)
        );
    }

    #[test]
    fn rejects_partially_reserved_kernel_image() {
        let info = valid_info(architecture::X86_64);
        let map = [
            MemoryRegion {
                physical_start: 0x0010_0000,
                length: 0x0010_0000,
                kind: memory_kind::RESERVED,
                attributes: 0,
            },
            MemoryRegion {
                physical_start: 0x0020_0000,
                length: 0x0010_0000,
                kind: memory_kind::KERNEL,
                attributes: memory_attribute::CACHE_WRITE_BACK,
            },
            MemoryRegion {
                physical_start: 0x0030_0000,
                length: 0x0050_0000,
                kind: memory_kind::USABLE,
                attributes: memory_attribute::CACHE_WRITE_BACK,
            },
        ];
        assert_eq!(
            validate_boot_handoff(architecture::X86_64, &info, &map),
            Err(KernelBootError::KernelImageNotReserved)
        );
    }

    #[test]
    fn rejects_invalid_boot_info_before_architecture_acceptance() {
        let mut info = valid_info(architecture::X86_64);
        info.magic = 0;
        assert_eq!(
            validate_boot_handoff(architecture::X86_64, &info, &valid_map()),
            Err(KernelBootError::InvalidBootInfo(
                BootInfoError::InvalidMagic
            ))
        );
    }

    #[test]
    fn validated_handoff_initializes_bitmap_allocator() {
        let info = valid_info(architecture::X86_64);
        let map = valid_map();
        let handoff = ValidatedBootHandoff::new(architecture::X86_64, &info, &map).unwrap();
        let mut bitmap = [0u64; 16];
        let mut allocator = handoff.bitmap_frame_allocator(&[], &mut bitmap).unwrap();

        assert_eq!(allocator.frame_count(), 1024);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x0040_0000);
    }

    #[test]
    fn validated_handoff_provides_allocator_for_canonical_map() {
        let info = valid_info(architecture::X86_64);
        let map = valid_map();
        let handoff = ValidatedBootHandoff::new(architecture::X86_64, &info, &map).unwrap();
        let mut allocator = handoff.frame_allocator();

        assert_eq!(handoff.info().architecture, architecture::X86_64);
        assert_eq!(handoff.memory_map().len(), 2);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x0040_0000);
    }
}
