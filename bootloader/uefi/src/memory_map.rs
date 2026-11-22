//! Firmware-independent translation of UEFI memory descriptors into WBL's canonical map.

use wicofe_bootloader_common::{MemoryRegion, memory_attribute, memory_kind};

pub const EFI_PAGE_SIZE: u64 = 4096;

pub const EFI_RESERVED_MEMORY_TYPE: u32 = 0;
pub const EFI_LOADER_CODE: u32 = 1;
pub const EFI_LOADER_DATA: u32 = 2;
pub const EFI_BOOT_SERVICES_CODE: u32 = 3;
pub const EFI_BOOT_SERVICES_DATA: u32 = 4;
pub const EFI_RUNTIME_SERVICES_CODE: u32 = 5;
pub const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;
pub const EFI_UNUSABLE_MEMORY: u32 = 8;
pub const EFI_ACPI_RECLAIM_MEMORY: u32 = 9;
pub const EFI_ACPI_MEMORY_NVS: u32 = 10;
pub const EFI_MEMORY_MAPPED_IO: u32 = 11;
pub const EFI_MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;
pub const EFI_PAL_CODE: u32 = 13;
pub const EFI_PERSISTENT_MEMORY: u32 = 14;
pub const EFI_UNACCEPTED_MEMORY_TYPE: u32 = 15;

pub const EFI_MEMORY_UC: u64 = 0x0000_0000_0000_0001;
pub const EFI_MEMORY_WC: u64 = 0x0000_0000_0000_0002;
pub const EFI_MEMORY_WT: u64 = 0x0000_0000_0000_0004;
pub const EFI_MEMORY_WB: u64 = 0x0000_0000_0000_0008;
pub const EFI_MEMORY_RUNTIME: u64 = 0x8000_0000_0000_0000;
const EFI_CACHE_MASK: u64 = EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB;

/// Stable prefix of EFI_MEMORY_DESCRIPTOR (40 bytes in UEFI 2.x).
/// Firmware descriptor arrays may use a larger stride; callers must pass
/// individually decoded descriptors rather than assume this is the stride.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UefiMemoryDescriptor {
    pub memory_type: u32,
    pub _padding: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMapError {
    EmptyDescriptor,
    MisalignedPhysicalAddress,
    AddressOverflow,
    OverlappingDescriptors,
    OutputTooSmall,
    ConflictingCacheAttributes,
}

fn classify(memory_type: u32) -> u32 {
    match memory_type {
        EFI_LOADER_CODE | EFI_LOADER_DATA | EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA => {
            memory_kind::BOOTLOADER_RECLAIM
        }
        EFI_RUNTIME_SERVICES_CODE | EFI_RUNTIME_SERVICES_DATA => memory_kind::FIRMWARE_RUNTIME,
        EFI_CONVENTIONAL_MEMORY => memory_kind::USABLE,
        EFI_ACPI_RECLAIM_MEMORY => memory_kind::ACPI_RECLAIM,
        EFI_ACPI_MEMORY_NVS => memory_kind::ACPI_NVS,
        EFI_MEMORY_MAPPED_IO | EFI_MEMORY_MAPPED_IO_PORT_SPACE => memory_kind::MMIO,
        // These defined UEFI types are deliberately never exposed as usable.
        EFI_RESERVED_MEMORY_TYPE
        | EFI_UNUSABLE_MEMORY
        | EFI_PAL_CODE
        | EFI_PERSISTENT_MEMORY
        | EFI_UNACCEPTED_MEMORY_TYPE => memory_kind::RESERVED,
        // Future or vendor-specific types are conservatively reserved too.
        _ => memory_kind::RESERVED,
    }
}

fn translate_attributes(attribute: u64, kind: u32) -> Result<u32, MemoryMapError> {
    let cache = attribute & EFI_CACHE_MASK;
    if cache.count_ones() > 1 {
        return Err(MemoryMapError::ConflictingCacheAttributes);
    }
    let mut translated = match cache {
        EFI_MEMORY_UC => memory_attribute::CACHE_UNCACHED,
        EFI_MEMORY_WC => memory_attribute::CACHE_WRITE_COMBINING,
        EFI_MEMORY_WT => memory_attribute::CACHE_WRITE_THROUGH,
        EFI_MEMORY_WB => memory_attribute::CACHE_WRITE_BACK,
        _ => 0,
    };
    if kind == memory_kind::FIRMWARE_RUNTIME || attribute & EFI_MEMORY_RUNTIME != 0 {
        translated |= memory_attribute::RUNTIME;
    }
    Ok(translated)
}

/// Translate sorted UEFI descriptors into sorted, coalesced canonical regions.
///
/// Unknown UEFI memory types are reserved. The input must be sorted and
/// non-overlapping. No descriptor is ever promoted to USABLE unless its type
/// is EFI_CONVENTIONAL_MEMORY.
pub fn translate_uefi_memory_map(
    descriptors: &[UefiMemoryDescriptor],
    output: &mut [MemoryRegion],
) -> Result<usize, MemoryMapError> {
    let mut count = 0usize;
    for descriptor in descriptors {
        if descriptor.number_of_pages == 0 {
            return Err(MemoryMapError::EmptyDescriptor);
        }
        if descriptor.physical_start % EFI_PAGE_SIZE != 0 {
            return Err(MemoryMapError::MisalignedPhysicalAddress);
        }
        let length = descriptor
            .number_of_pages
            .checked_mul(EFI_PAGE_SIZE)
            .ok_or(MemoryMapError::AddressOverflow)?;
        let end = descriptor
            .physical_start
            .checked_add(length)
            .ok_or(MemoryMapError::AddressOverflow)?;
        let kind = classify(descriptor.memory_type);
        let attributes = translate_attributes(descriptor.attribute, kind)?;

        if count != 0 {
            let previous = output[count - 1];
            let previous_end = previous
                .physical_start
                .checked_add(previous.length)
                .ok_or(MemoryMapError::AddressOverflow)?;
            if descriptor.physical_start < previous_end {
                return Err(MemoryMapError::OverlappingDescriptors);
            }
            if descriptor.physical_start == previous_end
                && previous.kind == kind
                && previous.attributes == attributes
            {
                output[count - 1].length = previous
                    .length
                    .checked_add(length)
                    .ok_or(MemoryMapError::AddressOverflow)?;
                continue;
            }
        }
        if count == output.len() {
            return Err(MemoryMapError::OutputTooSmall);
        }
        output[count] = MemoryRegion {
            physical_start: descriptor.physical_start,
            length: end - descriptor.physical_start,
            kind,
            attributes,
        };
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(
        memory_type: u32,
        start: u64,
        pages: u64,
        attribute: u64,
    ) -> UefiMemoryDescriptor {
        UefiMemoryDescriptor {
            memory_type,
            physical_start: start,
            number_of_pages: pages,
            attribute,
            ..UefiMemoryDescriptor::default()
        }
    }

    #[test]
    fn translates_memory_types_and_cache_attributes() {
        let input = [
            descriptor(EFI_CONVENTIONAL_MEMORY, 0x1000, 4, EFI_MEMORY_WB),
            descriptor(EFI_LOADER_DATA, 0x5000, 2, EFI_MEMORY_WB),
            descriptor(
                EFI_RUNTIME_SERVICES_DATA,
                0x7000,
                1,
                EFI_MEMORY_WT | EFI_MEMORY_RUNTIME,
            ),
            descriptor(EFI_MEMORY_MAPPED_IO, 0x8000, 1, EFI_MEMORY_UC),
            descriptor(0xffff, 0x9000, 1, 0),
        ];
        let mut output = [MemoryRegion::default(); 5];
        let count = translate_uefi_memory_map(&input, &mut output).unwrap();
        assert_eq!(count, 5);
        assert_eq!(output[0].kind, memory_kind::USABLE);
        assert_eq!(output[0].attributes, memory_attribute::CACHE_WRITE_BACK);
        assert_eq!(output[1].kind, memory_kind::BOOTLOADER_RECLAIM);
        assert_eq!(output[2].kind, memory_kind::FIRMWARE_RUNTIME);
        assert_eq!(
            output[2].attributes,
            memory_attribute::CACHE_WRITE_THROUGH | memory_attribute::RUNTIME
        );
        assert_eq!(output[3].kind, memory_kind::MMIO);
        assert_eq!(output[4].kind, memory_kind::RESERVED);
    }

    #[test]
    fn coalesces_adjacent_regions_with_identical_classification() {
        let input = [
            descriptor(EFI_CONVENTIONAL_MEMORY, 0x1000, 2, EFI_MEMORY_WB),
            descriptor(EFI_CONVENTIONAL_MEMORY, 0x3000, 3, EFI_MEMORY_WB),
        ];
        let mut output = [MemoryRegion::default(); 2];
        assert_eq!(translate_uefi_memory_map(&input, &mut output), Ok(1));
        assert_eq!(output[0].physical_start, 0x1000);
        assert_eq!(output[0].length, 5 * EFI_PAGE_SIZE);
    }

    #[test]
    fn rejects_empty_misaligned_overlapping_and_overflowing_descriptors() {
        let mut output = [MemoryRegion::default(); 2];
        assert_eq!(
            translate_uefi_memory_map(
                &[descriptor(EFI_CONVENTIONAL_MEMORY, 0x1000, 0, 0)],
                &mut output
            ),
            Err(MemoryMapError::EmptyDescriptor)
        );
        assert_eq!(
            translate_uefi_memory_map(
                &[descriptor(EFI_CONVENTIONAL_MEMORY, 0x1001, 1, 0)],
                &mut output
            ),
            Err(MemoryMapError::MisalignedPhysicalAddress)
        );
        let overlap = [
            descriptor(EFI_CONVENTIONAL_MEMORY, 0x1000, 2, 0),
            descriptor(EFI_LOADER_DATA, 0x2000, 1, 0),
        ];
        assert_eq!(
            translate_uefi_memory_map(&overlap, &mut output),
            Err(MemoryMapError::OverlappingDescriptors)
        );
        let overflow = [descriptor(EFI_CONVENTIONAL_MEMORY, u64::MAX - 0xfff, 2, 0)];
        assert_eq!(
            translate_uefi_memory_map(&overflow, &mut output),
            Err(MemoryMapError::AddressOverflow)
        );
    }

    #[test]
    fn rejects_conflicting_cache_attributes_and_small_output() {
        let conflicting = [descriptor(
            EFI_CONVENTIONAL_MEMORY,
            0x1000,
            1,
            EFI_MEMORY_WB | EFI_MEMORY_UC,
        )];
        let mut output = [MemoryRegion::default(); 1];
        assert_eq!(
            translate_uefi_memory_map(&conflicting, &mut output),
            Err(MemoryMapError::ConflictingCacheAttributes)
        );
        let input = [
            descriptor(EFI_CONVENTIONAL_MEMORY, 0x1000, 1, 0),
            descriptor(EFI_LOADER_DATA, 0x3000, 1, 0),
        ];
        assert_eq!(
            translate_uefi_memory_map(&input, &mut output),
            Err(MemoryMapError::OutputTooSmall)
        );
    }
}
