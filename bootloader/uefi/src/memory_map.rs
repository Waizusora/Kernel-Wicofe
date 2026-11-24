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

/// Errors returned while decoding a firmware-provided EFI memory-map buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorDecodeError {
    EmptyBuffer,
    DescriptorSizeTooSmall,
    DescriptorSizeMisaligned,
    BufferSizeNotMultipleOfDescriptorSize,
    OutputTooSmall,
    ArithmeticOverflow,
}

const EFI_MEMORY_DESCRIPTOR_PREFIX_SIZE: usize = 40;
const EFI_MEMORY_DESCRIPTOR_ALIGNMENT: usize = 8;

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, DescriptorDecodeError> {
    let end = offset
        .checked_add(4)
        .ok_or(DescriptorDecodeError::ArithmeticOverflow)?;
    let field = bytes
        .get(offset..end)
        .ok_or(DescriptorDecodeError::ArithmeticOverflow)?;
    let mut value = [0u8; 4];
    value.copy_from_slice(field);
    Ok(u32::from_le_bytes(value))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, DescriptorDecodeError> {
    let end = offset
        .checked_add(8)
        .ok_or(DescriptorDecodeError::ArithmeticOverflow)?;
    let field = bytes
        .get(offset..end)
        .ok_or(DescriptorDecodeError::ArithmeticOverflow)?;
    let mut value = [0u8; 8];
    value.copy_from_slice(field);
    Ok(u64::from_le_bytes(value))
}

/// Decode an EFI memory-map byte buffer using the descriptor stride reported
/// by firmware. Only the stable 40-byte EFI_MEMORY_DESCRIPTOR prefix is read;
/// any firmware-specific extension bytes are skipped.
///
/// The buffer and output storage are caller-owned. This function performs no
/// allocation and accepts unaligned buffer addresses safely.
pub fn decode_uefi_memory_descriptors(
    buffer: &[u8],
    descriptor_size: usize,
    output: &mut [UefiMemoryDescriptor],
) -> Result<usize, DescriptorDecodeError> {
    if buffer.is_empty() {
        return Err(DescriptorDecodeError::EmptyBuffer);
    }
    if descriptor_size < EFI_MEMORY_DESCRIPTOR_PREFIX_SIZE {
        return Err(DescriptorDecodeError::DescriptorSizeTooSmall);
    }
    if descriptor_size % EFI_MEMORY_DESCRIPTOR_ALIGNMENT != 0 {
        return Err(DescriptorDecodeError::DescriptorSizeMisaligned);
    }
    if buffer.len() % descriptor_size != 0 {
        return Err(DescriptorDecodeError::BufferSizeNotMultipleOfDescriptorSize);
    }

    let descriptor_count = buffer.len() / descriptor_size;
    if output.len() < descriptor_count {
        return Err(DescriptorDecodeError::OutputTooSmall);
    }

    for (index, destination) in output.iter_mut().take(descriptor_count).enumerate() {
        let start = index
            .checked_mul(descriptor_size)
            .ok_or(DescriptorDecodeError::ArithmeticOverflow)?;
        let prefix_end = start
            .checked_add(EFI_MEMORY_DESCRIPTOR_PREFIX_SIZE)
            .ok_or(DescriptorDecodeError::ArithmeticOverflow)?;
        let descriptor = buffer
            .get(start..prefix_end)
            .ok_or(DescriptorDecodeError::ArithmeticOverflow)?;

        *destination = UefiMemoryDescriptor {
            memory_type: read_u32_le(descriptor, 0)?,
            _padding: read_u32_le(descriptor, 4)?,
            physical_start: read_u64_le(descriptor, 8)?,
            virtual_start: read_u64_le(descriptor, 16)?,
            number_of_pages: read_u64_le(descriptor, 24)?,
            attribute: read_u64_le(descriptor, 32)?,
        };
    }

    Ok(descriptor_count)
}

#[cfg(test)]
mod descriptor_decode_tests {
    use super::*;

    fn write_descriptor(
        buffer: &mut [u8],
        offset: usize,
        memory_type: u32,
        physical_start: u64,
        virtual_start: u64,
        pages: u64,
        attribute: u64,
    ) {
        buffer[offset..offset + 4].copy_from_slice(&memory_type.to_le_bytes());
        buffer[offset + 4..offset + 8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        buffer[offset + 8..offset + 16].copy_from_slice(&physical_start.to_le_bytes());
        buffer[offset + 16..offset + 24].copy_from_slice(&virtual_start.to_le_bytes());
        buffer[offset + 24..offset + 32].copy_from_slice(&pages.to_le_bytes());
        buffer[offset + 32..offset + 40].copy_from_slice(&attribute.to_le_bytes());
    }

    #[test]
    fn decodes_standard_forty_byte_descriptor() {
        let mut bytes = [0u8; 40];
        write_descriptor(
            &mut bytes,
            0,
            EFI_CONVENTIONAL_MEMORY,
            0x1000,
            0,
            4,
            EFI_MEMORY_WB,
        );
        let mut output = [UefiMemoryDescriptor::default(); 1];

        assert_eq!(
            decode_uefi_memory_descriptors(&bytes, 40, &mut output),
            Ok(1)
        );
        assert_eq!(output[0].memory_type, EFI_CONVENTIONAL_MEMORY);
        assert_eq!(output[0]._padding, 0x1234_5678);
        assert_eq!(output[0].physical_start, 0x1000);
        assert_eq!(output[0].virtual_start, 0);
        assert_eq!(output[0].number_of_pages, 4);
        assert_eq!(output[0].attribute, EFI_MEMORY_WB);
    }

    #[test]
    fn honors_firmware_descriptor_strides_larger_than_prefix() {
        let mut bytes_48 = [0u8; 96];
        write_descriptor(
            &mut bytes_48,
            0,
            EFI_CONVENTIONAL_MEMORY,
            0x1000,
            0,
            2,
            EFI_MEMORY_WB,
        );
        write_descriptor(
            &mut bytes_48,
            48,
            EFI_LOADER_DATA,
            0x2000,
            0x7000,
            1,
            EFI_MEMORY_UC,
        );
        let mut bytes_56 = [0u8; 112];
        write_descriptor(
            &mut bytes_56,
            0,
            EFI_CONVENTIONAL_MEMORY,
            0x1000,
            0,
            2,
            EFI_MEMORY_WB,
        );
        write_descriptor(
            &mut bytes_56,
            56,
            EFI_LOADER_DATA,
            0x3000,
            0x8000,
            1,
            EFI_MEMORY_UC,
        );
        let mut output = [UefiMemoryDescriptor::default(); 2];

        assert_eq!(
            decode_uefi_memory_descriptors(&bytes_48, 48, &mut output),
            Ok(2)
        );
        assert_eq!(output[1].memory_type, EFI_LOADER_DATA);
        assert_eq!(output[1].physical_start, 0x2000);
        assert_eq!(output[1].virtual_start, 0x7000);

        assert_eq!(
            decode_uefi_memory_descriptors(&bytes_56, 56, &mut output),
            Ok(2)
        );
        assert_eq!(output[0].physical_start, 0x1000);
        assert_eq!(output[1].memory_type, EFI_LOADER_DATA);
        assert_eq!(output[1].physical_start, 0x3000);
        assert_eq!(output[1].virtual_start, 0x8000);
        assert_eq!(output[1].attribute, EFI_MEMORY_UC);
    }

    #[test]
    fn decodes_unaligned_buffer_without_unaligned_reads() {
        let mut storage = [0u8; 57];
        write_descriptor(
            &mut storage,
            1,
            EFI_LOADER_DATA,
            0x9000,
            0,
            3,
            EFI_MEMORY_WB,
        );
        let mut output = [UefiMemoryDescriptor::default(); 1];

        assert_eq!(
            decode_uefi_memory_descriptors(&storage[1..], 56, &mut output),
            Ok(1)
        );
        assert_eq!(output[0].physical_start, 0x9000);
        assert_eq!(output[0].number_of_pages, 3);
    }

    #[test]
    fn rejects_invalid_buffer_and_descriptor_strides() {
        let mut output = [UefiMemoryDescriptor::default(); 2];
        assert_eq!(
            decode_uefi_memory_descriptors(&[], 40, &mut output),
            Err(DescriptorDecodeError::EmptyBuffer)
        );
        assert_eq!(
            decode_uefi_memory_descriptors(&[0; 39], 39, &mut output),
            Err(DescriptorDecodeError::DescriptorSizeTooSmall)
        );
        assert_eq!(
            decode_uefi_memory_descriptors(&[0; 40], 41, &mut output),
            Err(DescriptorDecodeError::DescriptorSizeMisaligned)
        );
        assert_eq!(
            decode_uefi_memory_descriptors(&[0; 41], 40, &mut output),
            Err(DescriptorDecodeError::BufferSizeNotMultipleOfDescriptorSize)
        );
        assert_eq!(
            decode_uefi_memory_descriptors(&[0; 112], 56, &mut output[..1]),
            Err(DescriptorDecodeError::OutputTooSmall)
        );
    }
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
    fn all_uefi_loader_owned_allocation_types_remain_non_usable() {
        let input = [
            descriptor(EFI_LOADER_CODE, 0x1000, 1, EFI_MEMORY_WB),
            descriptor(EFI_LOADER_DATA, 0x2000, 1, EFI_MEMORY_WB),
            descriptor(EFI_BOOT_SERVICES_CODE, 0x3000, 1, EFI_MEMORY_WB),
            descriptor(EFI_BOOT_SERVICES_DATA, 0x4000, 1, EFI_MEMORY_WB),
            descriptor(EFI_CONVENTIONAL_MEMORY, 0x5000, 1, EFI_MEMORY_WB),
        ];
        let mut output = [MemoryRegion::default(); 5];

        assert_eq!(translate_uefi_memory_map(&input, &mut output), Ok(5));
        for region in &output[..4] {
            assert_eq!(region.kind, memory_kind::BOOTLOADER_RECLAIM);
            assert_ne!(region.kind, memory_kind::USABLE);
        }
        assert_eq!(output[4].kind, memory_kind::USABLE);
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
