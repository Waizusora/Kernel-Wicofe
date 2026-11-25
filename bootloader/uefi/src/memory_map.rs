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
pub enum ActiveStackMappingError {
    NoContainingDescriptor,
    UnsupportedMemoryType,
    InvalidDescriptorRange,
    DescriptorChanged,
}

/// Confirm that the active firmware stack still occupies the exact descriptor
/// range captured when its identity mapping was planned.
pub fn validate_active_stack_mapping(
    descriptors: &[UefiMemoryDescriptor],
    expected_start: u64,
    expected_length: u64,
    stack_pointer: u64,
) -> Result<(), ActiveStackMappingError> {
    let descriptor = descriptors
        .iter()
        .find(|descriptor| {
            let Some(length) = descriptor.number_of_pages.checked_mul(EFI_PAGE_SIZE) else {
                return false;
            };
            let Some(end) = descriptor.physical_start.checked_add(length) else {
                return false;
            };
            descriptor.number_of_pages != 0
                && stack_pointer >= descriptor.physical_start
                && stack_pointer < end
        })
        .ok_or(ActiveStackMappingError::NoContainingDescriptor)?;

    if descriptor.memory_type != EFI_LOADER_DATA && descriptor.memory_type != EFI_BOOT_SERVICES_DATA
    {
        return Err(ActiveStackMappingError::UnsupportedMemoryType);
    }
    let length = descriptor
        .number_of_pages
        .checked_mul(EFI_PAGE_SIZE)
        .ok_or(ActiveStackMappingError::InvalidDescriptorRange)?;
    if descriptor.physical_start != expected_start || length != expected_length {
        return Err(ActiveStackMappingError::DescriptorChanged);
    }
    Ok(())
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

/// A page-aligned, loader-owned physical range that must remain unavailable to allocators.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryReservation {
    pub physical_start: u64,
    pub length: u64,
    pub kind: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationError {
    InvalidRange,
    UnsupportedKind,
    UnsortedOrOverlappingReservations,
    NotContainedInLoaderMemory,
    AddressOverflow,
    OutputTooSmall,
}

fn push_region(
    output: &mut [MemoryRegion],
    count: &mut usize,
    region: MemoryRegion,
) -> Result<(), ReservationError> {
    if region.length == 0 {
        return Ok(());
    }
    if *count != 0 {
        let previous = output[*count - 1];
        let previous_end = previous
            .physical_start
            .checked_add(previous.length)
            .ok_or(ReservationError::AddressOverflow)?;
        if previous_end == region.physical_start
            && previous.kind == region.kind
            && previous.attributes == region.attributes
        {
            output[*count - 1].length = previous
                .length
                .checked_add(region.length)
                .ok_or(ReservationError::AddressOverflow)?;
            return Ok(());
        }
    }
    if *count == output.len() {
        return Err(ReservationError::OutputTooSmall);
    }
    output[*count] = region;
    *count += 1;
    Ok(())
}

/// Overlay explicit reservations on canonical UEFI regions.
///
/// Reservations must be sorted, page-aligned, non-overlapping, and fully
/// contained in one BOOTLOADER_RECLAIM region. Original cache/runtime
/// attributes are preserved. The input map is not modified.
pub fn apply_memory_reservations(
    regions: &[MemoryRegion],
    reservations: &[MemoryReservation],
    output: &mut [MemoryRegion],
) -> Result<usize, ReservationError> {
    let mut previous_reservation_end = 0_u64;
    for reservation in reservations {
        if reservation.length == 0
            || reservation.physical_start % EFI_PAGE_SIZE != 0
            || reservation.length % EFI_PAGE_SIZE != 0
        {
            return Err(ReservationError::InvalidRange);
        }
        if reservation.kind != memory_kind::KERNEL && reservation.kind != memory_kind::BOOT_INFO {
            return Err(ReservationError::UnsupportedKind);
        }
        let end = reservation
            .physical_start
            .checked_add(reservation.length)
            .ok_or(ReservationError::AddressOverflow)?;
        if reservation.physical_start < previous_reservation_end {
            return Err(ReservationError::UnsortedOrOverlappingReservations);
        }
        previous_reservation_end = end;
    }

    let mut count = 0usize;
    let mut reservation_index = 0usize;
    for region in regions {
        let region_end = region
            .physical_start
            .checked_add(region.length)
            .ok_or(ReservationError::AddressOverflow)?;
        let mut cursor = region.physical_start;

        while reservation_index < reservations.len()
            && reservations[reservation_index].physical_start < region_end
        {
            let reservation = reservations[reservation_index];
            let reservation_end = reservation
                .physical_start
                .checked_add(reservation.length)
                .ok_or(ReservationError::AddressOverflow)?;
            if reservation.physical_start < cursor || reservation_end > region_end {
                return Err(ReservationError::NotContainedInLoaderMemory);
            }
            if region.kind != memory_kind::BOOTLOADER_RECLAIM {
                return Err(ReservationError::NotContainedInLoaderMemory);
            }

            push_region(
                output,
                &mut count,
                MemoryRegion {
                    physical_start: cursor,
                    length: reservation.physical_start - cursor,
                    kind: region.kind,
                    attributes: region.attributes,
                },
            )?;
            push_region(
                output,
                &mut count,
                MemoryRegion {
                    physical_start: reservation.physical_start,
                    length: reservation.length,
                    kind: reservation.kind,
                    attributes: region.attributes,
                },
            )?;
            cursor = reservation_end;
            reservation_index += 1;
        }

        push_region(
            output,
            &mut count,
            MemoryRegion {
                physical_start: cursor,
                length: region_end
                    .checked_sub(cursor)
                    .ok_or(ReservationError::AddressOverflow)?,
                kind: region.kind,
                attributes: region.attributes,
            },
        )?;
    }

    if reservation_index != reservations.len() {
        return Err(ReservationError::NotContainedInLoaderMemory);
    }
    Ok(count)
}

/// Apply reservations directly to a canonical map buffer without allocating scratch memory.
///
/// The map is validated before mutation. Each reservation must fit in one original
/// BOOTLOADER_RECLAIM region; adjacent descriptors are not silently combined.
pub fn apply_memory_reservations_in_place(
    regions: &mut [MemoryRegion],
    region_count: usize,
    reservations: &[MemoryReservation],
) -> Result<usize, ReservationError> {
    if region_count > regions.len() {
        return Err(ReservationError::OutputTooSmall);
    }

    let mut previous_region_end = 0_u64;
    for region in regions.iter().take(region_count) {
        if region.length == 0 {
            return Err(ReservationError::InvalidRange);
        }
        let end = region
            .physical_start
            .checked_add(region.length)
            .ok_or(ReservationError::AddressOverflow)?;
        if region.physical_start < previous_region_end {
            return Err(ReservationError::UnsortedOrOverlappingReservations);
        }
        previous_region_end = end;
    }

    let mut previous_reservation_end = 0_u64;
    for reservation in reservations {
        if reservation.length == 0
            || reservation.physical_start % EFI_PAGE_SIZE != 0
            || reservation.length % EFI_PAGE_SIZE != 0
        {
            return Err(ReservationError::InvalidRange);
        }
        if reservation.kind != memory_kind::KERNEL && reservation.kind != memory_kind::BOOT_INFO {
            return Err(ReservationError::UnsupportedKind);
        }
        let end = reservation
            .physical_start
            .checked_add(reservation.length)
            .ok_or(ReservationError::AddressOverflow)?;
        if reservation.physical_start < previous_reservation_end {
            return Err(ReservationError::UnsortedOrOverlappingReservations);
        }
        previous_reservation_end = end;

        let containing = regions.iter().take(region_count).find(|region| {
            let Some(region_end) = region.physical_start.checked_add(region.length) else {
                return false;
            };
            reservation.physical_start >= region.physical_start && end <= region_end
        });
        if !containing.is_some_and(|region| region.kind == memory_kind::BOOTLOADER_RECLAIM) {
            return Err(ReservationError::NotContainedInLoaderMemory);
        }
    }

    let mut count = region_count;
    for reservation in reservations {
        let reservation_end = reservation
            .physical_start
            .checked_add(reservation.length)
            .ok_or(ReservationError::AddressOverflow)?;
        let index = regions
            .iter()
            .take(count)
            .position(|region| {
                let Some(region_end) = region.physical_start.checked_add(region.length) else {
                    return false;
                };
                reservation.physical_start >= region.physical_start
                    && reservation_end <= region_end
                    && region.kind == memory_kind::BOOTLOADER_RECLAIM
            })
            .ok_or(ReservationError::NotContainedInLoaderMemory)?;

        let original = regions[index];
        let original_end = original
            .physical_start
            .checked_add(original.length)
            .ok_or(ReservationError::AddressOverflow)?;
        let prefix_length = reservation.physical_start - original.physical_start;
        let suffix_length = original_end - reservation_end;
        let part_count = 1 + usize::from(prefix_length != 0) + usize::from(suffix_length != 0);
        let growth = part_count - 1;
        let new_count = count
            .checked_add(growth)
            .ok_or(ReservationError::OutputTooSmall)?;
        if new_count > regions.len() {
            return Err(ReservationError::OutputTooSmall);
        }

        regions.copy_within(index + 1..count, index + part_count);
        let mut destination = index;
        if prefix_length != 0 {
            regions[destination] = MemoryRegion {
                physical_start: original.physical_start,
                length: prefix_length,
                kind: original.kind,
                attributes: original.attributes,
            };
            destination += 1;
        }
        regions[destination] = MemoryRegion {
            physical_start: reservation.physical_start,
            length: reservation.length,
            kind: reservation.kind,
            attributes: original.attributes,
        };
        destination += 1;
        if suffix_length != 0 {
            regions[destination] = MemoryRegion {
                physical_start: reservation_end,
                length: suffix_length,
                kind: original.kind,
                attributes: original.attributes,
            };
        }
        count = new_count;
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

        assert_eq!(translate_uefi_memory_map(&input, &mut output), Ok(2));
        assert_eq!(output[0].physical_start, 0x1000);
        assert_eq!(output[0].length, 4 * EFI_PAGE_SIZE);
        assert_eq!(output[0].kind, memory_kind::BOOTLOADER_RECLAIM);
        assert_ne!(output[0].kind, memory_kind::USABLE);
        assert_eq!(output[1].physical_start, 0x5000);
        assert_eq!(output[1].kind, memory_kind::USABLE);
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

#[cfg(test)]
mod reservation_tests {
    use super::*;

    fn region(start: u64, pages: u64, kind: u32, attributes: u32) -> MemoryRegion {
        MemoryRegion {
            physical_start: start,
            length: pages * EFI_PAGE_SIZE,
            kind,
            attributes,
        }
    }

    fn reservation(start: u64, pages: u64, kind: u32) -> MemoryReservation {
        MemoryReservation {
            physical_start: start,
            length: pages * EFI_PAGE_SIZE,
            kind,
        }
    }

    #[test]
    fn in_place_reservations_split_regions_and_preserve_attributes() {
        let mut regions = [
            region(
                0x1000,
                9,
                memory_kind::BOOTLOADER_RECLAIM,
                memory_attribute::CACHE_WRITE_BACK,
            ),
            region(0xa000, 4, memory_kind::USABLE, 0),
            region(
                0xe000,
                4,
                memory_kind::BOOTLOADER_RECLAIM,
                memory_attribute::CACHE_UNCACHED,
            ),
            MemoryRegion::default(),
            MemoryRegion::default(),
            MemoryRegion::default(),
            MemoryRegion::default(),
        ];
        let reservations = [
            reservation(0x3000, 2, memory_kind::KERNEL),
            reservation(0xf000, 1, memory_kind::BOOT_INFO),
        ];

        assert_eq!(
            apply_memory_reservations_in_place(&mut regions, 3, &reservations),
            Ok(7)
        );
        assert_eq!(
            regions[0],
            region(
                0x1000,
                2,
                memory_kind::BOOTLOADER_RECLAIM,
                memory_attribute::CACHE_WRITE_BACK
            )
        );
        assert_eq!(
            regions[1],
            region(
                0x3000,
                2,
                memory_kind::KERNEL,
                memory_attribute::CACHE_WRITE_BACK
            )
        );
        assert_eq!(
            regions[2],
            region(
                0x5000,
                5,
                memory_kind::BOOTLOADER_RECLAIM,
                memory_attribute::CACHE_WRITE_BACK
            )
        );
        assert_eq!(regions[3], region(0xa000, 4, memory_kind::USABLE, 0));
        assert_eq!(
            regions[4],
            region(
                0xe000,
                1,
                memory_kind::BOOTLOADER_RECLAIM,
                memory_attribute::CACHE_UNCACHED
            )
        );
        assert_eq!(
            regions[5],
            region(
                0xf000,
                1,
                memory_kind::BOOT_INFO,
                memory_attribute::CACHE_UNCACHED
            )
        );
        assert_eq!(
            regions[6],
            region(
                0x10000,
                2,
                memory_kind::BOOTLOADER_RECLAIM,
                memory_attribute::CACHE_UNCACHED
            )
        );
    }

    #[test]
    fn in_place_reservations_validate_before_mutating_and_check_capacity() {
        let original = [
            region(0x1000, 8, memory_kind::BOOTLOADER_RECLAIM, 0),
            MemoryRegion::default(),
            MemoryRegion::default(),
        ];
        let mut regions = original;
        let invalid = [
            reservation(0x2000, 1, memory_kind::KERNEL),
            reservation(0x9000, 1, memory_kind::BOOT_INFO),
        ];
        assert_eq!(
            apply_memory_reservations_in_place(&mut regions, 1, &invalid),
            Err(ReservationError::NotContainedInLoaderMemory)
        );
        assert_eq!(regions, original);

        let mut small = [region(0x1000, 8, memory_kind::BOOTLOADER_RECLAIM, 0)];
        assert_eq!(
            apply_memory_reservations_in_place(
                &mut small,
                1,
                &[reservation(0x3000, 1, memory_kind::KERNEL)],
            ),
            Err(ReservationError::OutputTooSmall)
        );
        assert_eq!(
            apply_memory_reservations_in_place(&mut regions, 4, &[]),
            Err(ReservationError::OutputTooSmall)
        );
    }

    #[test]
    fn overlays_kernel_and_boot_info_ranges_and_preserves_attributes() {
        let input = [region(
            0x1000,
            10,
            memory_kind::BOOTLOADER_RECLAIM,
            memory_attribute::CACHE_WRITE_BACK,
        )];
        let reservations = [
            reservation(0x2000, 2, memory_kind::KERNEL),
            reservation(0x7000, 1, memory_kind::BOOT_INFO),
        ];
        let mut output = [MemoryRegion::default(); 5];

        let count = apply_memory_reservations(&input, &reservations, &mut output).unwrap();
        assert_eq!(count, 5);
        assert_eq!(
            output[0],
            region(0x1000, 1, memory_kind::BOOTLOADER_RECLAIM, 1)
        );
        assert_eq!(output[1], region(0x2000, 2, memory_kind::KERNEL, 1));
        assert_eq!(
            output[2],
            region(0x4000, 3, memory_kind::BOOTLOADER_RECLAIM, 1)
        );
        assert_eq!(output[3], region(0x7000, 1, memory_kind::BOOT_INFO, 1));
        assert_eq!(
            output[4],
            region(0x8000, 3, memory_kind::BOOTLOADER_RECLAIM, 1)
        );
    }

    #[test]
    fn rejects_unaligned_empty_overlapping_and_unsorted_reservations() {
        let input = [region(0x1000, 8, memory_kind::BOOTLOADER_RECLAIM, 0)];
        let mut output = [MemoryRegion::default(); 8];
        assert_eq!(
            apply_memory_reservations(
                &input,
                &[reservation(0x1001, 1, memory_kind::KERNEL)],
                &mut output
            ),
            Err(ReservationError::InvalidRange)
        );
        assert_eq!(
            apply_memory_reservations(
                &input,
                &[reservation(0x2000, 0, memory_kind::KERNEL)],
                &mut output
            ),
            Err(ReservationError::InvalidRange)
        );
        assert_eq!(
            apply_memory_reservations(
                &input,
                &[
                    reservation(0x3000, 2, memory_kind::KERNEL),
                    reservation(0x2000, 1, memory_kind::BOOT_INFO),
                ],
                &mut output,
            ),
            Err(ReservationError::UnsortedOrOverlappingReservations)
        );
        assert_eq!(
            apply_memory_reservations(
                &input,
                &[
                    reservation(0x2000, 2, memory_kind::KERNEL),
                    reservation(0x3000, 1, memory_kind::BOOT_INFO),
                ],
                &mut output,
            ),
            Err(ReservationError::UnsortedOrOverlappingReservations)
        );
    }

    #[test]
    fn refuses_to_promote_usable_or_uncovered_memory() {
        let usable = [region(0x1000, 4, memory_kind::USABLE, 0)];
        let mut output = [MemoryRegion::default(); 4];
        assert_eq!(
            apply_memory_reservations(
                &usable,
                &[reservation(0x2000, 1, memory_kind::KERNEL)],
                &mut output,
            ),
            Err(ReservationError::NotContainedInLoaderMemory)
        );
        let loader = [region(0x1000, 2, memory_kind::BOOTLOADER_RECLAIM, 0)];
        assert_eq!(
            apply_memory_reservations(
                &loader,
                &[reservation(0x3000, 1, memory_kind::BOOT_INFO)],
                &mut output,
            ),
            Err(ReservationError::NotContainedInLoaderMemory)
        );
    }

    #[test]
    fn rejects_unsupported_kinds_overflow_and_insufficient_output() {
        let input = [region(0x1000, 4, memory_kind::BOOTLOADER_RECLAIM, 0)];
        let mut output = [MemoryRegion::default(); 2];
        assert_eq!(
            apply_memory_reservations(
                &input,
                &[reservation(0x2000, 1, memory_kind::USABLE)],
                &mut output,
            ),
            Err(ReservationError::UnsupportedKind)
        );
        assert_eq!(
            apply_memory_reservations(
                &input,
                &[MemoryReservation {
                    physical_start: u64::MAX - 0xfff,
                    length: EFI_PAGE_SIZE,
                    kind: memory_kind::KERNEL,
                }],
                &mut output,
            ),
            Err(ReservationError::AddressOverflow)
        );
        assert_eq!(
            apply_memory_reservations(
                &input,
                &[reservation(0x2000, 1, memory_kind::KERNEL)],
                &mut output,
            ),
            Err(ReservationError::OutputTooSmall)
        );
    }
}

#[cfg(test)]
mod active_stack_mapping_tests {
    use super::*;

    fn descriptor(memory_type: u32, start: u64, pages: u64) -> UefiMemoryDescriptor {
        UefiMemoryDescriptor {
            memory_type,
            physical_start: start,
            number_of_pages: pages,
            ..UefiMemoryDescriptor::default()
        }
    }

    #[test]
    fn accepts_unchanged_loader_stack_descriptor() {
        let descriptors = [descriptor(EFI_LOADER_DATA, 0x10_0000, 16)];
        assert_eq!(
            validate_active_stack_mapping(&descriptors, 0x10_0000, 16 * EFI_PAGE_SIZE, 0x10_8000),
            Ok(())
        );
    }

    #[test]
    fn accepts_unchanged_boot_services_stack_descriptor() {
        let descriptors = [descriptor(EFI_BOOT_SERVICES_DATA, 0x20_0000, 8)];
        assert_eq!(
            validate_active_stack_mapping(&descriptors, 0x20_0000, 8 * EFI_PAGE_SIZE, 0x20_4000),
            Ok(())
        );
    }

    #[test]
    fn rejects_descriptor_split_after_mapping_was_planned() {
        let descriptors = [
            descriptor(EFI_LOADER_DATA, 0x30_0000, 4),
            descriptor(EFI_BOOT_SERVICES_DATA, 0x30_4000, 4),
        ];
        assert_eq!(
            validate_active_stack_mapping(&descriptors, 0x30_0000, 8 * EFI_PAGE_SIZE, 0x30_6000),
            Err(ActiveStackMappingError::DescriptorChanged)
        );
    }

    #[test]
    fn rejects_stack_pointer_outside_all_descriptors() {
        let descriptors = [descriptor(EFI_LOADER_DATA, 0x40_0000, 2)];
        assert_eq!(
            validate_active_stack_mapping(&descriptors, 0x40_0000, 2 * EFI_PAGE_SIZE, 0x50_0000),
            Err(ActiveStackMappingError::NoContainingDescriptor)
        );
    }

    #[test]
    fn rejects_unsupported_stack_memory_type() {
        let descriptors = [descriptor(EFI_RUNTIME_SERVICES_DATA, 0x60_0000, 2)];
        assert_eq!(
            validate_active_stack_mapping(&descriptors, 0x60_0000, 2 * EFI_PAGE_SIZE, 0x60_1000),
            Err(ActiveStackMappingError::UnsupportedMemoryType)
        );
    }
}
