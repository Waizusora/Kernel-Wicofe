#![no_std]

//! UEFI-facing boundary and checked allocation planning for Wicofe Bootloader.

pub use wicofe_bootloader_common::{BOOT_INFO_VERSION, BootInfo, MemoryRegion};
use wicofe_bootloader_elf::LoadSegment;
#[cfg(test)]
use wicofe_bootloader_elf::{PF_R, PF_W, PF_X};

pub const UEFI_PAGE_SIZE: u64 = 4096;
pub const KERNEL_PHYSICAL_ALIGNMENT: u64 = 2 * 1024 * 1024;
pub const MAX_KERNEL_IMAGE_SIZE: u64 = 512 * 1024 * 1024;

/// Page and alignment requirements for a contiguous kernel image allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelAllocationLayout {
    pub rounded_image_size: u64,
    pub allocation_size: u64,
    pub image_pages: usize,
    pub allocation_pages: usize,
}

/// Calculate an allocation large enough to select a 2 MiB-aligned subrange.
pub fn kernel_allocation_layout(image_size: u64) -> Option<KernelAllocationLayout> {
    if image_size == 0 || image_size > MAX_KERNEL_IMAGE_SIZE {
        return None;
    }

    let rounded_image_size = image_size.checked_add(UEFI_PAGE_SIZE - 1)? & !(UEFI_PAGE_SIZE - 1);
    let allocation_size =
        rounded_image_size.checked_add(KERNEL_PHYSICAL_ALIGNMENT - UEFI_PAGE_SIZE)?;
    let image_pages = usize::try_from(rounded_image_size / UEFI_PAGE_SIZE).ok()?;
    let allocation_pages = usize::try_from(allocation_size / UEFI_PAGE_SIZE).ok()?;

    Some(KernelAllocationLayout {
        rounded_image_size,
        allocation_size,
        image_pages,
        allocation_pages,
    })
}

/// Page-table backing-store requirements for a contiguous UEFI allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableAllocationLayout {
    pub table_count: usize,
    pub allocation_size: u64,
    pub allocation_pages: usize,
}

/// Calculate the exact number of UEFI pages required for a table pool.
///
/// Each architecture builder uses one 4 KiB physical page per translation
/// table. The caller must still validate the physical address range against
/// the architecture's output-address constraints.
pub fn page_table_allocation_layout(table_count: usize) -> Option<PageTableAllocationLayout> {
    if table_count == 0 {
        return None;
    }

    let allocation_size = u64::try_from(table_count)
        .ok()?
        .checked_mul(UEFI_PAGE_SIZE)?;
    Some(PageTableAllocationLayout {
        table_count,
        allocation_size,
        allocation_pages: table_count,
    })
}

/// Reserve enough additional tables to identity-map the table pool itself.
///
/// The required-capacity planners count every intermediate table touched by a
/// mapping. This computes a conservative fixed point for a contiguous pool,
/// including the worst possible offset at each 2 MiB, 1 GiB, and 512 GiB
/// boundary. The root table is already included in base_table_capacity.
pub fn page_table_pool_capacity(base_table_capacity: usize) -> Option<usize> {
    if base_table_capacity == 0 {
        return None;
    }

    fn maximum_regions_touched(pages: usize, region_pages: usize) -> Option<usize> {
        pages
            .checked_add(region_pages - 2)?
            .checked_div(region_pages)?
            .checked_add(1)
    }

    let mut capacity = base_table_capacity;
    loop {
        let extra = maximum_regions_touched(capacity, 1 << 27)?
            .checked_add(maximum_regions_touched(capacity, 1 << 18)?)?
            .checked_add(maximum_regions_touched(capacity, 1 << 9)?)?;
        let required = base_table_capacity.checked_add(extra)?;
        if required <= capacity {
            return Some(capacity);
        }
        capacity = required;
    }
}

/// Errors while validating the dedicated page-table pool mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageTablePoolError {
    InvalidRange,
    InvalidPermissions,
    AddressOverflow,
    OverlappingVirtualMapping,
    PhysicalAlias,
}

/// Validate that an identity-mapped page-table pool can be appended safely.
///
/// The caller appends exactly one mapping at `physical_start` with
/// `page_count` pages and READ|WRITE permissions. Existing mappings must not
/// overlap its virtual range or alias any of its physical frames.
pub fn validate_page_table_pool_mapping(
    mappings: &[KernelPageMapping],
    pool_mapping: &KernelPageMapping,
    physical_start: u64,
    page_count: usize,
) -> Result<(), PageTablePoolError> {
    let layout =
        page_table_allocation_layout(page_count).ok_or(PageTablePoolError::InvalidRange)?;
    let expected_page_count =
        u64::try_from(page_count).map_err(|_| PageTablePoolError::InvalidRange)?;
    if physical_start == 0 || physical_start % UEFI_PAGE_SIZE != 0 {
        return Err(PageTablePoolError::InvalidRange);
    }
    if pool_mapping.virtual_start != physical_start
        || pool_mapping.physical_start != physical_start
        || pool_mapping.page_count != expected_page_count
    {
        return Err(PageTablePoolError::InvalidRange);
    }
    if pool_mapping.permissions != (MAP_READ | MAP_WRITE) {
        return Err(PageTablePoolError::InvalidPermissions);
    }
    let pool_end = physical_start
        .checked_add(layout.allocation_size)
        .ok_or(PageTablePoolError::AddressOverflow)?;

    for mapping in mappings {
        if mapping.page_count == 0
            || mapping.virtual_start % UEFI_PAGE_SIZE != 0
            || mapping.physical_start % UEFI_PAGE_SIZE != 0
        {
            return Err(PageTablePoolError::InvalidRange);
        }
        mapping_access(mapping.permissions).map_err(|_| PageTablePoolError::InvalidPermissions)?;
        let size = mapping
            .page_count
            .checked_mul(UEFI_PAGE_SIZE)
            .ok_or(PageTablePoolError::AddressOverflow)?;
        let virtual_end = mapping
            .virtual_start
            .checked_add(size)
            .ok_or(PageTablePoolError::AddressOverflow)?;
        let physical_end = mapping
            .physical_start
            .checked_add(size)
            .ok_or(PageTablePoolError::AddressOverflow)?;

        if mapping.virtual_start < pool_end && physical_start < virtual_end {
            return Err(PageTablePoolError::OverlappingVirtualMapping);
        }
        if mapping.physical_start < pool_end && physical_start < physical_end {
            return Err(PageTablePoolError::PhysicalAlias);
        }
    }

    Ok(())
}

/// Hardware-independent permission bits for a 4 KiB kernel mapping.
pub const MAP_READ: u32 = 1 << 0;
pub const MAP_WRITE: u32 = 1 << 1;
pub const MAP_EXECUTE: u32 = 1 << 2;

/// One contiguous run of pages with identical ELF permissions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelPageMapping {
    pub physical_start: u64,
    pub virtual_start: u64,
    pub page_count: u64,
    pub permissions: u32,
}

/// Errors while proving that a required object is reachable through a mapping plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingCoverageError {
    InvalidRange,
    InvalidPermissions,
    AddressOverflow,
    MissingMapping,
    PhysicalAddressMismatch,
    InsufficientPermissions,
    UnexpectedMapping,
}

/// Prove a virtual range resolves to the expected contiguous physical range.
pub fn validate_mapping_coverage(
    mappings: &[KernelPageMapping],
    virtual_start: u64,
    physical_start: u64,
    length: u64,
    required_permissions: u32,
) -> Result<(), MappingCoverageError> {
    if length == 0 || virtual_start % UEFI_PAGE_SIZE != 0 || physical_start % UEFI_PAGE_SIZE != 0 {
        return Err(MappingCoverageError::InvalidRange);
    }
    mapping_access(required_permissions).map_err(|_| MappingCoverageError::InvalidPermissions)?;
    let requested_end = virtual_start
        .checked_add(length)
        .ok_or(MappingCoverageError::AddressOverflow)?;
    physical_start
        .checked_add(length)
        .ok_or(MappingCoverageError::AddressOverflow)?;

    let mut cursor = virtual_start;
    while cursor < requested_end {
        let mut selected = None;
        for mapping in mappings {
            if mapping.page_count == 0
                || mapping.virtual_start % UEFI_PAGE_SIZE != 0
                || mapping.physical_start % UEFI_PAGE_SIZE != 0
            {
                return Err(MappingCoverageError::InvalidRange);
            }
            mapping_access(mapping.permissions)
                .map_err(|_| MappingCoverageError::InvalidPermissions)?;
            let size = mapping
                .page_count
                .checked_mul(UEFI_PAGE_SIZE)
                .ok_or(MappingCoverageError::AddressOverflow)?;
            let end = mapping
                .virtual_start
                .checked_add(size)
                .ok_or(MappingCoverageError::AddressOverflow)?;
            mapping
                .physical_start
                .checked_add(size)
                .ok_or(MappingCoverageError::AddressOverflow)?;
            if cursor >= mapping.virtual_start && cursor < end {
                if selected.is_some() {
                    return Err(MappingCoverageError::UnexpectedMapping);
                }
                selected = Some((mapping, end));
            }
        }
        let (mapping, mapping_end) = selected.ok_or(MappingCoverageError::MissingMapping)?;
        let offset = cursor - mapping.virtual_start;
        let actual_physical = mapping
            .physical_start
            .checked_add(offset)
            .ok_or(MappingCoverageError::AddressOverflow)?;
        let expected_physical = physical_start
            .checked_add(cursor - virtual_start)
            .ok_or(MappingCoverageError::AddressOverflow)?;
        if actual_physical != expected_physical {
            return Err(MappingCoverageError::PhysicalAddressMismatch);
        }
        if mapping.permissions & required_permissions != required_permissions {
            return Err(MappingCoverageError::InsufficientPermissions);
        }
        cursor = requested_end.min(mapping_end);
    }
    Ok(())
}

/// Reject any mapping that intersects a virtual guard or deliberately unmapped range.
pub fn validate_mapping_absent(
    mappings: &[KernelPageMapping],
    virtual_start: u64,
    length: u64,
) -> Result<(), MappingCoverageError> {
    if length == 0 || virtual_start % UEFI_PAGE_SIZE != 0 {
        return Err(MappingCoverageError::InvalidRange);
    }
    let end = virtual_start
        .checked_add(length)
        .ok_or(MappingCoverageError::AddressOverflow)?;
    for mapping in mappings {
        if mapping.page_count == 0 || mapping.virtual_start % UEFI_PAGE_SIZE != 0 {
            return Err(MappingCoverageError::InvalidRange);
        }
        let mapping_size = mapping
            .page_count
            .checked_mul(UEFI_PAGE_SIZE)
            .ok_or(MappingCoverageError::AddressOverflow)?;
        let mapping_end = mapping
            .virtual_start
            .checked_add(mapping_size)
            .ok_or(MappingCoverageError::AddressOverflow)?;
        if virtual_start < mapping_end && mapping.virtual_start < end {
            return Err(MappingCoverageError::UnexpectedMapping);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPlanError {
    InvalidBase,
    InvalidSegment,
    AddressOverflow,
    OutputTooSmall,
    SharedPage,
}

/// Convert validated PT_LOAD segments into page-aligned mapping runs.
///
/// The caller supplies storage for the result. No allocation or page-table
/// mutation occurs here. Segments sharing a 4 KiB page are rejected because
/// that page cannot safely express two different permission sets.
pub fn plan_kernel_page_mappings(
    image_physical_base: u64,
    image_virtual_base: u64,
    segments: &[LoadSegment],
    output: &mut [KernelPageMapping],
) -> Result<usize, MappingPlanError> {
    if image_physical_base == 0
        || image_physical_base % KERNEL_PHYSICAL_ALIGNMENT != 0
        || image_virtual_base % KERNEL_PHYSICAL_ALIGNMENT != 0
    {
        return Err(MappingPlanError::InvalidBase);
    }

    let mut count = 0usize;
    for segment in segments {
        if segment.memory_size == 0
            || segment.file_size > segment.memory_size
            || segment.virtual_address < image_virtual_base
            || (segment.is_writable() && segment.is_executable())
        {
            return Err(MappingPlanError::InvalidSegment);
        }

        let segment_end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .ok_or(MappingPlanError::AddressOverflow)?;
        let page_start = segment.virtual_address & !(UEFI_PAGE_SIZE - 1);
        let page_end = segment_end
            .checked_add(UEFI_PAGE_SIZE - 1)
            .ok_or(MappingPlanError::AddressOverflow)?
            & !(UEFI_PAGE_SIZE - 1);
        let offset = page_start
            .checked_sub(image_virtual_base)
            .ok_or(MappingPlanError::InvalidSegment)?;
        let physical_start = image_physical_base
            .checked_add(offset)
            .ok_or(MappingPlanError::AddressOverflow)?;
        let page_count = (page_end - page_start) / UEFI_PAGE_SIZE;
        let permissions = (if segment.is_readable() { MAP_READ } else { 0 })
            | (if segment.is_writable() { MAP_WRITE } else { 0 })
            | (if segment.is_executable() {
                MAP_EXECUTE
            } else {
                0
            });

        for previous in &output[..count] {
            let previous_end = previous
                .virtual_start
                .checked_add(previous.page_count * UEFI_PAGE_SIZE)
                .ok_or(MappingPlanError::AddressOverflow)?;
            if page_start < previous_end && previous.virtual_start < page_end {
                return Err(MappingPlanError::SharedPage);
            }
        }

        if count == output.len() {
            return Err(MappingPlanError::OutputTooSmall);
        }
        output[count] = KernelPageMapping {
            physical_start,
            virtual_start: page_start,
            page_count,
            permissions,
        };
        count += 1;
    }

    Ok(count)
}

/// Errors while translating ELF permissions into architecture page mappings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingConversionError {
    OutputTooSmall,
    UnsupportedPermissions,
}

/// Validate permissions shared by both architecture page-table builders.
fn mapping_access(permissions: u32) -> Result<(bool, bool), MappingConversionError> {
    if permissions & !(MAP_READ | MAP_WRITE | MAP_EXECUTE) != 0
        || permissions & MAP_READ == 0
        || permissions & (MAP_WRITE | MAP_EXECUTE) == (MAP_WRITE | MAP_EXECUTE)
    {
        return Err(MappingConversionError::UnsupportedPermissions);
    }
    Ok((permissions & MAP_WRITE != 0, permissions & MAP_EXECUTE != 0))
}

/// Translate planned ELF mappings into the x86-64 page-table builder input.
#[cfg(target_arch = "x86_64")]
pub fn convert_kernel_page_mappings(
    mappings: &[KernelPageMapping],
    output: &mut [wicofe_kernel_x86_64::paging::PageMapping],
) -> Result<usize, MappingConversionError> {
    if output.len() < mappings.len() {
        return Err(MappingConversionError::OutputTooSmall);
    }
    for (index, mapping) in mappings.iter().enumerate() {
        let (writable, executable) = mapping_access(mapping.permissions)?;
        output[index] = wicofe_kernel_x86_64::paging::PageMapping {
            virtual_start: mapping.virtual_start,
            physical_start: mapping.physical_start,
            page_count: mapping.page_count,
            writable,
            executable,
        };
    }
    Ok(mappings.len())
}

/// Translate planned ELF mappings into the AArch64 translation-table input.
///
/// The MAIR attribute index is supplied by the caller; this conversion does
/// not program MAIR_EL1 or enable the MMU.
#[cfg(target_arch = "aarch64")]
pub fn convert_kernel_page_mappings(
    mappings: &[KernelPageMapping],
    attribute_index: u8,
    output: &mut [wicofe_kernel_aarch64::paging::PageMapping],
) -> Result<usize, MappingConversionError> {
    if output.len() < mappings.len() {
        return Err(MappingConversionError::OutputTooSmall);
    }
    if attribute_index >= 8 {
        return Err(MappingConversionError::UnsupportedPermissions);
    }
    for (index, mapping) in mappings.iter().enumerate() {
        let (writable, executable) = mapping_access(mapping.permissions)?;
        output[index] = wicofe_kernel_aarch64::paging::PageMapping {
            virtual_start: mapping.virtual_start,
            physical_start: mapping.physical_start,
            page_count: mapping.page_count,
            writable,
            executable,
            attribute_index,
        };
    }
    Ok(mappings.len())
}

/// A physical range that must remain reachable through an identity mapping.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityMappingRange {
    pub physical_start: u64,
    pub length: u64,
    pub permissions: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityMappingError {
    InvalidRange,
    AddressOverflow,
    UnsupportedPermissions,
    OverlappingRange,
    OutputTooSmall,
}

/// Normalize identity ranges to page boundaries and merge overlapping ranges
/// only when their permissions agree. Adjacent ranges remain distinct.
pub fn coalesce_identity_mapping_ranges(
    input: &[IdentityMappingRange],
    output: &mut [IdentityMappingRange],
) -> Result<usize, IdentityMappingError> {
    if input.len() > output.len() {
        return Err(IdentityMappingError::OutputTooSmall);
    }

    for (index, range) in input.iter().enumerate() {
        if range.length == 0 {
            return Err(IdentityMappingError::InvalidRange);
        }
        mapping_access(range.permissions)
            .map_err(|_| IdentityMappingError::UnsupportedPermissions)?;
        let end = range
            .physical_start
            .checked_add(range.length)
            .ok_or(IdentityMappingError::AddressOverflow)?;
        let page_start = range.physical_start & !(UEFI_PAGE_SIZE - 1);
        let page_end = end
            .checked_add(UEFI_PAGE_SIZE - 1)
            .ok_or(IdentityMappingError::AddressOverflow)?
            & !(UEFI_PAGE_SIZE - 1);
        if page_end <= page_start {
            return Err(IdentityMappingError::InvalidRange);
        }
        output[index] = IdentityMappingRange {
            physical_start: page_start,
            length: page_end - page_start,
            permissions: range.permissions,
        };
    }

    for index in 1..input.len() {
        let mut cursor = index;
        while cursor != 0 && output[cursor].physical_start < output[cursor - 1].physical_start {
            output.swap(cursor, cursor - 1);
            cursor -= 1;
        }
    }

    let mut merged_count = 0usize;
    for index in 0..input.len() {
        let current = output[index];
        if merged_count != 0 {
            let previous = output[merged_count - 1];
            let previous_end = previous
                .physical_start
                .checked_add(previous.length)
                .ok_or(IdentityMappingError::AddressOverflow)?;
            if current.physical_start < previous_end {
                if current.permissions != previous.permissions {
                    return Err(IdentityMappingError::OverlappingRange);
                }
                let current_end = current
                    .physical_start
                    .checked_add(current.length)
                    .ok_or(IdentityMappingError::AddressOverflow)?;
                output[merged_count - 1].length =
                    previous.length.max(current_end - previous.physical_start);
                continue;
            }
        }
        output[merged_count] = current;
        merged_count += 1;
    }

    Ok(merged_count)
}

/// Plan identity mappings for explicitly supplied WBL-owned physical ranges.
/// The caller discovers ranges and selects permissions; overlaps fail closed.
pub fn plan_identity_page_mappings(
    ranges: &[IdentityMappingRange],
    output: &mut [KernelPageMapping],
) -> Result<usize, IdentityMappingError> {
    let mut count = 0usize;
    for range in ranges {
        if range.length == 0 {
            return Err(IdentityMappingError::InvalidRange);
        }
        let (writable, executable) = mapping_access(range.permissions)
            .map_err(|_| IdentityMappingError::UnsupportedPermissions)?;
        let end = range
            .physical_start
            .checked_add(range.length)
            .ok_or(IdentityMappingError::AddressOverflow)?;
        let page_start = range.physical_start & !(UEFI_PAGE_SIZE - 1);
        let page_end = end
            .checked_add(UEFI_PAGE_SIZE - 1)
            .ok_or(IdentityMappingError::AddressOverflow)?
            & !(UEFI_PAGE_SIZE - 1);
        let page_count = (page_end - page_start) / UEFI_PAGE_SIZE;
        for previous in &output[..count] {
            let previous_size = previous
                .page_count
                .checked_mul(UEFI_PAGE_SIZE)
                .ok_or(IdentityMappingError::AddressOverflow)?;
            let previous_end = previous
                .virtual_start
                .checked_add(previous_size)
                .ok_or(IdentityMappingError::AddressOverflow)?;
            if page_start < previous_end && previous.virtual_start < page_end {
                return Err(IdentityMappingError::OverlappingRange);
            }
        }
        if count == output.len() {
            return Err(IdentityMappingError::OutputTooSmall);
        }
        output[count] = KernelPageMapping {
            physical_start: page_start,
            virtual_start: page_start,
            page_count,
            permissions: MAP_READ
                | if writable { MAP_WRITE } else { 0 }
                | if executable { MAP_EXECUTE } else { 0 },
        };
        count += 1;
    }
    Ok(count)
}

/// Errors while combining kernel mappings with WBL identity mappings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CombinedMappingError {
    OutputTooSmall,
    InvalidKernelMapping,
    AddressOverflow,
    Identity(IdentityMappingError),
    OverlappingMapping,
}

/// Combine kernel virtual mappings and explicit WBL identity ranges.
///
/// All ranges are validated before the result is passed to an architecture
/// page-table builder. This function does not discover WBL ranges or activate
/// the resulting tables.
pub fn plan_combined_page_mappings(
    kernel_mappings: &[KernelPageMapping],
    identity_ranges: &[IdentityMappingRange],
    output: &mut [KernelPageMapping],
) -> Result<usize, CombinedMappingError> {
    let required = kernel_mappings
        .len()
        .checked_add(identity_ranges.len())
        .ok_or(CombinedMappingError::OutputTooSmall)?;
    if output.len() < required {
        return Err(CombinedMappingError::OutputTooSmall);
    }

    for (index, mapping) in kernel_mappings.iter().enumerate() {
        mapping_access(mapping.permissions)
            .map_err(|_| CombinedMappingError::InvalidKernelMapping)?;
        if mapping.page_count == 0 {
            return Err(CombinedMappingError::InvalidKernelMapping);
        }
        let size = mapping
            .page_count
            .checked_mul(UEFI_PAGE_SIZE)
            .ok_or(CombinedMappingError::AddressOverflow)?;
        mapping
            .virtual_start
            .checked_add(size)
            .ok_or(CombinedMappingError::AddressOverflow)?;
        mapping
            .physical_start
            .checked_add(size)
            .ok_or(CombinedMappingError::AddressOverflow)?;
        output[index] = *mapping;
    }

    let identity_output = &mut output[kernel_mappings.len()..required];
    let identity_count = plan_identity_page_mappings(identity_ranges, identity_output)
        .map_err(CombinedMappingError::Identity)?;

    for identity in &identity_output[..identity_count] {
        let identity_size = identity
            .page_count
            .checked_mul(UEFI_PAGE_SIZE)
            .ok_or(CombinedMappingError::AddressOverflow)?;
        let identity_end = identity
            .virtual_start
            .checked_add(identity_size)
            .ok_or(CombinedMappingError::AddressOverflow)?;
        for kernel in kernel_mappings {
            let kernel_size = kernel
                .page_count
                .checked_mul(UEFI_PAGE_SIZE)
                .ok_or(CombinedMappingError::AddressOverflow)?;
            let kernel_end = kernel
                .virtual_start
                .checked_add(kernel_size)
                .ok_or(CombinedMappingError::AddressOverflow)?;
            if identity.virtual_start < kernel_end && kernel.virtual_start < identity_end {
                return Err(CombinedMappingError::OverlappingMapping);
            }
        }
    }

    Ok(kernel_mappings.len() + identity_count)
}

/// PE/COFF image-section mapping errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeMappingError {
    InvalidImage,
    UnsupportedMachine,
    InvalidOptionalHeader,
    InvalidSectionTable,
    InvalidSection,
    UnsupportedPermissions,
    AddressOverflow,
    OutputTooSmall,
    OverlappingSections,
}

const PE_PAGE_SIZE: u64 = UEFI_PAGE_SIZE;
const PE_MACHINE_X86_64: u16 = 0x8664;
const PE_MACHINE_AARCH64: u16 = 0xaa64;
const PE_IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const PE_IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const PE_IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub const MAX_PE_IDENTITY_MAPPINGS: usize = 97;
const PE_MAX_SECTIONS: usize = MAX_PE_IDENTITY_MAPPINGS - 1;

fn pe_read_u16(image: &[u8], offset: usize) -> Result<u16, PeMappingError> {
    let bytes = image
        .get(
            offset
                ..offset
                    .checked_add(2)
                    .ok_or(PeMappingError::AddressOverflow)?,
        )
        .ok_or(PeMappingError::InvalidImage)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn pe_read_u32(image: &[u8], offset: usize) -> Result<u32, PeMappingError> {
    let bytes = image
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or(PeMappingError::AddressOverflow)?,
        )
        .ok_or(PeMappingError::InvalidImage)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Build identity mappings for a loaded PE32+ image, preserving section
/// read/write/execute permissions. The caller must supply the firmware-loaded
/// image base and a slice spanning the complete SizeOfImage allocation.
pub fn plan_pe_identity_mappings(
    image_base: u64,
    image: &[u8],
    output: &mut [KernelPageMapping],
) -> Result<usize, PeMappingError> {
    if image_base == 0 || image_base % PE_PAGE_SIZE != 0 || image.len() < 0x40 {
        return Err(PeMappingError::InvalidImage);
    }
    if image.get(0..2) != Some(b"MZ") {
        return Err(PeMappingError::InvalidImage);
    }

    let pe_offset =
        usize::try_from(pe_read_u32(image, 0x3c)?).map_err(|_| PeMappingError::AddressOverflow)?;
    let signature_end = pe_offset
        .checked_add(4)
        .ok_or(PeMappingError::AddressOverflow)?;
    if image.get(pe_offset..signature_end) != Some(b"PE\0\0") {
        return Err(PeMappingError::InvalidImage);
    }

    let coff = signature_end;
    let machine = pe_read_u16(image, coff)?;
    let expected_machine = if cfg!(target_arch = "x86_64") {
        PE_MACHINE_X86_64
    } else {
        PE_MACHINE_AARCH64
    };
    if machine != expected_machine {
        return Err(PeMappingError::UnsupportedMachine);
    }
    let section_count = usize::from(pe_read_u16(image, coff + 2)?);
    let optional_size = usize::from(pe_read_u16(image, coff + 16)?);
    if section_count == 0 || section_count > PE_MAX_SECTIONS {
        return Err(PeMappingError::InvalidSectionTable);
    }

    let optional = coff
        .checked_add(20)
        .ok_or(PeMappingError::AddressOverflow)?;
    let optional_end = optional
        .checked_add(optional_size)
        .ok_or(PeMappingError::AddressOverflow)?;
    if optional_size < 64 || optional_end > image.len() || pe_read_u16(image, optional)? != 0x20b {
        return Err(PeMappingError::InvalidOptionalHeader);
    }
    let size_of_image = usize::try_from(pe_read_u32(image, optional + 56)?)
        .map_err(|_| PeMappingError::AddressOverflow)?;
    let size_of_headers = usize::try_from(pe_read_u32(image, optional + 60)?)
        .map_err(|_| PeMappingError::AddressOverflow)?;
    if size_of_image == 0
        || size_of_image > image.len()
        || size_of_image as u64 % PE_PAGE_SIZE != 0
        || size_of_headers == 0
        || size_of_headers > size_of_image
    {
        return Err(PeMappingError::InvalidImage);
    }
    image_base
        .checked_add(size_of_image as u64)
        .ok_or(PeMappingError::AddressOverflow)?;

    let section_table_size = section_count
        .checked_mul(40)
        .ok_or(PeMappingError::AddressOverflow)?;
    let section_table_end = optional_end
        .checked_add(section_table_size)
        .ok_or(PeMappingError::AddressOverflow)?;
    if section_table_end > size_of_headers || section_table_end > image.len() {
        return Err(PeMappingError::InvalidSectionTable);
    }

    if output.len() < section_count + 1 {
        return Err(PeMappingError::OutputTooSmall);
    }

    let mut count = 0usize;
    let header_pages = size_of_headers
        .checked_add(PE_PAGE_SIZE as usize - 1)
        .ok_or(PeMappingError::AddressOverflow)?
        / PE_PAGE_SIZE as usize;
    output[count] = KernelPageMapping {
        physical_start: image_base,
        virtual_start: image_base,
        page_count: header_pages as u64,
        permissions: MAP_READ,
    };
    count += 1;
    let header_end = (header_pages as u64)
        .checked_mul(PE_PAGE_SIZE)
        .ok_or(PeMappingError::AddressOverflow)?;

    for index in 0..section_count {
        let section = optional_end
            .checked_add(
                index
                    .checked_mul(40)
                    .ok_or(PeMappingError::AddressOverflow)?,
            )
            .ok_or(PeMappingError::AddressOverflow)?;
        let virtual_size = u64::from(pe_read_u32(image, section + 8)?);
        let virtual_address = u64::from(pe_read_u32(image, section + 12)?);
        let raw_size = u64::from(pe_read_u32(image, section + 16)?);
        let span = virtual_size.max(raw_size);
        if span == 0 {
            continue;
        }
        let end = virtual_address
            .checked_add(span)
            .ok_or(PeMappingError::AddressOverflow)?;
        if virtual_address < header_end || end > size_of_image as u64 {
            return Err(PeMappingError::InvalidSection);
        }
        let page_start = virtual_address & !(PE_PAGE_SIZE - 1);
        let page_end = end
            .checked_add(PE_PAGE_SIZE - 1)
            .ok_or(PeMappingError::AddressOverflow)?
            & !(PE_PAGE_SIZE - 1);
        let characteristics = pe_read_u32(image, section + 36)?;
        let writable = characteristics & PE_IMAGE_SCN_MEM_WRITE != 0;
        let executable = characteristics & PE_IMAGE_SCN_MEM_EXECUTE != 0;
        let readable = characteristics & PE_IMAGE_SCN_MEM_READ != 0;
        if !readable || (writable && executable) {
            return Err(PeMappingError::UnsupportedPermissions);
        }
        for previous in &output[..count] {
            let previous_end = previous
                .virtual_start
                .checked_add(
                    previous
                        .page_count
                        .checked_mul(PE_PAGE_SIZE)
                        .ok_or(PeMappingError::AddressOverflow)?,
                )
                .ok_or(PeMappingError::AddressOverflow)?;
            if page_start + image_base < previous_end
                && previous.virtual_start < page_end + image_base
            {
                return Err(PeMappingError::OverlappingSections);
            }
        }
        let physical_start = image_base
            .checked_add(page_start)
            .ok_or(PeMappingError::AddressOverflow)?;
        output[count] = KernelPageMapping {
            physical_start,
            virtual_start: physical_start,
            page_count: (page_end - page_start) / PE_PAGE_SIZE,
            permissions: MAP_READ
                | if writable { MAP_WRITE } else { 0 }
                | if executable { MAP_EXECUTE } else { 0 },
        };
        count += 1;
    }

    Ok(count)
}

/// UEFI removable-media fallback path for x86-64 firmware.
pub const X86_64_FALLBACK_PATH: &str = r"\EFI\BOOT\BOOTX64.EFI";

/// UEFI removable-media fallback path for AArch64 firmware.
pub const AARCH64_FALLBACK_PATH: &str = r"\EFI\BOOT\BOOTAA64.EFI";

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(address: u64, size: u64, flags: u32) -> LoadSegment {
        LoadSegment {
            file_offset: 0,
            virtual_address: address,
            file_size: size,
            memory_size: size,
            flags,
            alignment: UEFI_PAGE_SIZE,
        }
    }

    #[test]
    fn identity_mapping_planner_rounds_ranges_and_preserves_permissions() {
        let ranges = [IdentityMappingRange {
            physical_start: 0x10_0123,
            length: 0x1800,
            permissions: MAP_READ | MAP_EXECUTE,
        }];
        let mut output = [KernelPageMapping::default(); 1];
        assert_eq!(plan_identity_page_mappings(&ranges, &mut output), Ok(1));
        assert_eq!(output[0].physical_start, 0x10_0000);
        assert_eq!(output[0].virtual_start, 0x10_0000);
        assert_eq!(output[0].page_count, 2);
        assert_eq!(output[0].permissions, MAP_READ | MAP_EXECUTE);
    }

    #[test]
    fn identity_mapping_planner_rejects_overlap_wx_and_overflow() {
        let mut output = [KernelPageMapping::default(); 2];
        let overlap = [
            IdentityMappingRange {
                physical_start: 0x20_0000,
                length: 0x1800,
                permissions: MAP_READ,
            },
            IdentityMappingRange {
                physical_start: 0x20_1000,
                length: 0x1000,
                permissions: MAP_READ,
            },
        ];
        assert_eq!(
            plan_identity_page_mappings(&overlap, &mut output),
            Err(IdentityMappingError::OverlappingRange)
        );
        let wx = [IdentityMappingRange {
            physical_start: 0x30_0000,
            length: 0x1000,
            permissions: MAP_READ | MAP_WRITE | MAP_EXECUTE,
        }];
        assert_eq!(
            plan_identity_page_mappings(&wx, &mut output),
            Err(IdentityMappingError::UnsupportedPermissions)
        );
        let overflow = [IdentityMappingRange {
            physical_start: u64::MAX - 0xfff,
            length: 0x2000,
            permissions: MAP_READ,
        }];
        assert_eq!(
            plan_identity_page_mappings(&overflow, &mut output),
            Err(IdentityMappingError::AddressOverflow)
        );
    }

    #[test]
    fn identity_mapping_planner_rejects_empty_ranges_and_small_output() {
        let empty = [IdentityMappingRange {
            physical_start: 0x40_0000,
            length: 0,
            permissions: MAP_READ,
        }];
        assert_eq!(
            plan_identity_page_mappings(&empty, &mut []),
            Err(IdentityMappingError::InvalidRange)
        );
        let two = [
            IdentityMappingRange {
                physical_start: 0x50_0000,
                length: 0x1000,
                permissions: MAP_READ,
            },
            IdentityMappingRange {
                physical_start: 0x60_0000,
                length: 0x1000,
                permissions: MAP_READ,
            },
        ];
        assert_eq!(
            plan_identity_page_mappings(&two, &mut [KernelPageMapping::default(); 1]),
            Err(IdentityMappingError::OutputTooSmall)
        );
    }

    #[test]
    fn combined_mapping_planner_appends_disjoint_identity_ranges() {
        let kernel = [KernelPageMapping {
            physical_start: 0x20_0000,
            virtual_start: 0xffff_ffff_8000_0000,
            page_count: 2,
            permissions: MAP_READ | MAP_EXECUTE,
        }];
        let identity = [IdentityMappingRange {
            physical_start: 0x40_0123,
            length: 0x1000,
            permissions: MAP_READ | MAP_WRITE,
        }];
        let mut output = [KernelPageMapping::default(); 2];
        assert_eq!(
            plan_combined_page_mappings(&kernel, &identity, &mut output),
            Ok(2)
        );
        assert_eq!(output[0], kernel[0]);
        assert_eq!(output[1].physical_start, 0x40_0000);
        assert_eq!(output[1].virtual_start, 0x40_0000);
        assert_eq!(output[1].permissions, MAP_READ | MAP_WRITE);
    }

    #[test]
    fn combined_mapping_planner_rejects_virtual_collisions_and_bad_kernel_ranges() {
        let kernel = [KernelPageMapping {
            physical_start: 0x20_0000,
            virtual_start: 0x30_0000,
            page_count: 2,
            permissions: MAP_READ | MAP_WRITE,
        }];
        let collision = [IdentityMappingRange {
            physical_start: 0x30_1000,
            length: 0x1000,
            permissions: MAP_READ,
        }];
        let mut output = [KernelPageMapping::default(); 2];
        assert_eq!(
            plan_combined_page_mappings(&kernel, &collision, &mut output),
            Err(CombinedMappingError::OverlappingMapping)
        );

        let invalid = [KernelPageMapping {
            permissions: MAP_WRITE | MAP_EXECUTE,
            ..kernel[0]
        }];
        assert_eq!(
            plan_combined_page_mappings(&invalid, &[], &mut output),
            Err(CombinedMappingError::InvalidKernelMapping)
        );
    }

    #[test]
    fn combined_mapping_planner_checks_capacity_and_address_overflow() {
        let kernel = [KernelPageMapping {
            physical_start: 0x20_0000,
            virtual_start: 0x30_0000,
            page_count: 1,
            permissions: MAP_READ,
        }];
        let identity = [IdentityMappingRange {
            physical_start: 0x40_0000,
            length: UEFI_PAGE_SIZE,
            permissions: MAP_READ,
        }];
        assert_eq!(
            plan_combined_page_mappings(&kernel, &identity, &mut [KernelPageMapping::default(); 1]),
            Err(CombinedMappingError::OutputTooSmall)
        );

        let overflowing = [KernelPageMapping {
            virtual_start: u64::MAX - 0xfff,
            ..kernel[0]
        }];
        assert_eq!(
            plan_combined_page_mappings(&overflowing, &[], &mut [KernelPageMapping::default(); 1]),
            Err(CombinedMappingError::AddressOverflow)
        );
    }

    #[test]
    fn page_table_pool_capacity_reserves_self_mapping_tables() {
        assert_eq!(page_table_pool_capacity(1), Some(7));
        assert_eq!(page_table_pool_capacity(4), Some(10));
        assert_eq!(page_table_pool_capacity(512), Some(519));
        assert_eq!(page_table_pool_capacity(0), None);
        assert_eq!(page_table_pool_capacity(usize::MAX), None);
    }

    #[test]
    fn page_table_allocation_layout_matches_table_count() {
        let layout = page_table_allocation_layout(7).unwrap();
        assert_eq!(layout.table_count, 7);
        assert_eq!(layout.allocation_pages, 7);
        assert_eq!(layout.allocation_size, 7 * UEFI_PAGE_SIZE);
    }

    #[test]
    fn page_table_allocation_layout_rejects_zero_and_overflow() {
        assert_eq!(page_table_allocation_layout(0), None);
        assert_eq!(page_table_allocation_layout(usize::MAX), None);
    }

    #[test]
    fn mapping_access_rejects_unrepresentable_permissions() {
        assert_eq!(
            mapping_access(MAP_WRITE | MAP_EXECUTE),
            Err(MappingConversionError::UnsupportedPermissions)
        );
        assert_eq!(
            mapping_access(MAP_WRITE),
            Err(MappingConversionError::UnsupportedPermissions)
        );
        assert_eq!(
            mapping_access(MAP_READ | (1 << 8)),
            Err(MappingConversionError::UnsupportedPermissions)
        );
        assert_eq!(mapping_access(MAP_READ | MAP_EXECUTE), Ok((false, true)));
        assert_eq!(mapping_access(MAP_READ | MAP_WRITE), Ok((true, false)));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn converts_kernel_mappings_for_x86_64_builder() {
        let source = [KernelPageMapping {
            physical_start: 0x20_0000,
            virtual_start: 0xffff_ffff_8000_0000,
            page_count: 2,
            permissions: MAP_READ | MAP_EXECUTE,
        }];
        let mut output = [wicofe_kernel_x86_64::paging::PageMapping {
            virtual_start: 0,
            physical_start: 0,
            page_count: 0,
            writable: false,
            executable: false,
        }; 1];
        assert_eq!(convert_kernel_page_mappings(&source, &mut output), Ok(1));
        assert_eq!(output[0].physical_start, source[0].physical_start);
        assert_eq!(output[0].virtual_start, source[0].virtual_start);
        assert_eq!(output[0].page_count, 2);
        assert!(!output[0].writable);
        assert!(output[0].executable);
    }

    fn synthetic_pe_image() -> [u8; 0x5000] {
        let mut image = [0u8; 0x5000];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        let machine = if cfg!(target_arch = "x86_64") {
            PE_MACHINE_X86_64
        } else {
            PE_MACHINE_AARCH64
        };
        image[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        image[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
        let optional = coff + 20;
        image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[optional + 56..optional + 60].copy_from_slice(&0x5000u32.to_le_bytes());
        image[optional + 60..optional + 64].copy_from_slice(&0x1000u32.to_le_bytes());
        let sections = optional + 0xf0;
        image[sections + 8..sections + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        image[sections + 12..sections + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[sections + 36..sections + 40]
            .copy_from_slice(&(PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_EXECUTE).to_le_bytes());
        let data = sections + 40;
        image[data + 8..data + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        image[data + 12..data + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        image[data + 36..data + 40]
            .copy_from_slice(&(PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_WRITE).to_le_bytes());
        image
    }

    #[test]
    fn pe_identity_mapping_preserves_header_text_and_data_permissions() {
        let image = synthetic_pe_image();
        let mut mappings = [KernelPageMapping::default(); 3];
        assert_eq!(
            plan_pe_identity_mappings(0x10_0000, &image, &mut mappings),
            Ok(3)
        );
        assert_eq!(mappings[0].physical_start, 0x10_0000);
        assert_eq!(mappings[0].permissions, MAP_READ);
        assert_eq!(mappings[1].physical_start, 0x10_1000);
        assert_eq!(mappings[1].permissions, MAP_READ | MAP_EXECUTE);
        assert_eq!(mappings[2].physical_start, 0x10_2000);
        assert_eq!(mappings[2].permissions, MAP_READ | MAP_WRITE);
    }

    #[test]
    fn pe_identity_mapping_rejects_wx_shared_pages_and_small_output() {
        let mut image = synthetic_pe_image();
        let mut mappings = [KernelPageMapping::default(); 3];
        let sections = 0x80 + 4 + 20 + 0xf0;
        image[sections + 36..sections + 40].copy_from_slice(
            &(PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_MEM_WRITE | PE_IMAGE_SCN_MEM_EXECUTE)
                .to_le_bytes(),
        );
        assert_eq!(
            plan_pe_identity_mappings(0x10_0000, &image, &mut mappings),
            Err(PeMappingError::UnsupportedPermissions)
        );

        image = synthetic_pe_image();
        image[sections + 40 + 12..sections + 40 + 16].copy_from_slice(&0x1800u32.to_le_bytes());
        assert_eq!(
            plan_pe_identity_mappings(0x10_0000, &image, &mut mappings),
            Err(PeMappingError::OverlappingSections)
        );
        assert_eq!(
            plan_pe_identity_mappings(0x10_0000, &image, &mut mappings[..2]),
            Err(PeMappingError::OutputTooSmall)
        );
    }

    #[test]
    fn pe_identity_mapping_rejects_invalid_headers_and_wrong_machine() {
        let mut image = synthetic_pe_image();
        image[0..2].copy_from_slice(b"NO");
        assert_eq!(
            plan_pe_identity_mappings(0x10_0000, &image, &mut [KernelPageMapping::default(); 3]),
            Err(PeMappingError::InvalidImage)
        );
        image = synthetic_pe_image();
        let wrong_machine = if cfg!(target_arch = "x86_64") {
            PE_MACHINE_AARCH64
        } else {
            PE_MACHINE_X86_64
        };
        image[0x84..0x86].copy_from_slice(&wrong_machine.to_le_bytes());
        assert_eq!(
            plan_pe_identity_mappings(0x10_0000, &image, &mut [KernelPageMapping::default(); 3]),
            Err(PeMappingError::UnsupportedMachine)
        );
    }

    #[test]
    fn fallback_names_match_uefi_architecture_conventions() {
        assert!(X86_64_FALLBACK_PATH.ends_with("BOOTX64.EFI"));
        assert!(AARCH64_FALLBACK_PATH.ends_with("BOOTAA64.EFI"));
    }

    #[test]
    fn allocation_layout_rounds_and_reserves_alignment_slack() {
        let layout = kernel_allocation_layout(UEFI_PAGE_SIZE + 1).unwrap();
        assert_eq!(layout.rounded_image_size, 2 * UEFI_PAGE_SIZE);
        assert_eq!(layout.image_pages, 2);
        assert_eq!(
            layout.allocation_size,
            2 * UEFI_PAGE_SIZE + KERNEL_PHYSICAL_ALIGNMENT - UEFI_PAGE_SIZE
        );
        assert_eq!(
            layout.allocation_pages,
            layout.allocation_size as usize / UEFI_PAGE_SIZE as usize
        );
    }

    #[test]
    fn allocation_layout_handles_alignment_boundaries() {
        let layout = kernel_allocation_layout(KERNEL_PHYSICAL_ALIGNMENT).unwrap();
        assert_eq!(layout.rounded_image_size, KERNEL_PHYSICAL_ALIGNMENT);
        assert_eq!(
            layout.allocation_size,
            2 * KERNEL_PHYSICAL_ALIGNMENT - UEFI_PAGE_SIZE
        );
    }

    #[test]
    fn allocation_layout_rejects_zero_and_oversized_images() {
        assert_eq!(kernel_allocation_layout(0), None);
        assert_eq!(kernel_allocation_layout(MAX_KERNEL_IMAGE_SIZE + 1), None);
    }

    #[test]
    fn plans_page_mappings_with_elf_permissions() {
        let base = 0xffff_ffff_8000_0000;
        let segments = [
            segment(base, 0x1800, PF_R | PF_X),
            segment(base + 0x2000, 0x1000, PF_R | PF_W),
        ];
        let mut output = [KernelPageMapping::default(); 2];
        let count = plan_kernel_page_mappings(0x20_0000, base, &segments, &mut output).unwrap();
        assert_eq!(count, 2);
        assert_eq!(output[0].physical_start, 0x20_0000);
        assert_eq!(output[0].virtual_start, base);
        assert_eq!(output[0].page_count, 2);
        assert_eq!(output[0].permissions, MAP_READ | MAP_EXECUTE);
        assert_eq!(output[1].physical_start, 0x20_2000);
        assert_eq!(output[1].permissions, MAP_READ | MAP_WRITE);
    }

    #[test]
    fn rejects_segments_that_share_a_page() {
        let base = 0xffff_ffff_8000_0000;
        let segments = [
            segment(base, 0x1001, PF_R | PF_X),
            segment(base + 0x1800, 0x800, PF_R | PF_W),
        ];
        let mut output = [KernelPageMapping::default(); 2];
        assert_eq!(
            plan_kernel_page_mappings(0x20_0000, base, &segments, &mut output),
            Err(MappingPlanError::SharedPage)
        );
    }

    #[test]
    fn rejects_writable_executable_mapping_and_small_output() {
        let base = 0xffff_ffff_8000_0000;
        let mut output = [KernelPageMapping::default(); 1];
        assert_eq!(
            plan_kernel_page_mappings(
                0x20_0000,
                base,
                &[segment(base, 0x1000, PF_R | PF_W | PF_X)],
                &mut output
            ),
            Err(MappingPlanError::InvalidSegment)
        );
        assert_eq!(
            plan_kernel_page_mappings(
                0x20_0000,
                base,
                &[
                    segment(base, 0x1000, PF_R),
                    segment(base + 0x2000, 0x1000, PF_R)
                ],
                &mut []
            ),
            Err(MappingPlanError::OutputTooSmall)
        );
    }
}

mod memory_map;
pub use memory_map::{
    ActiveStackMappingError, DescriptorDecodeError, MemoryMapError, MemoryReservation,
    ReservationError, UefiMemoryDescriptor, apply_memory_reservations,
    apply_memory_reservations_in_place, coalesce_memory_reservations,
    decode_uefi_memory_descriptors, translate_uefi_memory_map, validate_active_stack_mapping,
};

#[cfg(test)]
mod identity_range_coalescing_tests {
    use super::*;

    fn range(start: u64, length: u64, permissions: u32) -> IdentityMappingRange {
        IdentityMappingRange {
            physical_start: start,
            length,
            permissions,
        }
    }

    #[test]
    fn merges_ranges_that_share_a_page_after_rounding() {
        let input = [
            range(0x1001, 0x800, MAP_READ),
            range(0x1800, 0x1000, MAP_READ),
        ];
        let mut output = [IdentityMappingRange::default(); 2];
        assert_eq!(coalesce_identity_mapping_ranges(&input, &mut output), Ok(1));
        assert_eq!(output[0], range(0x1000, 0x2000, MAP_READ));
    }

    #[test]
    fn keeps_disjoint_and_adjacent_ranges_separate() {
        let input = [
            range(0x3000, 0x1000, MAP_READ),
            range(0x1000, 0x1000, MAP_READ),
        ];
        let mut output = [IdentityMappingRange::default(); 2];
        assert_eq!(coalesce_identity_mapping_ranges(&input, &mut output), Ok(2));
        assert_eq!(output[0], range(0x1000, 0x1000, MAP_READ));
        assert_eq!(output[1], range(0x3000, 0x1000, MAP_READ));
    }

    #[test]
    fn rejects_overlapping_ranges_with_different_permissions() {
        let input = [
            range(0x1000, 0x2000, MAP_READ),
            range(0x2000, 0x1000, MAP_READ | MAP_WRITE),
        ];
        let mut output = [IdentityMappingRange::default(); 2];
        assert_eq!(
            coalesce_identity_mapping_ranges(&input, &mut output),
            Err(IdentityMappingError::OverlappingRange)
        );
    }

    #[test]
    fn rejects_invalid_permissions_overflow_and_small_output() {
        let mut output = [IdentityMappingRange::default(); 1];
        assert_eq!(
            coalesce_identity_mapping_ranges(&[range(0x1000, 0, MAP_READ)], &mut output),
            Err(IdentityMappingError::InvalidRange)
        );
        assert_eq!(
            coalesce_identity_mapping_ranges(&[range(0x1000, 0x1000, MAP_WRITE)], &mut output),
            Err(IdentityMappingError::UnsupportedPermissions)
        );
        assert_eq!(
            coalesce_identity_mapping_ranges(
                &[range(u64::MAX - 0x7ff, 0x1000, MAP_READ)],
                &mut output
            ),
            Err(IdentityMappingError::AddressOverflow)
        );
        assert_eq!(
            coalesce_identity_mapping_ranges(
                &[
                    range(0x1000, 0x1000, MAP_READ),
                    range(0x3000, 0x1000, MAP_READ)
                ],
                &mut output
            ),
            Err(IdentityMappingError::OutputTooSmall)
        );
    }
    #[test]
    fn mapping_coverage_proves_translation_permissions_and_adjacent_ranges() {
        let mappings = [
            KernelPageMapping {
                physical_start: 0x20_0000,
                virtual_start: 0xffff_ffff_8000_0000,
                page_count: 1,
                permissions: MAP_READ,
            },
            KernelPageMapping {
                physical_start: 0x20_1000,
                virtual_start: 0xffff_ffff_8000_1000,
                page_count: 1,
                permissions: MAP_READ | MAP_WRITE,
            },
        ];
        assert_eq!(
            validate_mapping_coverage(
                &mappings,
                0xffff_ffff_8000_0000,
                0x20_0000,
                0x2000,
                MAP_READ,
            ),
            Ok(())
        );
        assert_eq!(
            validate_mapping_coverage(
                &mappings,
                0xffff_ffff_8000_0000,
                0x20_0000,
                0x2000,
                MAP_READ | MAP_WRITE,
            ),
            Err(MappingCoverageError::InsufficientPermissions)
        );
        assert_eq!(
            validate_mapping_coverage(
                &mappings,
                0xffff_ffff_8000_0000,
                0x30_0000,
                0x1000,
                MAP_READ,
            ),
            Err(MappingCoverageError::PhysicalAddressMismatch)
        );
    }

    #[test]
    fn mapping_coverage_rejects_gaps_and_guard_mapping() {
        let mappings = [KernelPageMapping {
            physical_start: 0x40_0000,
            virtual_start: 0xffff_0000_0000_0000,
            page_count: 1,
            permissions: MAP_READ | MAP_WRITE,
        }];
        assert_eq!(
            validate_mapping_coverage(
                &mappings,
                0xffff_0000_0000_0000,
                0x40_0000,
                0x2000,
                MAP_READ,
            ),
            Err(MappingCoverageError::MissingMapping)
        );
        assert_eq!(
            validate_mapping_absent(&mappings, 0xffff_0000_0000_0000, 0x1000),
            Err(MappingCoverageError::UnexpectedMapping)
        );
        assert_eq!(
            validate_mapping_absent(&mappings, 0xffff_0000_0000_1000, 0x1000),
            Ok(())
        );
    }
}

#[cfg(test)]
mod page_table_pool_tests {
    use super::*;

    fn pool_mapping() -> KernelPageMapping {
        KernelPageMapping {
            physical_start: 0x80_0000,
            virtual_start: 0x80_0000,
            page_count: 4,
            permissions: MAP_READ | MAP_WRITE,
        }
    }

    #[test]
    fn page_table_pool_capacity_covers_self_mapping_boundaries() {
        for base_capacity in [
            1,
            511,
            512,
            513,
            1 << 18,
            (1 << 18) + 1,
            1 << 27,
        ] {
            let capacity = page_table_pool_capacity(base_capacity).unwrap();
            let maximum_regions_touched = |pages: usize, region_pages: usize| {
                (pages + region_pages - 2) / region_pages + 1
            };
            let required = base_capacity
                + maximum_regions_touched(capacity, 1 << 27)
                + maximum_regions_touched(capacity, 1 << 18)
                + maximum_regions_touched(capacity, 1 << 9);
            assert!(capacity >= required);
        }
    }

    #[test]
    fn page_table_pool_capacity_and_allocation_layout_reject_overflow() {
        assert_eq!(page_table_pool_capacity(0), None);
        assert_eq!(page_table_pool_capacity(usize::MAX), None);
        assert_eq!(page_table_allocation_layout(0), None);
        assert_eq!(page_table_allocation_layout(usize::MAX), None);
        assert_eq!(
            page_table_allocation_layout(4),
            Some(PageTableAllocationLayout {
                table_count: 4,
                allocation_size: 4 * UEFI_PAGE_SIZE,
                allocation_pages: 4,
            })
        );
    }

    #[test]
    fn accepts_exact_read_write_non_executable_identity_pool() {
        assert_eq!(
            validate_page_table_pool_mapping(&[], &pool_mapping(), 0x80_0000, 4),
            Ok(())
        );
    }

    #[test]
    fn rejects_non_identity_or_wrong_sized_pool_mapping() {
        let mut mapping = pool_mapping();
        mapping.virtual_start += UEFI_PAGE_SIZE;
        assert_eq!(
            validate_page_table_pool_mapping(&[], &mapping, 0x80_0000, 4),
            Err(PageTablePoolError::InvalidRange)
        );

        let mut mapping = pool_mapping();
        mapping.page_count -= 1;
        assert_eq!(
            validate_page_table_pool_mapping(&[], &mapping, 0x80_0000, 4),
            Err(PageTablePoolError::InvalidRange)
        );
    }

    #[test]
    fn rejects_executable_or_read_only_pool_mapping() {
        let mut mapping = pool_mapping();
        mapping.permissions |= MAP_EXECUTE;
        assert_eq!(
            validate_page_table_pool_mapping(&[], &mapping, 0x80_0000, 4),
            Err(PageTablePoolError::InvalidPermissions)
        );

        let mut mapping = pool_mapping();
        mapping.permissions = MAP_READ;
        assert_eq!(
            validate_page_table_pool_mapping(&[], &mapping, 0x80_0000, 4),
            Err(PageTablePoolError::InvalidPermissions)
        );
    }

    #[test]
    fn rejects_virtual_overlap_with_pool() {
        let mappings = [KernelPageMapping {
            physical_start: 0x90_0000,
            virtual_start: 0x80_1000,
            page_count: 1,
            permissions: MAP_READ,
        }];
        assert_eq!(
            validate_page_table_pool_mapping(&mappings, &pool_mapping(), 0x80_0000, 4),
            Err(PageTablePoolError::OverlappingVirtualMapping)
        );
    }

    #[test]
    fn rejects_physical_alias_of_pool_frames() {
        let mappings = [KernelPageMapping {
            physical_start: 0x80_1000,
            virtual_start: 0xffff_8000_0000_0000,
            page_count: 1,
            permissions: MAP_READ,
        }];
        assert_eq!(
            validate_page_table_pool_mapping(&mappings, &pool_mapping(), 0x80_0000, 4),
            Err(PageTablePoolError::PhysicalAlias)
        );
    }

    #[test]
    fn rejects_invalid_pool_address_and_range_overflow() {
        let mut mapping = pool_mapping();
        assert_eq!(
            validate_page_table_pool_mapping(&[], &mapping, 0, 4),
            Err(PageTablePoolError::InvalidRange)
        );

        let overflow_address = !(UEFI_PAGE_SIZE - 1);
        mapping.physical_start = overflow_address;
        mapping.virtual_start = overflow_address;
        mapping.page_count = 1;
        assert_eq!(
            validate_page_table_pool_mapping(&[], &mapping, overflow_address, 1),
            Err(PageTablePoolError::AddressOverflow)
        );
    }
}
