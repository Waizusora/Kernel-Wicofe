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
