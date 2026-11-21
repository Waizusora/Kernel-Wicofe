#![no_std]

//! UEFI-facing boundary and checked allocation planning for Wicofe Bootloader.

pub use wicofe_bootloader_common::{BOOT_INFO_VERSION, BootInfo, MemoryRegion};

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
///
/// The extra space accounts for the worst-case alignment adjustment. The
/// caller may release the unused prefix and suffix after placing the image.
pub fn kernel_allocation_layout(image_size: u64) -> Option<KernelAllocationLayout> {
    if image_size == 0 || image_size > MAX_KERNEL_IMAGE_SIZE {
        return None;
    }

    let rounded_image_size = image_size.checked_add(UEFI_PAGE_SIZE - 1)?
        & !(UEFI_PAGE_SIZE - 1);
    let allocation_size = rounded_image_size
        .checked_add(KERNEL_PHYSICAL_ALIGNMENT - UEFI_PAGE_SIZE)?;
    let image_pages = usize::try_from(rounded_image_size / UEFI_PAGE_SIZE).ok()?;
    let allocation_pages = usize::try_from(allocation_size / UEFI_PAGE_SIZE).ok()?;

    Some(KernelAllocationLayout {
        rounded_image_size,
        allocation_size,
        image_pages,
        allocation_pages,
    })
}

/// UEFI removable-media fallback path for x86-64 firmware.
pub const X86_64_FALLBACK_PATH: &str = r"\EFI\BOOT\BOOTX64.EFI";

/// UEFI removable-media fallback path for AArch64 firmware.
pub const AARCH64_FALLBACK_PATH: &str = r"\EFI\BOOT\BOOTAA64.EFI";

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(layout.allocation_size, 2 * UEFI_PAGE_SIZE + KERNEL_PHYSICAL_ALIGNMENT - UEFI_PAGE_SIZE);
        assert_eq!(layout.allocation_pages, layout.allocation_size as usize / UEFI_PAGE_SIZE as usize);
    }

    #[test]
    fn allocation_layout_handles_alignment_boundaries() {
        let layout = kernel_allocation_layout(KERNEL_PHYSICAL_ALIGNMENT).unwrap();
        assert_eq!(layout.rounded_image_size, KERNEL_PHYSICAL_ALIGNMENT);
        assert_eq!(layout.allocation_size, 2 * KERNEL_PHYSICAL_ALIGNMENT - UEFI_PAGE_SIZE);
    }

    #[test]
    fn allocation_layout_rejects_zero_and_oversized_images() {
        assert_eq!(kernel_allocation_layout(0), None);
        assert_eq!(kernel_allocation_layout(MAX_KERNEL_IMAGE_SIZE + 1), None);
    }
}
