//! Kernel-side validation of the WBL boot handoff.
//!
//! This module accepts only an already mapped and bounds-checked memory-map
//! slice. Mapping arbitrary physical addresses is the responsibility of the
//! architecture entry code and must happen before this API is called.

use wicofe_bootloader_common::{
    architecture, validate_boot_info, BootInfo, BootInfoError, MemoryRegion,
};

/// Failure while validating the boot contract for this kernel image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelBootError {
    InvalidBootInfo(BootInfoError),
    ArchitectureMismatch {
        expected: u32,
        actual: u32,
    },
}

/// Validate ABI v2 metadata and ensure the handoff targets this architecture.
///
/// `expected_architecture` must be one of
/// `wicofe_bootloader_common::architecture::{X86_64, AARCH64}`.
/// The supplied memory map must already be safely accessible.
pub fn validate_boot_handoff(
    expected_architecture: u32,
    info: &BootInfo,
    memory_map: &[MemoryRegion],
) -> Result<(), KernelBootError> {
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicofe_bootloader_common::{memory_attribute, memory_kind, BOOT_INFO_MAGIC, BOOT_INFO_VERSION};

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
            memory_map_entries: 2,
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
}
