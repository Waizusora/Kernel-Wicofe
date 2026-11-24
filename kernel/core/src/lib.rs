#![no_std]

//! Architecture-independent kernel foundation.
//!
//! The core validates the versioned boot contract before architecture code
//! consumes physical addresses or memory-map entries.

pub mod boot;
pub mod memory;

pub use wicofe_bootloader_common::BootInfo;

/// Kernel version reported by the initial development scaffold.
pub const KERNEL_VERSION: (u16, u16, u16) = (0, 1, 0);

/// Validate the version field before interpreting a boot handoff structure.
pub const fn supports_boot_info(info: &BootInfo) -> bool {
    info.version == wicofe_bootloader_common::BOOT_INFO_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_current_boot_info_version() {
        let info = BootInfo {
            version: wicofe_bootloader_common::BOOT_INFO_VERSION,
            ..BootInfo::default()
        };
        assert!(supports_boot_info(&info));
    }

    #[test]
    fn rejects_unknown_boot_info_version() {
        let info = BootInfo {
            version: u32::MAX,
            ..BootInfo::default()
        };
        assert!(!supports_boot_info(&info));
    }
}
