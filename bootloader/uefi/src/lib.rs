#![no_std]

//! UEFI-facing boundary for Wicofe Bootloader (WBL).
//!
//! The PE/COFF entry point, protocol discovery, memory-map handling, and image
//! loading are deferred to a later implementation stage. This crate is a
//! library scaffold, not yet a bootable UEFI application.

pub use wicofe_bootloader_common::{BootInfo, MemoryRegion, BOOT_INFO_VERSION};

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
}
