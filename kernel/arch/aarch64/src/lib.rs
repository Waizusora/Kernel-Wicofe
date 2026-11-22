#![no_std]

//! AArch64-specific kernel boundary and translation-table primitives.

pub mod paging;

/// Architecture identifier used by the WBL handoff protocol.
pub const ARCHITECTURE_ID: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_identifier_is_aarch64() {
        assert_eq!(ARCHITECTURE_ID, 2);
    }
}
