#![no_std]

//! AArch64-specific kernel boundary. Exception-level setup and assembly
//! routines are not implemented in this initial workspace scaffold.

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
