#![no_std]

//! x86_64-specific kernel boundary. CPU setup and assembly routines are not
//! implemented in this initial workspace scaffold.

/// Architecture identifier used by the WBL handoff protocol.
pub const ARCHITECTURE_ID: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_identifier_is_x86_64() {
        assert_eq!(ARCHITECTURE_ID, 1);
    }
}
