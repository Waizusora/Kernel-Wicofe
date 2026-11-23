#![no_std]

//! AArch64-specific kernel boundary and translation-table primitives.

pub mod paging;

/// Architecture identifier used by the WBL handoff protocol.
pub const ARCHITECTURE_ID: u32 = 2;

/// Architectural register snapshot required before the AArch64 kernel handoff.
///
/// This is a read-only validation model. It does not program translation
/// registers, change exception masks, or switch exception levels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffCpuState {
    pub current_el: u64,
    pub aarch64_state: bool,
    pub daif: u64,
    pub sctlr_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffCpuStateError {
    UnsupportedExceptionLevel,
    NotAarch64State,
    ExceptionsNotMasked,
    TranslationDisabled,
    InvalidTranslationConfiguration,
    InvalidMemoryAttributes,
    MisalignedTranslationTable,
}

/// Validate the CPU state against the AArch64 ABI v2 entry contract.
///
/// The expected translation regime is 4 KiB granules and 48-bit virtual
/// addresses for both TTBR0_EL1 and TTBR1_EL1. Attribute index zero is
/// Normal, Inner/Outer Write-Back cacheable memory (MAIR byte 0 = 0xff).
pub const fn validate_handoff_cpu_state(
    state: HandoffCpuState,
) -> Result<(), HandoffCpuStateError> {
    const CURRENT_EL_MASK: u64 = 0b11 << 2;
    const CURRENT_EL1: u64 = 0b01 << 2;
    const DAIF_MASK: u64 = 0b1111 << 6;
    const SCTLR_M: u64 = 1;
    const TCR_T0SZ_MASK: u64 = 0b11_1111;
    const TCR_TG0_MASK: u64 = 0b11 << 14;
    const TCR_T1SZ_MASK: u64 = 0b11_1111 << 16;
    const TCR_TG1_MASK: u64 = 0b11 << 30;
    const TCR_TG1_4K: u64 = 0b10 << 30;
    const TTBR_ADDRESS_ALIGNMENT_MASK: u64 = 0xfff;

    if state.current_el & CURRENT_EL_MASK != CURRENT_EL1 {
        return Err(HandoffCpuStateError::UnsupportedExceptionLevel);
    }
    if !state.aarch64_state {
        return Err(HandoffCpuStateError::NotAarch64State);
    }
    if state.daif & DAIF_MASK != DAIF_MASK {
        return Err(HandoffCpuStateError::ExceptionsNotMasked);
    }
    if state.sctlr_el1 & SCTLR_M == 0 {
        return Err(HandoffCpuStateError::TranslationDisabled);
    }
    if state.tcr_el1 & TCR_T0SZ_MASK != 16
        || state.tcr_el1 & TCR_TG0_MASK != 0
        || (state.tcr_el1 & TCR_T1SZ_MASK) >> 16 != 16
        || state.tcr_el1 & TCR_TG1_MASK != TCR_TG1_4K
    {
        return Err(HandoffCpuStateError::InvalidTranslationConfiguration);
    }
    if state.mair_el1 & 0xff != 0xff {
        return Err(HandoffCpuStateError::InvalidMemoryAttributes);
    }
    if state.ttbr0_el1 & TTBR_ADDRESS_ALIGNMENT_MASK != 0
        || state.ttbr1_el1 & TTBR_ADDRESS_ALIGNMENT_MASK != 0
    {
        return Err(HandoffCpuStateError::MisalignedTranslationTable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_handoff_state() -> HandoffCpuState {
        HandoffCpuState {
            current_el: 1 << 2,
            aarch64_state: true,
            daif: 0b1111 << 6,
            sctlr_el1: 1,
            tcr_el1: 16 | (16 << 16) | (0b10 << 30),
            mair_el1: 0xff,
            ttbr0_el1: 0x1000,
            ttbr1_el1: 0x2000,
        }
    }

    #[test]
    fn accepts_valid_handoff_cpu_state() {
        assert_eq!(validate_handoff_cpu_state(valid_handoff_state()), Ok(()));
    }

    #[test]
    fn rejects_wrong_exception_level_and_execution_state() {
        let mut state = valid_handoff_state();
        state.current_el = 2 << 2;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::UnsupportedExceptionLevel)
        );
        state = valid_handoff_state();
        state.aarch64_state = false;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::NotAarch64State)
        );
    }

    #[test]
    fn rejects_unmasked_exceptions_and_disabled_translation() {
        let mut state = valid_handoff_state();
        state.daif &= !(1 << 7);
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::ExceptionsNotMasked)
        );
        state = valid_handoff_state();
        state.sctlr_el1 = 0;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::TranslationDisabled)
        );
    }

    #[test]
    fn rejects_wrong_granule_address_size_and_memory_attributes() {
        let mut state = valid_handoff_state();
        state.tcr_el1 = 16 | (16 << 16) | (0b01 << 30);
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::InvalidTranslationConfiguration)
        );
        state = valid_handoff_state();
        state.mair_el1 = 0;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::InvalidMemoryAttributes)
        );
    }

    #[test]
    fn rejects_misaligned_translation_table_roots() {
        let mut state = valid_handoff_state();
        state.ttbr1_el1 |= 1;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::MisalignedTranslationTable)
        );
    }

    #[test]
    fn architecture_identifier_is_aarch64() {
        assert_eq!(ARCHITECTURE_ID, 2);
    }
}
