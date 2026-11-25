#![no_std]

//! x86_64-specific kernel boundary and paging primitives.

pub mod paging;

/// Architecture identifier used by the WBL handoff protocol.
pub const ARCHITECTURE_ID: u32 = 1;

/// Architectural register snapshot required before the x86_64 kernel handoff.
///
/// This is a read-only validation model. It does not change control registers,
/// descriptor tables, interrupt state, or the active page-table root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffCpuState {
    pub cr0: u64,
    pub cr4: u64,
    pub efer: u64,
    pub rflags: u64,
    pub cs: u16,
}

/// Snapshot of the active x86_64 global descriptor table and segment selectors.
///
/// This records descriptor-table metadata only; it does not prove that the
/// referenced descriptors have the required type, privilege, or flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorTableState {
    pub base: u64,
    pub limit: u16,
    pub cs: u16,
    pub ss: u16,
    pub ds: u16,
    pub es: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorTableStateError {
    NullCodeSelector,
    CodeSelectorUsesLdt,
    CodeSelectorPrivilegeMismatch,
    CodeDescriptorOutsideTable,
    DescriptorTableAddressOverflow,
}

/// Check that the current CS selector names an in-bounds GDT descriptor.
///
/// This is deliberately not a descriptor-content validator. WBL must install
/// its own known GDT before handoff rather than relying on firmware descriptors.
pub const fn validate_descriptor_table_state(
    state: DescriptorTableState,
) -> Result<(), DescriptorTableStateError> {
    if state.base.checked_add(u64::from(state.limit)).is_none() {
        return Err(DescriptorTableStateError::DescriptorTableAddressOverflow);
    }
    if state.cs & !0b11 == 0 {
        return Err(DescriptorTableStateError::NullCodeSelector);
    }
    if state.cs & (1 << 2) != 0 {
        return Err(DescriptorTableStateError::CodeSelectorUsesLdt);
    }
    if state.cs & 0b11 != 0 {
        return Err(DescriptorTableStateError::CodeSelectorPrivilegeMismatch);
    }
    let descriptor_end = u32::from(state.cs & !0b111) + 7;
    if descriptor_end > u32::from(state.limit) {
        return Err(DescriptorTableStateError::CodeDescriptorOutsideTable);
    }
    Ok(())
}

/// Capture GDTR and the active code/data selectors without modifying them.
///
/// # Safety
///
/// The caller must execute in privileged x86_64 mode.
#[cfg(target_arch = "x86_64")]
pub unsafe fn capture_descriptor_table_state() -> DescriptorTableState {
    let mut gdtr = [0u8; 10];
    let cs: u16;
    let ss: u16;
    let ds: u16;
    let es: u16;
    // SAFETY: SGDT and segment-register moves are read-only privileged-state queries.
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack, preserves_flags));
        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {0:x}, ds", out(reg) ds, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {0:x}, es", out(reg) es, options(nomem, nostack, preserves_flags));
    }
    DescriptorTableState {
        limit: u16::from_le_bytes([gdtr[0], gdtr[1]]),
        base: u64::from_le_bytes([gdtr[2], gdtr[3], gdtr[4], gdtr[5], gdtr[6], gdtr[7], gdtr[8], gdtr[9]]),
        cs,
        ss,
        ds,
        es,
    }
}

/// Capture the current privileged CPU state without changing it.
///
/// # Safety
///
/// The caller must execute at CPL 0. Reading control registers and EFER from
/// an unprivileged context would fault.
#[cfg(target_arch = "x86_64")]
pub unsafe fn capture_handoff_cpu_state() -> HandoffCpuState {
    let cr0: u64;
    let cr4: u64;
    let rflags: u64;
    let cs: u16;
    let efer_low: u32;
    let efer_high: u32;

    // SAFETY: the caller guarantees CPL 0; these instructions only read state.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        core::arch::asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
        core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xc000_0080u32,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags)
        );
    }

    HandoffCpuState {
        cr0,
        cr4,
        efer: (u64::from(efer_high) << 32) | u64::from(efer_low),
        rflags,
        cs,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffCpuStateError {
    PagingDisabled,
    WriteProtectDisabled,
    PhysicalAddressExtensionsDisabled,
    FiveLevelPagingEnabled,
    LongModeDisabled,
    InterruptsEnabled,
    DirectionFlagSet,
    NotRunningAtKernelPrivilege,
}

/// Validate the firmware CPU state against the x86_64 ABI v2 entry contract.
///
/// The caller must obtain a trustworthy register snapshot while executing at
/// CPL 0. This check cannot inspect GDT descriptor contents; WBL must establish
/// or independently verify flat 64-bit code/data descriptors before transfer.
pub const fn validate_handoff_cpu_state(
    state: HandoffCpuState,
) -> Result<(), HandoffCpuStateError> {
    const CR0_PG: u64 = 1 << 31;
    const CR0_WP: u64 = 1 << 16;
    const CR4_PAE: u64 = 1 << 5;
    const CR4_LA57: u64 = 1 << 12;
    const EFER_LME: u64 = 1 << 8;
    const EFER_LMA: u64 = 1 << 10;
    const RFLAGS_IF: u64 = 1 << 9;
    const RFLAGS_DF: u64 = 1 << 10;

    if state.cr0 & CR0_PG == 0 {
        return Err(HandoffCpuStateError::PagingDisabled);
    }
    if state.cr0 & CR0_WP == 0 {
        return Err(HandoffCpuStateError::WriteProtectDisabled);
    }
    if state.cr4 & CR4_PAE == 0 {
        return Err(HandoffCpuStateError::PhysicalAddressExtensionsDisabled);
    }
    if state.cr4 & CR4_LA57 != 0 {
        return Err(HandoffCpuStateError::FiveLevelPagingEnabled);
    }
    if state.efer & (EFER_LME | EFER_LMA) != (EFER_LME | EFER_LMA) {
        return Err(HandoffCpuStateError::LongModeDisabled);
    }
    if state.rflags & RFLAGS_IF != 0 {
        return Err(HandoffCpuStateError::InterruptsEnabled);
    }
    if state.rflags & RFLAGS_DF != 0 {
        return Err(HandoffCpuStateError::DirectionFlagSet);
    }
    if state.cs & 0b11 != 0 {
        return Err(HandoffCpuStateError::NotRunningAtKernelPrivilege);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_handoff_state() -> HandoffCpuState {
        HandoffCpuState {
            cr0: (1 << 31) | (1 << 16),
            cr4: 1 << 5,
            efer: (1 << 8) | (1 << 10),
            rflags: 0x2,
            cs: 0x8,
        }
    }

    #[test]
    fn accepts_valid_handoff_cpu_state() {
        assert_eq!(validate_handoff_cpu_state(valid_handoff_state()), Ok(()));
    }

    #[test]
    fn rejects_missing_paging_and_write_protect() {
        let mut state = valid_handoff_state();
        state.cr0 &= !(1 << 31);
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::PagingDisabled)
        );
        state = valid_handoff_state();
        state.cr0 &= !(1 << 16);
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::WriteProtectDisabled)
        );
    }

    #[test]
    fn rejects_missing_pae_or_long_mode() {
        let mut state = valid_handoff_state();
        state.cr4 = 0;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::PhysicalAddressExtensionsDisabled)
        );
        state = valid_handoff_state();
        state.efer &= !(1 << 10);
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::LongModeDisabled)
        );
    }

    #[test]
    fn rejects_five_level_paging_mode() {
        let mut state = valid_handoff_state();
        state.cr4 |= 1 << 12;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::FiveLevelPagingEnabled)
        );
    }

    #[test]
    fn rejects_unmasked_interrupts_direction_flag_and_nonzero_cpl() {
        let mut state = valid_handoff_state();
        state.rflags |= 1 << 9;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::InterruptsEnabled)
        );
        state = valid_handoff_state();
        state.rflags |= 1 << 10;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::DirectionFlagSet)
        );
        state = valid_handoff_state();
        state.cs |= 3;
        assert_eq!(
            validate_handoff_cpu_state(state),
            Err(HandoffCpuStateError::NotRunningAtKernelPrivilege)
        );
    }

    #[test]
    fn accepts_code_selector_within_gdt_bounds() {
        let state = DescriptorTableState {
            base: 0x1000,
            limit: 0x17,
            cs: 0x8,
            ss: 0x10,
            ds: 0x10,
            es: 0x10,
        };
        assert_eq!(validate_descriptor_table_state(state), Ok(()));
    }

    #[test]
    fn rejects_invalid_code_selector_and_gdt_bounds() {
        let mut state = DescriptorTableState {
            base: 0x1000,
            limit: 0x17,
            cs: 0x8,
            ss: 0x10,
            ds: 0x10,
            es: 0x10,
        };
        state.cs = 0;
        assert_eq!(validate_descriptor_table_state(state), Err(DescriptorTableStateError::NullCodeSelector));
        state.cs = 0x0c;
        assert_eq!(validate_descriptor_table_state(state), Err(DescriptorTableStateError::CodeSelectorUsesLdt));
        state.cs = 0x0b;
        assert_eq!(validate_descriptor_table_state(state), Err(DescriptorTableStateError::CodeSelectorPrivilegeMismatch));
        state.cs = 0x18;
        assert_eq!(validate_descriptor_table_state(state), Err(DescriptorTableStateError::CodeDescriptorOutsideTable));
        state.cs = 0x8;
        state.base = u64::MAX;
        assert_eq!(validate_descriptor_table_state(state), Err(DescriptorTableStateError::DescriptorTableAddressOverflow));
    }

    #[test]
    fn architecture_identifier_is_x86_64() {
        assert_eq!(ARCHITECTURE_ID, 1);
    }
}
