//! x86-64 four-level paging descriptor encoding for 4 KiB pages.
//!
//! This module builds and validates leaf-entry values only. It does not
//! allocate page-table pages, install CR3, or change the active address space.

pub const PAGE_SIZE: u64 = 4096;
pub const ENTRIES_PER_TABLE: usize = 512;
pub const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
pub const PRESENT: u64 = 1 << 0;
pub const WRITABLE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const NO_EXECUTE: u64 = 1 << 63;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingError {
    MisalignedAddress,
    PhysicalAddressOutOfRange,
    NonCanonicalVirtualAddress,
    WritableExecutable,
}

/// Encode a present 4 KiB leaf mapping for supervisor mode.
///
/// Read access is implicit in x86-64 page tables. Non-executable mappings
/// receive the NX bit; callers must enable EFER.NXE before installing them.
pub fn encode_page(
    physical_address: u64,
    writable: bool,
    executable: bool,
) -> Result<u64, PagingError> {
    if physical_address % PAGE_SIZE != 0 {
        return Err(PagingError::MisalignedAddress);
    }
    if physical_address & !PHYSICAL_ADDRESS_MASK != 0 {
        return Err(PagingError::PhysicalAddressOutOfRange);
    }
    if writable && executable {
        return Err(PagingError::WritableExecutable);
    }

    let mut entry = physical_address | PRESENT;
    if writable {
        entry |= WRITABLE;
    }
    if !executable {
        entry |= NO_EXECUTE;
    }
    Ok(entry)
}

/// Return PML4, PDPT, PD, and PT indexes for a canonical 48-bit VA.
pub fn page_table_indices(virtual_address: u64) -> Result<[usize; 4], PagingError> {
    let upper = virtual_address >> 48;
    let sign = (virtual_address >> 47) & 1;
    if (sign == 0 && upper != 0) || (sign == 1 && upper != 0xffff) {
        return Err(PagingError::NonCanonicalVirtualAddress);
    }

    Ok([
        ((virtual_address >> 39) & 0x1ff) as usize,
        ((virtual_address >> 30) & 0x1ff) as usize,
        ((virtual_address >> 21) & 0x1ff) as usize,
        ((virtual_address >> 12) & 0x1ff) as usize,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_writable_non_executable_kernel_data() {
        let entry = encode_page(0x20_0000, true, false).unwrap();
        assert_eq!(entry & PHYSICAL_ADDRESS_MASK, 0x20_0000);
        assert_ne!(entry & PRESENT, 0);
        assert_ne!(entry & WRITABLE, 0);
        assert_ne!(entry & NO_EXECUTE, 0);
        assert_eq!(entry & USER, 0);
    }

    #[test]
    fn encodes_read_only_executable_kernel_text() {
        let entry = encode_page(0x40_0000, false, true).unwrap();
        assert_ne!(entry & PRESENT, 0);
        assert_eq!(entry & WRITABLE, 0);
        assert_eq!(entry & NO_EXECUTE, 0);
    }

    #[test]
    fn rejects_invalid_page_addresses_and_wx() {
        assert_eq!(
            encode_page(0x2001, false, true),
            Err(PagingError::MisalignedAddress)
        );
        assert_eq!(
            encode_page(1 << 52, false, true),
            Err(PagingError::PhysicalAddressOutOfRange)
        );
        assert_eq!(
            encode_page(0x20_0000, true, true),
            Err(PagingError::WritableExecutable)
        );
    }

    #[test]
    fn extracts_indices_for_kernel_high_half() {
        assert_eq!(
            page_table_indices(0xffff_ffff_8000_0000),
            Ok([511, 510, 0, 0])
        );
    }

    #[test]
    fn rejects_noncanonical_virtual_address() {
        assert_eq!(
            page_table_indices(0x0000_8000_0000_0000),
            Err(PagingError::NonCanonicalVirtualAddress)
        );
    }
}
