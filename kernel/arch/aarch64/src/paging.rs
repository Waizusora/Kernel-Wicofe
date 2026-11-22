//! AArch64 four-level translation descriptor encoding for 4 KiB pages.
//!
//! This module builds and validates level-3 page descriptors only. It does
//! not allocate translation tables, program TTBR/TCR/MAIR, or enable MMU.

pub const PAGE_SIZE: u64 = 4096;
pub const ENTRIES_PER_TABLE: usize = 512;
pub const OUTPUT_ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
pub const VALID: u64 = 1 << 0;
pub const PAGE_DESCRIPTOR: u64 = 1 << 1;
pub const ATTR_INDEX_SHIFT: u32 = 2;
pub const INNER_SHAREABLE: u64 = 0b11 << 8;
pub const ACCESS_FLAG: u64 = 1 << 10;
pub const AP_EL1_READ_ONLY: u64 = 0b10 << 6;
pub const PXN: u64 = 1 << 53;
pub const UXN: u64 = 1 << 54;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingError {
    MisalignedAddress,
    OutputAddressOutOfRange,
    InvalidAttributeIndex,
    NonCanonicalVirtualAddress,
    WritableExecutable,
}

/// Encode an EL1-only, inner-shareable 4 KiB page descriptor.
///
/// AttrIndx selects an entry configured by MAIR_EL1. The caller is responsible
/// for programming a compatible MAIR/TCR regime before enabling translation.
pub fn encode_page(
    output_address: u64,
    writable: bool,
    executable: bool,
    attribute_index: u8,
) -> Result<u64, PagingError> {
    if output_address % PAGE_SIZE != 0 {
        return Err(PagingError::MisalignedAddress);
    }
    if output_address & !OUTPUT_ADDRESS_MASK != 0 {
        return Err(PagingError::OutputAddressOutOfRange);
    }
    if attribute_index >= 8 {
        return Err(PagingError::InvalidAttributeIndex);
    }
    if writable && executable {
        return Err(PagingError::WritableExecutable);
    }

    let mut descriptor = output_address
        | VALID
        | PAGE_DESCRIPTOR
        | ((attribute_index as u64) << ATTR_INDEX_SHIFT)
        | INNER_SHAREABLE
        | ACCESS_FLAG
        | UXN;
    if !writable {
        descriptor |= AP_EL1_READ_ONLY;
    }
    if !executable {
        descriptor |= PXN;
    }
    Ok(descriptor)
}

/// Return level-0 through level-3 indexes for a canonical 48-bit VA.
pub fn translation_table_indices(virtual_address: u64) -> Result<[usize; 4], PagingError> {
    if virtual_address >> 48 != 0xffff {
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
        let descriptor = encode_page(0x20_0000, true, false, 0).unwrap();
        assert_eq!(descriptor & OUTPUT_ADDRESS_MASK, 0x20_0000);
        assert_ne!(descriptor & VALID, 0);
        assert_ne!(descriptor & PAGE_DESCRIPTOR, 0);
        assert_ne!(descriptor & PXN, 0);
        assert_ne!(descriptor & UXN, 0);
        assert_eq!(descriptor & AP_EL1_READ_ONLY, 0);
    }

    #[test]
    fn encodes_read_only_executable_kernel_text() {
        let descriptor = encode_page(0x40_0000, false, true, 1).unwrap();
        assert_ne!(descriptor & VALID, 0);
        assert_eq!(descriptor & AP_EL1_READ_ONLY, AP_EL1_READ_ONLY);
        assert_eq!(descriptor & PXN, 0);
        assert_ne!(descriptor & UXN, 0);
        assert_eq!((descriptor >> ATTR_INDEX_SHIFT) & 0b111, 1);
    }

    #[test]
    fn rejects_invalid_addresses_attributes_and_wx() {
        assert_eq!(
            encode_page(0x2001, false, true, 0),
            Err(PagingError::MisalignedAddress)
        );
        assert_eq!(
            encode_page(1 << 48, false, true, 0),
            Err(PagingError::OutputAddressOutOfRange)
        );
        assert_eq!(
            encode_page(0x20_0000, false, true, 8),
            Err(PagingError::InvalidAttributeIndex)
        );
        assert_eq!(
            encode_page(0x20_0000, true, true, 0),
            Err(PagingError::WritableExecutable)
        );
    }

    #[test]
    fn extracts_indices_for_kernel_high_half() {
        assert_eq!(
            translation_table_indices(0xffff_0000_0000_0000),
            Ok([0, 0, 0, 0])
        );
    }

    #[test]
    fn rejects_noncanonical_virtual_address() {
        assert_eq!(
            translation_table_indices(0x0000_8000_0000_0000),
            Err(PagingError::NonCanonicalVirtualAddress)
        );
    }
}
