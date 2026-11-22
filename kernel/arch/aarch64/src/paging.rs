//! AArch64 four-level translation tables for 4 KiB pages.
//!
//! The builder operates on caller-owned, zeroable table storage. It does not
//! allocate physical memory, program translation registers, or enable MMU.

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
    EmptyTablePool,
    InvalidTablePool,
    TablePoolExhausted,
    DuplicateMapping,
    AddressOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageMapping {
    pub virtual_start: u64,
    pub physical_start: u64,
    pub page_count: u64,
    pub writable: bool,
    pub executable: bool,
    pub attribute_index: u8,
}

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

/// Build mappings into a caller-provided pool of zeroed tables.
/// Address zero in the physical-address slice is the root L0 table.
pub fn build_page_tables(
    tables: &mut [[u64; ENTRIES_PER_TABLE]],
    table_physical_addresses: &[u64],
    mappings: &[PageMapping],
) -> Result<usize, PagingError> {
    if tables.is_empty() || tables.len() != table_physical_addresses.len() {
        return Err(PagingError::EmptyTablePool);
    }
    for (index, address) in table_physical_addresses.iter().enumerate() {
        if address % PAGE_SIZE != 0
            || address & !OUTPUT_ADDRESS_MASK != 0
            || table_physical_addresses[..index].contains(address)
        {
            return Err(PagingError::InvalidTablePool);
        }
    }
    for table in tables.iter_mut() {
        table.fill(0);
    }

    let mut used = 1usize;
    for mapping in mappings {
        if mapping.page_count == 0 {
            return Err(PagingError::AddressOverflow);
        }
        if mapping.writable && mapping.executable {
            return Err(PagingError::WritableExecutable);
        }
        if mapping.virtual_start % PAGE_SIZE != 0 || mapping.physical_start % PAGE_SIZE != 0 {
            return Err(PagingError::MisalignedAddress);
        }
        for page in 0..mapping.page_count {
            let offset = page
                .checked_mul(PAGE_SIZE)
                .ok_or(PagingError::AddressOverflow)?;
            let va = mapping
                .virtual_start
                .checked_add(offset)
                .ok_or(PagingError::AddressOverflow)?;
            let pa = mapping
                .physical_start
                .checked_add(offset)
                .ok_or(PagingError::AddressOverflow)?;
            let leaf = encode_page(
                pa,
                mapping.writable,
                mapping.executable,
                mapping.attribute_index,
            )?;
            let indexes = translation_table_indices(va)?;
            let mut parent = 0usize;
            for slot in indexes.iter().take(3) {
                let entry = tables[parent][*slot];
                if entry & VALID != 0 {
                    let child_address = entry & OUTPUT_ADDRESS_MASK;
                    parent = table_physical_addresses[..used]
                        .iter()
                        .position(|address| *address == child_address)
                        .ok_or(PagingError::InvalidTablePool)?;
                } else {
                    if used == tables.len() {
                        return Err(PagingError::TablePoolExhausted);
                    }
                    let child = used;
                    used += 1;
                    tables[parent][*slot] =
                        table_physical_addresses[child] | VALID | PAGE_DESCRIPTOR;
                    parent = child;
                }
            }
            let leaf_slot = indexes[3];
            if tables[parent][leaf_slot] & VALID != 0 {
                return Err(PagingError::DuplicateMapping);
            }
            tables[parent][leaf_slot] = leaf;
        }
    }
    Ok(used)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_high_half_mappings_and_reuses_tables() {
        let mut tables = [[0u64; ENTRIES_PER_TABLE]; 4];
        let addresses = [0x1000, 0x2000, 0x3000, 0x4000];
        let base = 0xffff_0000_0000_0000;
        let mappings = [
            PageMapping {
                virtual_start: base,
                physical_start: 0x20_0000,
                page_count: 1,
                writable: false,
                executable: true,
                attribute_index: 1,
            },
            PageMapping {
                virtual_start: base + PAGE_SIZE,
                physical_start: 0x20_1000,
                page_count: 1,
                writable: true,
                executable: false,
                attribute_index: 0,
            },
        ];
        assert_eq!(build_page_tables(&mut tables, &addresses, &mappings), Ok(4));
        let i = translation_table_indices(base).unwrap();
        let l1 = addresses.iter().position(|address| *address == (tables[0][i[0]] & OUTPUT_ADDRESS_MASK)).unwrap();
        let l2 = addresses.iter().position(|address| *address == (tables[l1][i[1]] & OUTPUT_ADDRESS_MASK)).unwrap();
        let l3 = addresses.iter().position(|address| *address == (tables[l2][i[2]] & OUTPUT_ADDRESS_MASK)).unwrap();
        let text = tables[l3][i[3]];
        let data = tables[l3][i[3] + 1];
        assert_ne!(text & VALID, 0);
        assert_eq!(text & AP_EL1_READ_ONLY, AP_EL1_READ_ONLY);
        assert_eq!(text & PXN, 0);
        assert_ne!(data & PXN, 0);
        assert_eq!(data & AP_EL1_READ_ONLY, 0);
    }

    #[test]
    fn rejects_wx_duplicate_and_exhausted_pool() {
        let mut tables = [[0u64; ENTRIES_PER_TABLE]; 4];
        let addresses = [0x1000, 0x2000, 0x3000, 0x4000];
        let mapping = PageMapping {
            virtual_start: 0xffff_0000_0000_0000,
            physical_start: 0x20_0000,
            page_count: 1,
            writable: true,
            executable: true,
            attribute_index: 0,
        };
        assert_eq!(
            build_page_tables(&mut tables, &addresses, &[mapping]),
            Err(PagingError::WritableExecutable)
        );
        let valid = PageMapping {
            writable: false,
            executable: true,
            ..mapping
        };
        assert_eq!(
            build_page_tables(&mut tables, &addresses, &[valid, valid]),
            Err(PagingError::DuplicateMapping)
        );
        let mut short = [[0u64; ENTRIES_PER_TABLE]; 3];
        assert_eq!(
            build_page_tables(&mut short, &addresses[..3], &[valid]),
            Err(PagingError::TablePoolExhausted)
        );
    }

    #[test]
    fn rejects_invalid_table_pool_and_noncanonical_address() {
        let mut tables = [[0u64; ENTRIES_PER_TABLE]; 2];
        assert_eq!(
            build_page_tables(&mut tables, &[0x1000, 0x1000], &[]),
            Err(PagingError::InvalidTablePool)
        );
        assert_eq!(
            translation_table_indices(0x0000_8000_0000_0000),
            Err(PagingError::NonCanonicalVirtualAddress)
        );
    }
}
