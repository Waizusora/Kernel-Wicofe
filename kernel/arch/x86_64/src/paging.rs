//! x86-64 four-level paging for 4 KiB pages.
//!
//! The builder operates on caller-owned, zeroable page-table storage. It does
//! not allocate physical memory, install CR3, or change the active address space.

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
}

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

/// Build mappings into a caller-provided pool of zeroed 4 KiB tables.
/// Address zero in the physical-address slice is the root PML4.
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
            || address & !PHYSICAL_ADDRESS_MASK != 0
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
            let leaf = encode_page(pa, mapping.writable, mapping.executable)?;
            let indexes = page_table_indices(va)?;
            let mut parent = 0usize;
            for slot in indexes.iter().take(3) {
                let entry = tables[parent][*slot];
                if entry & PRESENT != 0 {
                    let child_address = entry & PHYSICAL_ADDRESS_MASK;
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
                    tables[parent][*slot] = table_physical_addresses[child] | PRESENT | WRITABLE;
                    parent = child;
                }
            }
            let leaf_slot = indexes[3];
            if tables[parent][leaf_slot] & PRESENT != 0 {
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

    fn table_index(addresses: &[u64], entry: u64) -> usize {
        addresses
            .iter()
            .position(|address| *address == (entry & PHYSICAL_ADDRESS_MASK))
            .unwrap()
    }

    #[test]
    fn builds_high_half_mappings_and_reuses_tables() {
        let mut tables = [[0u64; ENTRIES_PER_TABLE]; 4];
        let addresses = [0x1000, 0x2000, 0x3000, 0x4000];
        let base = 0xffff_ffff_8000_0000;
        let mappings = [
            PageMapping {
                virtual_start: base,
                physical_start: 0x20_0000,
                page_count: 1,
                writable: false,
                executable: true,
            },
            PageMapping {
                virtual_start: base + PAGE_SIZE,
                physical_start: 0x20_1000,
                page_count: 1,
                writable: true,
                executable: false,
            },
        ];
        assert_eq!(build_page_tables(&mut tables, &addresses, &mappings), Ok(4));
        let i = page_table_indices(base).unwrap();
        let pdpt = table_index(&addresses, tables[0][i[0]]);
        let pd = table_index(&addresses, tables[pdpt][i[1]]);
        let pt = table_index(&addresses, tables[pd][i[2]]);
        let text = tables[pt][i[3]];
        let data = tables[pt][i[3] + 1];
        assert_ne!(text & PRESENT, 0);
        assert_eq!(text & WRITABLE, 0);
        assert_eq!(text & NO_EXECUTE, 0);
        assert_ne!(data & WRITABLE, 0);
        assert_ne!(data & NO_EXECUTE, 0);
    }

    #[test]
    fn rejects_wx_duplicate_and_exhausted_pool() {
        let mut tables = [[0u64; ENTRIES_PER_TABLE]; 4];
        let addresses = [0x1000, 0x2000, 0x3000, 0x4000];
        let mapping = PageMapping {
            virtual_start: 0xffff_ffff_8000_0000,
            physical_start: 0x20_0000,
            page_count: 1,
            writable: true,
            executable: true,
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
            page_table_indices(0x0000_8000_0000_0000),
            Err(PagingError::NonCanonicalVirtualAddress)
        );
    }
}
