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
    InvalidTableTopology,
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

/// Validate a complete mapping before sizing or mutating the table pool.
fn validate_mapping(mapping: &PageMapping) -> Result<u64, PagingError> {
    if mapping.page_count == 0 {
        return Err(PagingError::AddressOverflow);
    }
    if mapping.writable && mapping.executable {
        return Err(PagingError::WritableExecutable);
    }
    if mapping.virtual_start % PAGE_SIZE != 0 || mapping.physical_start % PAGE_SIZE != 0 {
        return Err(PagingError::MisalignedAddress);
    }
    let last_offset = (mapping.page_count - 1)
        .checked_mul(PAGE_SIZE)
        .ok_or(PagingError::AddressOverflow)?;
    let last_virtual = mapping
        .virtual_start
        .checked_add(last_offset)
        .ok_or(PagingError::AddressOverflow)?;
    let last_physical = mapping
        .physical_start
        .checked_add(last_offset)
        .ok_or(PagingError::AddressOverflow)?;
    let first_indexes = page_table_indices(mapping.virtual_start)?;
    let last_indexes = page_table_indices(last_virtual)?;
    if ((mapping.virtual_start >> 47) & 1) != ((last_virtual >> 47) & 1) {
        return Err(PagingError::NonCanonicalVirtualAddress);
    }
    let _ = (first_indexes, last_indexes);
    encode_page(last_physical, mapping.writable, mapping.executable)?;
    Ok(last_virtual)
}

/// Return a safe upper bound for the number of 4 KiB tables needed.
///
/// The count includes the root table and every intermediate table touched by
/// each mapping. Shared intermediate tables across separate mappings may be
/// counted more than once; the result is therefore suitable for allocation
/// without requiring a heap-backed set.
pub fn required_table_capacity(mappings: &[PageMapping]) -> Result<usize, PagingError> {
    let mut capacity = 1usize;
    for mapping in mappings {
        let last_address = validate_mapping(mapping)?;
        for shift in [39_u32, 30, 21] {
            let first = mapping.virtual_start >> shift;
            let last = last_address >> shift;
            let count =
                usize::try_from(last - first + 1).map_err(|_| PagingError::AddressOverflow)?;
            capacity = capacity
                .checked_add(count)
                .ok_or(PagingError::AddressOverflow)?;
        }
    }
    Ok(capacity)
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
    for mapping in mappings {
        validate_mapping(mapping)?;
    }
    for table in tables.iter_mut() {
        table.fill(0);
    }

    let mut used = 1usize;
    for mapping in mappings {
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
    validate_page_table_topology(tables, table_physical_addresses, used)?;
    Ok(used)
}

/// Validate that every intermediate descriptor forms a unique tree inside the used pool.
pub fn validate_page_table_topology(
    tables: &[[u64; ENTRIES_PER_TABLE]],
    table_physical_addresses: &[u64],
    used_table_count: usize,
) -> Result<(), PagingError> {
    if used_table_count == 0
        || used_table_count > tables.len()
        || tables.len() != table_physical_addresses.len()
    {
        return Err(PagingError::InvalidTableTopology);
    }

    for (parent, table) in tables.iter().take(used_table_count).enumerate() {
        for entry in table {
            if entry & PRESENT == 0 || entry & (WRITABLE | NO_EXECUTE) != WRITABLE {
                continue;
            }
            if entry & !(PHYSICAL_ADDRESS_MASK | PRESENT | WRITABLE) != 0 {
                return Err(PagingError::InvalidTableTopology);
            }
            let child_address = entry & PHYSICAL_ADDRESS_MASK;
            let child = table_physical_addresses[..used_table_count]
                .iter()
                .position(|address| *address == child_address)
                .ok_or(PagingError::InvalidTableTopology)?;
            if child <= parent {
                return Err(PagingError::InvalidTableTopology);
            }
        }
    }

    for child_address in table_physical_addresses.iter().take(used_table_count).skip(1) {
        let mut references = 0usize;
        for table in tables.iter().take(used_table_count) {
            for entry in table {
                if entry & PRESENT != 0
                    && entry & PHYSICAL_ADDRESS_MASK == *child_address
                {
                    references = references
                        .checked_add(1)
                        .ok_or(PagingError::InvalidTableTopology)?;
                }
            }
        }
        if references != 1 {
            return Err(PagingError::InvalidTableTopology);
        }
    }
    Ok(())
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
    fn table_capacity_covers_all_intermediate_tables() {
        let base = 0xffff_ffff_8000_0000;
        let mappings = [
            PageMapping {
                virtual_start: base,
                physical_start: 0x20_0000,
                page_count: 513,
                writable: false,
                executable: true,
            },
            PageMapping {
                virtual_start: base + 0x20_1000,
                physical_start: 0x40_0000,
                page_count: 1,
                writable: true,
                executable: false,
            },
        ];
        let capacity = required_table_capacity(&mappings).unwrap();
        assert!(capacity >= 5);
        assert_eq!(
            required_table_capacity(&[PageMapping {
                page_count: 0,
                ..mappings[0]
            }]),
            Err(PagingError::AddressOverflow)
        );
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
    fn validates_mapping_before_sizing_or_clearing_tables() {
        let wx = PageMapping {
            virtual_start: 0xffff_ffff_8000_0000,
            physical_start: 0x20_0000,
            page_count: 1,
            writable: true,
            executable: true,
        };
        assert_eq!(
            required_table_capacity(&[wx]),
            Err(PagingError::WritableExecutable)
        );
        let overflow = PageMapping {
            physical_start: PHYSICAL_ADDRESS_MASK,
            page_count: 2,
            writable: false,
            executable: false,
            ..wx
        };
        assert_eq!(
            required_table_capacity(&[overflow]),
            Err(PagingError::PhysicalAddressOutOfRange)
        );

        let mut tables = [[u64::MAX; ENTRIES_PER_TABLE]; 4];
        let addresses = [0x1000, 0x2000, 0x3000, 0x4000];
        assert_eq!(
            build_page_tables(&mut tables, &addresses, &[wx]),
            Err(PagingError::WritableExecutable)
        );
        assert!(
            tables
                .iter()
                .all(|table| table.iter().all(|entry| *entry == u64::MAX))
        );
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
    #[test]
    fn rejects_page_table_descriptors_outside_the_used_tree() {
        let mut tables = [[0u64; ENTRIES_PER_TABLE]; 4];
        let addresses = [0x1000, 0x2000, 0x3000, 0x4000];
        let mapping = PageMapping {
            virtual_start: 0xffff_ffff_8000_0000,
            physical_start: 0x20_0000,
            page_count: 1,
            writable: false,
            executable: true,
        };
        assert_eq!(
            build_page_tables(&mut tables, &addresses, &[mapping]),
            Ok(4)
        );
        assert_eq!(validate_page_table_topology(&tables, &addresses, 4), Ok(()));

        let indexes = page_table_indices(mapping.virtual_start).unwrap();
        tables[0][indexes[0]] = 0x9000 | PRESENT | WRITABLE;
        assert_eq!(
            validate_page_table_topology(&tables, &addresses, 4),
            Err(PagingError::InvalidTableTopology)
        );
    }

    #[test]
    fn rejects_duplicate_and_unreachable_page_table_pages() {
        let mut tables = [[0u64; ENTRIES_PER_TABLE]; 4];
        let addresses = [0x1000, 0x2000, 0x3000, 0x4000];
        let mapping = PageMapping {
            virtual_start: 0xffff_ffff_8000_0000,
            physical_start: 0x20_0000,
            page_count: 1,
            writable: false,
            executable: true,
        };
        assert_eq!(
            build_page_tables(&mut tables, &addresses, &[mapping]),
            Ok(4)
        );
        let indexes = page_table_indices(mapping.virtual_start).unwrap();
        let pdpt = table_index(&addresses, tables[0][indexes[0]]);
        let pd = table_index(&addresses, tables[pdpt][indexes[1]]);
        tables[pdpt][indexes[1]] = addresses[3] | PRESENT | WRITABLE;
        assert_eq!(
            validate_page_table_topology(&tables, &addresses, 4),
            Err(PagingError::InvalidTableTopology)
        );
    }
}
