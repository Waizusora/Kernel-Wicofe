//! Early physical-frame allocation over the validated WBL memory map.
//!
//! This is a monotonic bootstrap allocator: it returns 4 KiB frames only from
//! USABLE regions and never frees or coalesces frames. The caller must first
//! validate BootInfo and the complete memory map, and must ensure that the
//! map excludes every live kernel, loader, page-table, and handoff allocation.

use wicofe_bootloader_common::{MemoryRegion, memory_kind};

/// Base page size used by ABI v2.
pub const FRAME_SIZE: u64 = 4096;

/// A physical 4 KiB frame base address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysFrame {
    start: u64,
}

impl PhysFrame {
    /// Return the physical base address of this frame.
    pub const fn start(self) -> u64 {
        self.start
    }
}

/// A simple, allocation-free bump allocator for early physical memory.
pub struct FrameAllocator<'a> {
    regions: &'a [MemoryRegion],
    region_index: usize,
    next_address: Option<u64>,
}

impl<'a> FrameAllocator<'a> {
    /// Create an allocator over a previously validated canonical memory map.
    pub const fn new(regions: &'a [MemoryRegion]) -> Self {
        Self {
            regions,
            region_index: 0,
            next_address: None,
        }
    }

    /// Allocate the next available 4 KiB frame from a USABLE region.
    ///
    /// Returns `None` when all usable regions are exhausted. This allocator
    /// deliberately has no free operation; reclamation and concurrency belong
    /// to later memory-management milestones.
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        while self.region_index < self.regions.len() {
            let region = &self.regions[self.region_index];
            if region.kind != memory_kind::USABLE {
                self.region_index += 1;
                self.next_address = None;
                continue;
            }

            let end = region.physical_start.checked_add(region.length)?;
            let address = match self.next_address {
                Some(address) => address,
                None => {
                    let aligned = align_up(region.physical_start, FRAME_SIZE)?;
                    self.next_address = Some(aligned);
                    aligned
                }
            };

            if address.checked_add(FRAME_SIZE)? <= end {
                self.next_address = address.checked_add(FRAME_SIZE);
                return Some(PhysFrame { start: address });
            }

            self.region_index += 1;
            self.next_address = None;
        }

        None
    }
}

const fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment - 1;
    match value.checked_add(mask) {
        Some(sum) => Some(sum & !mask),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicofe_bootloader_common::memory_kind;

    fn region(start: u64, length: u64, kind: u32) -> MemoryRegion {
        MemoryRegion {
            physical_start: start,
            length,
            kind,
            attributes: 0,
        }
    }

    #[test]
    fn allocates_only_from_usable_regions() {
        let map = [
            region(0x1000, 0x2000, memory_kind::RESERVED),
            region(0x4000, 0x3000, memory_kind::USABLE),
        ];
        let mut allocator = FrameAllocator::new(&map);

        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x4000);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x5000);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x6000);
        assert_eq!(allocator.allocate_frame(), None);
    }

    #[test]
    fn advances_to_the_next_usable_region() {
        let map = [
            region(0x1000, 0x1000, memory_kind::USABLE),
            region(0x2000, 0x3000, memory_kind::BOOT_INFO),
            region(0x8000, 0x2000, memory_kind::USABLE),
        ];
        let mut allocator = FrameAllocator::new(&map);

        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x1000);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x8000);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x9000);
        assert_eq!(allocator.allocate_frame(), None);
    }

    #[test]
    fn empty_map_has_no_frames() {
        let mut allocator = FrameAllocator::new(&[]);
        assert_eq!(allocator.allocate_frame(), None);
    }

    #[test]
    fn returns_page_aligned_frame_addresses() {
        let map = [region(0x4000, 0x3000, memory_kind::USABLE)];
        let mut allocator = FrameAllocator::new(&map);

        while let Some(frame) = allocator.allocate_frame() {
            assert_eq!(frame.start() % FRAME_SIZE, 0);
        }
    }
}
