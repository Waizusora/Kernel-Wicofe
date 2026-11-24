//! Early physical-frame allocation over the validated WBL memory map.
//!
//! This is a monotonic bootstrap allocator: it returns 4 KiB frames only from
//! USABLE regions and never frees or coalesces frames. Callers can additionally
//! exclude live physical allocations with explicit reservation ranges.

use wicofe_bootloader_common::{MemoryRegion, memory_kind};

/// Base page size used by ABI v2.
pub const FRAME_SIZE: u64 = 4096;

/// A half-open physical address range [start, end).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    start: u64,
    length: u64,
}

impl PhysicalRange {
    /// Construct a non-empty physical range, rejecting address overflow.
    pub const fn new(start: u64, length: u64) -> Option<Self> {
        if length == 0 || start.checked_add(length).is_none() {
            return None;
        }
        Some(Self { start, length })
    }

    /// Return the first byte in the range.
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Return the exclusive end address.
    pub const fn end(self) -> u64 {
        self.start + self.length
    }

    const fn overlaps_frame(self, frame_start: u64, frame_end: u64) -> bool {
        self.start < frame_end && frame_start < self.end()
    }
}

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
    reservations: &'a [PhysicalRange],
    region_index: usize,
    next_address: Option<u64>,
}

impl<'a> FrameAllocator<'a> {
    /// Create an allocator over a previously validated canonical memory map.
    pub const fn new(regions: &'a [MemoryRegion]) -> Self {
        Self {
            regions,
            reservations: &[],
            region_index: 0,
            next_address: None,
        }
    }

    /// Create an allocator while excluding additional physical ranges.
    ///
    /// Reservations may be unaligned and need not be sorted. Any 4 KiB frame
    /// intersecting at least one reservation is skipped in its entirety.
    /// Returns None if a reservation is empty or overflows the address space.
    pub const fn with_reservations(
        regions: &'a [MemoryRegion],
        reservations: &'a [PhysicalRange],
    ) -> Option<Self> {
        let mut index = 0;
        while index < reservations.len() {
            let range = reservations[index];
            if range.length == 0 || range.start.checked_add(range.length).is_none() {
                return None;
            }
            index += 1;
        }

        Some(Self {
            regions,
            reservations,
            region_index: 0,
            next_address: None,
        })
    }

    /// Allocate the next available 4 KiB frame from a USABLE region.
    ///
    /// Returns None when all usable regions are exhausted. This allocator
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
            let mut address = match self.next_address {
                Some(address) => address,
                None => {
                    let aligned = align_up(region.physical_start, FRAME_SIZE)?;
                    self.next_address = Some(aligned);
                    aligned
                }
            };

            loop {
                let frame_end = match address.checked_add(FRAME_SIZE) {
                    Some(frame_end) if frame_end <= end => frame_end,
                    _ => break,
                };

                let reserved = self
                    .reservations
                    .iter()
                    .any(|range| range.overlaps_frame(address, frame_end));

                self.next_address = Some(frame_end);
                if !reserved {
                    return Some(PhysFrame { start: address });
                }
                address = frame_end;
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

    #[test]
    fn skips_frames_intersecting_explicit_reservations() {
        let map = [region(0x4000, 0x5000, memory_kind::USABLE)];
        let reservations = [
            PhysicalRange::new(0x5000, 0x1000).unwrap(),
            PhysicalRange::new(0x7001, 1).unwrap(),
        ];
        let mut allocator = FrameAllocator::with_reservations(&map, &reservations).unwrap();

        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x4000);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x6000);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x8000);
        assert_eq!(allocator.allocate_frame(), None);
    }

    #[test]
    fn rejects_empty_or_overflowing_reservations() {
        assert_eq!(PhysicalRange::new(0x1000, 0), None);
        assert_eq!(PhysicalRange::new(u64::MAX - 7, 8), None);

        let map = [region(0x4000, 0x2000, memory_kind::USABLE)];
        let invalid = [PhysicalRange {
            start: u64::MAX - 7,
            length: 8,
        }];
        assert!(FrameAllocator::with_reservations(&map, &invalid).is_none());
    }

    #[test]
    fn reservation_may_be_unaligned_and_skip_whole_frame() {
        let map = [region(0x4000, 0x4000, memory_kind::USABLE)];
        let reservations = [PhysicalRange::new(0x4fff, 2).unwrap()];
        let mut allocator = FrameAllocator::with_reservations(&map, &reservations).unwrap();

        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x6000);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x7000);
        assert_eq!(allocator.allocate_frame(), None);
    }
}
