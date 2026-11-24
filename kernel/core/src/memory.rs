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

/// Errors returned while initializing or using the bitmap allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitmapAllocatorError {
    /// The caller-provided bitmap does not contain enough words.
    BitmapTooSmall { required_words: usize, provided_words: usize },
    /// A memory-region boundary or aggregate frame count overflowed.
    AddressOverflow,
    /// A reservation is empty or its end address overflows.
    InvalidReservation,
    /// The frame is not wholly contained in a usable region.
    FrameNotUsable,
    /// The frame is already free and therefore cannot be freed again.
    DoubleFree,
}

/// A compact bitmap allocator spanning all usable regions in the memory map.
///
/// Bitmap bit 1 means allocated/unavailable; bit 0 means free. Bits are indexed
/// densely across usable frames only, so holes and reserved map entries consume
/// no bitmap space. The caller owns the backing bitmap storage.
pub struct BitmapFrameAllocator<'a> {
    regions: &'a [MemoryRegion],
    reservations: &'a [PhysicalRange],
    bitmap: &'a mut [u64],
    frame_count: usize,
}

impl<'a> BitmapFrameAllocator<'a> {
    /// Calculate the number of bitmap words required for the supplied map.
    pub fn required_words(regions: &[MemoryRegion]) -> Result<usize, BitmapAllocatorError> {
        let frames = usable_frame_count(regions)?;
        frames
            .checked_add(63)
            .map(|rounded| rounded / 64)
            .ok_or(BitmapAllocatorError::AddressOverflow)
    }

    /// Initialize a bitmap over usable frames, excluding explicit reservations.
    ///
    /// The bitmap is initialized in-place. Extra words are set to all ones so
    /// out-of-range bits can never be allocated.
    pub fn new(
        regions: &'a [MemoryRegion],
        reservations: &'a [PhysicalRange],
        bitmap: &'a mut [u64],
    ) -> Result<Self, BitmapAllocatorError> {
        for range in reservations {
            if range.length == 0 || range.start.checked_add(range.length).is_none() {
                return Err(BitmapAllocatorError::InvalidReservation);
            }
        }

        let frame_count = usable_frame_count(regions)?;
        let required_words = frame_count
            .checked_add(63)
            .ok_or(BitmapAllocatorError::AddressOverflow)?
            / 64;
        if bitmap.len() < required_words {
            return Err(BitmapAllocatorError::BitmapTooSmall {
                required_words,
                provided_words: bitmap.len(),
            });
        }

        bitmap.fill(u64::MAX);
        let mut index = 0usize;
        for region in regions {
            if region.kind != memory_kind::USABLE {
                continue;
            }
            let (mut address, end) = usable_frame_bounds(region)?;
            while address < end {
                let frame_end = address
                    .checked_add(FRAME_SIZE)
                    .ok_or(BitmapAllocatorError::AddressOverflow)?;
                let reserved = reservations
                    .iter()
                    .any(|range| range.overlaps_frame(address, frame_end));
                if !reserved {
                    bitmap[index / 64] &= !(1u64 << (index % 64));
                }
                index = index
                    .checked_add(1)
                    .ok_or(BitmapAllocatorError::AddressOverflow)?;
                address = frame_end;
            }
        }

        Ok(Self { regions, reservations, bitmap, frame_count })
    }

    /// Allocate the first free physical frame.
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        for word_index in 0..self.bitmap.len() {
            let free_bits = !self.bitmap[word_index];
            if free_bits == 0 {
                continue;
            }
            let bit = free_bits.trailing_zeros() as usize;
            let index = word_index.checked_mul(64)?.checked_add(bit)?;
            if index >= self.frame_count {
                return None;
            }
            let frame = self.frame_at_index(index)?;
            self.bitmap[word_index] |= 1u64 << bit;
            return Some(frame);
        }
        None
    }

    /// Return a previously allocated frame to the free pool.
    ///
    /// Reserved ranges are never freeable, even if a caller supplies a frame
    /// address that overlaps one. Double-free and non-usable addresses fail.
    pub fn free_frame(&mut self, frame: PhysFrame) -> Result<(), BitmapAllocatorError> {
        if frame.start % FRAME_SIZE != 0 {
            return Err(BitmapAllocatorError::FrameNotUsable);
        }
        let end = frame
            .start
            .checked_add(FRAME_SIZE)
            .ok_or(BitmapAllocatorError::AddressOverflow)?;
        if self.reservations.iter().any(|range| range.overlaps_frame(frame.start, end)) {
            return Err(BitmapAllocatorError::FrameNotUsable);
        }

        let index = self.index_of_frame(frame.start)?;
        let word = index / 64;
        let mask = 1u64 << (index % 64);
        if self.bitmap[word] & mask == 0 {
            return Err(BitmapAllocatorError::DoubleFree);
        }
        self.bitmap[word] &= !mask;
        Ok(())
    }

    /// Number of usable frames represented by this bitmap.
    pub const fn frame_count(&self) -> usize {
        self.frame_count
    }

    /// Number of currently free frames.
    pub fn free_count(&self) -> usize {
        self.bitmap
            .iter()
            .enumerate()
            .map(|(word_index, word)| {
                let remaining = self.frame_count.saturating_sub(word_index * 64).min(64);
                ((!word).count_ones() as usize).min(remaining)
            })
            .sum()
    }

    fn frame_at_index(&self, target: usize) -> Option<PhysFrame> {
        let mut index = 0usize;
        for region in self.regions {
            if region.kind != memory_kind::USABLE {
                continue;
            }
            let (mut address, end) = usable_frame_bounds(region).ok()?;
            while address < end {
                if index == target {
                    return Some(PhysFrame { start: address });
                }
                index = index.checked_add(1)?;
                address = address.checked_add(FRAME_SIZE)?;
            }
        }
        None
    }

    fn index_of_frame(&self, target: u64) -> Result<usize, BitmapAllocatorError> {
        let mut index = 0usize;
        for region in self.regions {
            if region.kind != memory_kind::USABLE {
                continue;
            }
            let (start, end) = usable_frame_bounds(region)?;
            if target >= start && target.checked_add(FRAME_SIZE).is_some_and(|frame_end| frame_end <= end) {
                return Ok(index + ((target - start) / FRAME_SIZE) as usize);
            }
            let frames = ((end - start) / FRAME_SIZE) as usize;
            index = index.checked_add(frames).ok_or(BitmapAllocatorError::AddressOverflow)?;
        }
        Err(BitmapAllocatorError::FrameNotUsable)
    }
}

fn usable_frame_count(regions: &[MemoryRegion]) -> Result<usize, BitmapAllocatorError> {
    let mut total = 0usize;
    for region in regions {
        if region.kind != memory_kind::USABLE {
            continue;
        }
        let (start, end) = usable_frame_bounds(region)?;
        let frames = usize::try_from((end - start) / FRAME_SIZE)
            .map_err(|_| BitmapAllocatorError::AddressOverflow)?;
        total = total.checked_add(frames).ok_or(BitmapAllocatorError::AddressOverflow)?;
    }
    Ok(total)
}

fn usable_frame_bounds(region: &MemoryRegion) -> Result<(u64, u64), BitmapAllocatorError> {
    let region_end = region
        .physical_start
        .checked_add(region.length)
        .ok_or(BitmapAllocatorError::AddressOverflow)?;
    let start = align_up(region.physical_start, FRAME_SIZE)
        .ok_or(BitmapAllocatorError::AddressOverflow)?;
    let end = region_end & !(FRAME_SIZE - 1);
    Ok((start.min(end), end))
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
