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

/// Errors returned by the fixed-capacity reservation manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationError {
    /// The requested range is empty or its end address overflows.
    InvalidRange,
    /// The reservation overlaps an existing reservation.
    Overlap,
    /// The caller-provided reservation buffer is full.
    CapacityExceeded,
    /// No reservation exactly matches the requested range.
    NotFound,
}

/// Allocation-free manager for physical ranges that must not be handed out.
///
/// Storage is supplied by the caller. Reservations are kept in insertion order;
/// overlapping entries are rejected, while adjacent entries remain distinct.
pub struct ReservationManager<'a> {
    entries: &'a mut [PhysicalRange],
    len: usize,
}

impl<'a> ReservationManager<'a> {
    /// Create an empty manager over caller-owned reservation storage.
    pub const fn new(entries: &'a mut [PhysicalRange]) -> Self {
        Self { entries, len: 0 }
    }

    /// Reserve a non-empty physical address range.
    pub fn reserve(&mut self, start: u64, length: u64) -> Result<PhysicalRange, ReservationError> {
        let range = PhysicalRange::new(start, length).ok_or(ReservationError::InvalidRange)?;
        self.reserve_range(range)?;
        Ok(range)
    }

    /// Insert an already validated physical range.
    pub fn reserve_range(&mut self, range: PhysicalRange) -> Result<(), ReservationError> {
        if range.length == 0 || range.start.checked_add(range.length).is_none() {
            return Err(ReservationError::InvalidRange);
        }
        if self.entries[..self.len]
            .iter()
            .any(|existing| existing.start < range.end() && range.start < existing.end())
        {
            return Err(ReservationError::Overlap);
        }
        if self.len == self.entries.len() {
            return Err(ReservationError::CapacityExceeded);
        }
        self.entries[self.len] = range;
        self.len += 1;
        Ok(())
    }

    /// Release a reservation only when its exact range is present.
    pub fn release(&mut self, range: PhysicalRange) -> Result<(), ReservationError> {
        let index = self.entries[..self.len]
            .iter()
            .position(|entry| *entry == range)
            .ok_or(ReservationError::NotFound)?;
        self.entries.copy_within(index + 1..self.len, index);
        self.len -= 1;
        Ok(())
    }

    /// Check whether any reservation intersects the supplied address range.
    pub fn overlaps(&self, range: PhysicalRange) -> bool {
        self.entries[..self.len]
            .iter()
            .any(|entry| entry.start < range.end() && range.start < entry.end())
    }

    /// Return the active reservations as a compact immutable slice.
    pub fn ranges(&self) -> &[PhysicalRange] {
        &self.entries[..self.len]
    }

    /// Number of active reservations.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the manager currently has no reservations.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum number of reservations this manager can hold.
    pub const fn capacity(&self) -> usize {
        self.entries.len()
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
    BitmapTooSmall {
        required_words: usize,
        provided_words: usize,
    },
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

        Ok(Self {
            regions,
            reservations,
            bitmap,
            frame_count,
        })
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
        if self
            .reservations
            .iter()
            .any(|range| range.overlaps_frame(frame.start, end))
        {
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
            if target >= start
                && target
                    .checked_add(FRAME_SIZE)
                    .is_some_and(|frame_end| frame_end <= end)
            {
                return Ok(index + ((target - start) / FRAME_SIZE) as usize);
            }
            let frames = ((end - start) / FRAME_SIZE) as usize;
            index = index
                .checked_add(frames)
                .ok_or(BitmapAllocatorError::AddressOverflow)?;
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
        total = total
            .checked_add(frames)
            .ok_or(BitmapAllocatorError::AddressOverflow)?;
    }
    Ok(total)
}

fn usable_frame_bounds(region: &MemoryRegion) -> Result<(u64, u64), BitmapAllocatorError> {
    let region_end = region
        .physical_start
        .checked_add(region.length)
        .ok_or(BitmapAllocatorError::AddressOverflow)?;
    let start =
        align_up(region.physical_start, FRAME_SIZE).ok_or(BitmapAllocatorError::AddressOverflow)?;
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
    fn reservation_manager_tracks_ranges_and_releases_exact_entries() {
        let empty = PhysicalRange::new(0, 1).unwrap();
        let mut storage = [empty; 2];
        let mut manager = ReservationManager::new(&mut storage);

        let first = manager.reserve(0x1000, 0x1000).unwrap();
        let second = manager.reserve(0x2000, 0x1000).unwrap();
        assert_eq!(manager.len(), 2);
        assert_eq!(manager.capacity(), 2);
        assert!(!manager.is_empty());
        assert_eq!(manager.ranges(), &[first, second]);
        assert!(manager.overlaps(PhysicalRange::new(0x1800, 0x100).unwrap()));
        assert!(!manager.overlaps(PhysicalRange::new(0x4000, 0x100).unwrap()));

        manager.release(first).unwrap();
        assert_eq!(manager.ranges(), &[second]);
        assert_eq!(manager.release(first), Err(ReservationError::NotFound));
        assert_eq!(manager.reserve(0x4000, 0x1000), PhysicalRange::new(0x4000, 0x1000).ok_or(ReservationError::InvalidRange));
        assert_eq!(manager.len(), 2);
    }

    #[test]
    fn reservation_manager_rejects_invalid_overlapping_and_excess_ranges() {
        let empty = PhysicalRange::new(0, 1).unwrap();
        let mut storage = [empty; 1];
        let mut manager = ReservationManager::new(&mut storage);

        assert_eq!(
            manager.reserve(0x1000, 0),
            Err(ReservationError::InvalidRange)
        );
        assert_eq!(
            manager.reserve(u64::MAX - 7, 8),
            Err(ReservationError::InvalidRange)
        );
        manager.reserve(0x4000, 0x1000).unwrap();
        assert_eq!(
            manager.reserve(0x4800, 0x1000),
            Err(ReservationError::Overlap)
        );
        assert_eq!(
            manager.reserve(0x6000, 0x1000),
            Err(ReservationError::CapacityExceeded)
        );
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn bitmap_allocator_compacts_usable_regions_and_reuses_freed_frames() {
        let map = [
            region(0x1000, 0x2000, memory_kind::RESERVED),
            region(0x4000, 0x2000, memory_kind::USABLE),
            region(0x8000, 0x1000, memory_kind::BOOT_INFO),
            region(0xa000, 0x2000, memory_kind::USABLE),
        ];
        let words = BitmapFrameAllocator::required_words(&map).unwrap();
        assert_eq!(words, 1);
        let mut bitmap = [0u64; 1];
        let mut allocator = BitmapFrameAllocator::new(&map, &[], &mut bitmap).unwrap();

        assert_eq!(allocator.frame_count(), 4);
        assert_eq!(allocator.free_count(), 4);
        let first = allocator.allocate_frame().unwrap();
        let second = allocator.allocate_frame().unwrap();
        assert_eq!(first.start(), 0x4000);
        assert_eq!(second.start(), 0x5000);
        allocator.free_frame(first).unwrap();
        assert_eq!(allocator.free_count(), 3);
        assert_eq!(allocator.allocate_frame().unwrap(), first);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0xa000);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0xb000);
        assert_eq!(allocator.allocate_frame(), None);
    }

    #[test]
    fn bitmap_allocator_keeps_reserved_frames_unavailable() {
        let map = [region(0x4000, 0x3000, memory_kind::USABLE)];
        let reservations = [PhysicalRange::new(0x5001, 1).unwrap()];
        let mut bitmap = [0u64; 1];
        let mut allocator = BitmapFrameAllocator::new(&map, &reservations, &mut bitmap).unwrap();

        assert_eq!(allocator.free_count(), 2);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x4000);
        assert_eq!(allocator.allocate_frame().unwrap().start(), 0x6000);
        assert_eq!(allocator.allocate_frame(), None);
        assert_eq!(
            allocator.free_frame(PhysFrame { start: 0x5000 }),
            Err(BitmapAllocatorError::FrameNotUsable)
        );
    }

    #[test]
    fn bitmap_allocator_rejects_double_free_and_non_usable_frames() {
        let map = [
            region(0x4000, 0x2000, memory_kind::USABLE),
            region(0x8000, 0x1000, memory_kind::RESERVED),
        ];
        let mut bitmap = [0u64; 1];
        let mut allocator = BitmapFrameAllocator::new(&map, &[], &mut bitmap).unwrap();
        let frame = allocator.allocate_frame().unwrap();

        allocator.free_frame(frame).unwrap();
        assert_eq!(
            allocator.free_frame(frame),
            Err(BitmapAllocatorError::DoubleFree)
        );
        assert_eq!(
            allocator.free_frame(PhysFrame { start: 0x8000 }),
            Err(BitmapAllocatorError::FrameNotUsable)
        );
        assert_eq!(
            allocator.free_frame(PhysFrame { start: 0x4001 }),
            Err(BitmapAllocatorError::FrameNotUsable)
        );
    }

    #[test]
    fn bitmap_allocator_rejects_insufficient_metadata() {
        let map = [region(0x4000, 0x4_1000, memory_kind::USABLE)];
        let mut bitmap = [0u64; 1];
        assert_eq!(
            BitmapFrameAllocator::new(&map, &[], &mut bitmap).err(),
            Some(BitmapAllocatorError::BitmapTooSmall {
                required_words: 2,
                provided_words: 1,
            })
        );
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
