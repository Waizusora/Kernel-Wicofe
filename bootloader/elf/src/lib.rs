#![no_std]

//! Bounds-checked ELF64 loader validation for WBL.
//!
//! This crate parses an in-memory kernel image without allocation. It does not
//! allocate physical memory, copy segments, or establish page tables.

pub const ELF64_HEADER_SIZE: usize = 64;
pub const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
pub const MAX_PROGRAM_HEADERS: u16 = 128;
pub const PAGE_SIZE: u64 = 4096;
pub const MAX_SEGMENT_ALIGNMENT: u64 = 2 * 1024 * 1024;

pub const ET_EXEC: u16 = 2;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const X86_64_KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;
pub const AARCH64_KERNEL_BASE: u64 = 0xffff_0000_0000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    TruncatedHeader,
    InvalidMagic,
    UnsupportedClass,
    UnsupportedByteOrder,
    UnsupportedIdentVersion,
    UnsupportedElfType,
    UnsupportedMachine,
    InvalidHeaderSize,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderCount,
    ProgramHeaderTableOutOfBounds,
    InvalidLoadSegment,
    FileRangeOutOfBounds,
    AddressOverflow,
    InvalidSegmentAlignment,
    SegmentOutsideKernelImage,
    OverlappingLoadSegments,
    WritableExecutableSegment,
    MissingLoadSegment,
    InvalidEntryPoint,
    InvalidKernelBase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: u32,
    pub alignment: u64,
}

impl LoadSegment {
    pub const fn is_readable(self) -> bool {
        self.flags & PF_R != 0
    }

    pub const fn is_writable(self) -> bool {
        self.flags & PF_W != 0
    }

    pub const fn is_executable(self) -> bool {
        self.flags & PF_X != 0
    }
}

/// Validated ELF image metadata. The original image bytes remain borrowed.
pub struct ElfImage<'a> {
    bytes: &'a [u8],
    machine: u16,
    entry: u64,
    image_base: u64,
    image_size: u64,
    program_header_offset: usize,
    program_header_count: u16,
}

impl<'a> ElfImage<'a> {
    pub fn parse(bytes: &'a [u8], expected_machine: u16) -> Result<Self, ElfError> {
        if bytes.len() < ELF64_HEADER_SIZE {
            return Err(ElfError::TruncatedHeader);
        }
        if bytes.get(0..4) != Some(b"\x7fELF") {
            return Err(ElfError::InvalidMagic);
        }
        if bytes[4] != 2 {
            return Err(ElfError::UnsupportedClass);
        }
        if bytes[5] != 1 {
            return Err(ElfError::UnsupportedByteOrder);
        }
        if bytes[6] != 1 {
            return Err(ElfError::UnsupportedIdentVersion);
        }

        let elf_type = read_u16(bytes, 16).ok_or(ElfError::TruncatedHeader)?;
        let machine = read_u16(bytes, 18).ok_or(ElfError::TruncatedHeader)?;
        let version = read_u32(bytes, 20).ok_or(ElfError::TruncatedHeader)?;
        let entry = read_u64(bytes, 24).ok_or(ElfError::TruncatedHeader)?;
        let phoff = read_u64(bytes, 32).ok_or(ElfError::TruncatedHeader)?;
        let ehsize = read_u16(bytes, 52).ok_or(ElfError::TruncatedHeader)?;
        let phentsize = read_u16(bytes, 54).ok_or(ElfError::TruncatedHeader)?;
        let phnum = read_u16(bytes, 56).ok_or(ElfError::TruncatedHeader)?;

        if elf_type != ET_EXEC {
            return Err(ElfError::UnsupportedElfType);
        }
        if version != 1 {
            return Err(ElfError::UnsupportedIdentVersion);
        }
        if machine != expected_machine || (machine != EM_X86_64 && machine != EM_AARCH64) {
            return Err(ElfError::UnsupportedMachine);
        }
        if ehsize as usize != ELF64_HEADER_SIZE {
            return Err(ElfError::InvalidHeaderSize);
        }
        if phentsize as usize != ELF64_PROGRAM_HEADER_SIZE {
            return Err(ElfError::InvalidProgramHeaderSize);
        }
        if phnum == 0 || phnum > MAX_PROGRAM_HEADERS {
            return Err(ElfError::InvalidProgramHeaderCount);
        }

        let phoff = usize::try_from(phoff).map_err(|_| ElfError::ProgramHeaderTableOutOfBounds)?;
        let table_size = usize::from(phnum)
            .checked_mul(ELF64_PROGRAM_HEADER_SIZE)
            .ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
        let table_end = phoff
            .checked_add(table_size)
            .ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
        if phoff < ELF64_HEADER_SIZE || table_end > bytes.len() {
            return Err(ElfError::ProgramHeaderTableOutOfBounds);
        }

        let image_base = match machine {
            EM_X86_64 => X86_64_KERNEL_BASE,
            EM_AARCH64 => AARCH64_KERNEL_BASE,
            _ => return Err(ElfError::UnsupportedMachine),
        };

        let mut image_end = image_base;
        let mut load_count = 0_u16;
        let mut entry_is_executable = false;

        for index in 0..phnum {
            let segment = parse_program_header(bytes, phoff, index)?;
            if segment.is_none() {
                continue;
            }
            let segment = segment.ok_or(ElfError::InvalidLoadSegment)?;
            if load_count == 0 && segment.virtual_address != image_base {
                return Err(ElfError::SegmentOutsideKernelImage);
            }
            load_count += 1;

            if segment.memory_size == 0 || segment.file_size > segment.memory_size {
                return Err(ElfError::InvalidLoadSegment);
            }
            if segment.flags & !(PF_R | PF_W | PF_X) != 0 {
                return Err(ElfError::InvalidLoadSegment);
            }
            if segment.is_writable() && segment.is_executable() {
                return Err(ElfError::WritableExecutableSegment);
            }
            if segment.alignment > MAX_SEGMENT_ALIGNMENT
                || (segment.alignment > 1
                    && (!segment.alignment.is_power_of_two()
                        || segment.virtual_address % segment.alignment
                            != segment.file_offset % segment.alignment))
                || segment.virtual_address % PAGE_SIZE != segment.file_offset % PAGE_SIZE
            {
                return Err(ElfError::InvalidSegmentAlignment);
            }

            let file_end = segment
                .file_offset
                .checked_add(segment.file_size)
                .ok_or(ElfError::AddressOverflow)?;
            if file_end > bytes.len() as u64 {
                return Err(ElfError::FileRangeOutOfBounds);
            }
            let memory_end = segment
                .virtual_address
                .checked_add(segment.memory_size)
                .ok_or(ElfError::AddressOverflow)?;
            if segment.virtual_address < image_base || memory_end <= segment.virtual_address {
                return Err(ElfError::SegmentOutsideKernelImage);
            }
            if memory_end > image_end {
                image_end = memory_end;
            }
            if segment.is_executable() && entry >= segment.virtual_address && entry < memory_end {
                entry_is_executable = true;
            }

            for previous_index in 0..index {
                if let Some(previous) = parse_program_header(bytes, phoff, previous_index)? {
                    let previous_end = previous
                        .virtual_address
                        .checked_add(previous.memory_size)
                        .ok_or(ElfError::AddressOverflow)?;
                    if segment.virtual_address < previous_end
                        && previous.virtual_address < memory_end
                    {
                        return Err(ElfError::OverlappingLoadSegments);
                    }
                }
            }
        }

        if load_count == 0 {
            return Err(ElfError::MissingLoadSegment);
        }
        if entry < image_base || entry >= image_end || !entry_is_executable {
            return Err(ElfError::InvalidEntryPoint);
        }

        Ok(Self {
            bytes,
            machine,
            entry,
            image_base,
            image_size: image_end - image_base,
            program_header_offset: phoff,
            program_header_count: phnum,
        })
    }

    pub const fn machine(&self) -> u16 {
        self.machine
    }

    pub const fn entry(&self) -> u64 {
        self.entry
    }

    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    pub const fn image_size(&self) -> u64 {
        self.image_size
    }

    pub const fn program_header_count(&self) -> u16 {
        self.program_header_count
    }

    /// Return the loadable segment at the supplied program-header index.
    pub fn load_segment(&self, index: u16) -> Option<LoadSegment> {
        if index >= self.program_header_count {
            return None;
        }
        parse_program_header(self.bytes, self.program_header_offset, index)
            .ok()
            .flatten()
    }
}

fn parse_program_header(
    bytes: &[u8],
    table_offset: usize,
    index: u16,
) -> Result<Option<LoadSegment>, ElfError> {
    let offset = table_offset
        .checked_add(usize::from(index) * ELF64_PROGRAM_HEADER_SIZE)
        .ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
    let kind = read_u32(bytes, offset).ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
    if kind != PT_LOAD {
        return Ok(None);
    }
    let flags = read_u32(bytes, offset + 4).ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
    let file_offset = read_u64(bytes, offset + 8).ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
    let virtual_address =
        read_u64(bytes, offset + 16).ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
    let file_size = read_u64(bytes, offset + 32).ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
    let memory_size =
        read_u64(bytes, offset + 40).ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
    let alignment = read_u64(bytes, offset + 48).ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;

    Ok(Some(LoadSegment {
        file_offset,
        virtual_address,
        file_size,
        memory_size,
        flags,
        alignment,
    }))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE_SIZE: usize = 0x1004;

    fn image(machine: u16) -> [u8; FILE_SIZE] {
        let mut bytes = [0_u8; FILE_SIZE];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, ET_EXEC);
        put_u16(&mut bytes, 18, machine);
        put_u32(&mut bytes, 20, 1);
        let base = if machine == EM_X86_64 {
            X86_64_KERNEL_BASE
        } else {
            AARCH64_KERNEL_BASE
        };
        put_u64(&mut bytes, 24, base + 0x100);
        put_u64(&mut bytes, 32, ELF64_HEADER_SIZE as u64);
        put_u16(&mut bytes, 52, ELF64_HEADER_SIZE as u16);
        put_u16(&mut bytes, 54, ELF64_PROGRAM_HEADER_SIZE as u16);
        put_u16(&mut bytes, 56, 1);
        put_u32(&mut bytes, 64, PT_LOAD);
        put_u32(&mut bytes, 68, PF_R | PF_X);
        put_u64(&mut bytes, 72, 0x1000);
        put_u64(&mut bytes, 80, base);
        put_u64(&mut bytes, 96, 4);
        put_u64(&mut bytes, 104, 0x1000);
        put_u64(&mut bytes, 112, 0x1000);
        bytes[0x1000..0x1004].copy_from_slice(b"KERN");
        bytes
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_x86_64_et_exec() {
        let bytes = image(EM_X86_64);
        let parsed = ElfImage::parse(&bytes, EM_X86_64).expect("valid x86 image");
        assert_eq!(parsed.machine(), EM_X86_64);
        assert_eq!(parsed.image_base(), X86_64_KERNEL_BASE);
        assert_eq!(parsed.image_size(), 0x1000);
        assert_eq!(parsed.entry(), X86_64_KERNEL_BASE + 0x100);
        let segment = parsed.load_segment(0).expect("load segment");
        assert!(segment.is_executable());
        assert_eq!(segment.file_size, 4);
    }

    #[test]
    fn parses_aarch64_et_exec() {
        let bytes = image(EM_AARCH64);
        let parsed = ElfImage::parse(&bytes, EM_AARCH64).expect("valid arm image");
        assert_eq!(parsed.image_base(), AARCH64_KERNEL_BASE);
    }

    #[test]
    fn rejects_wrong_machine_and_non_executable_entry() {
        let bytes = image(EM_X86_64);
        assert_eq!(
            ElfImage::parse(&bytes, EM_AARCH64).err(),
            Some(ElfError::UnsupportedMachine)
        );

        let mut bytes = image(EM_X86_64);
        put_u64(&mut bytes, 24, X86_64_KERNEL_BASE + 0x2000);
        assert_eq!(
            ElfImage::parse(&bytes, EM_X86_64).err(),
            Some(ElfError::InvalidEntryPoint)
        );
    }

    #[test]
    fn rejects_file_bounds_and_writable_executable_segments() {
        let mut bytes = image(EM_X86_64);
        put_u64(&mut bytes, 96, 0x2000);
        put_u64(&mut bytes, 104, 0x3000);
        assert_eq!(
            ElfImage::parse(&bytes, EM_X86_64).err(),
            Some(ElfError::FileRangeOutOfBounds)
        );

        bytes = image(EM_X86_64);
        put_u32(&mut bytes, 68, PF_R | PF_W | PF_X);
        assert_eq!(
            ElfImage::parse(&bytes, EM_X86_64).err(),
            Some(ElfError::WritableExecutableSegment)
        );
    }

    #[test]
    fn rejects_truncated_program_header_table() {
        let mut bytes = image(EM_X86_64);
        put_u64(&mut bytes, 32, u64::MAX);
        assert_eq!(
            ElfImage::parse(&bytes, EM_X86_64).err(),
            Some(ElfError::ProgramHeaderTableOutOfBounds)
        );
    }
}
