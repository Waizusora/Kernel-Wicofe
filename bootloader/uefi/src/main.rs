#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;
use wicofe_bootloader_common::{
    BOOT_INFO_MAGIC, BOOT_INFO_VERSION, BootInfo, MemoryRegion, architecture, validate_boot_info,
};
#[cfg(target_arch = "aarch64")]
use wicofe_bootloader_elf::EM_AARCH64;
#[cfg(target_arch = "x86_64")]
use wicofe_bootloader_elf::EM_X86_64;
use wicofe_bootloader_elf::{ElfImage, LoadSegment};
#[cfg(target_arch = "aarch64")]
use wicofe_bootloader_uefi::convert_kernel_page_mappings;
#[cfg(target_arch = "x86_64")]
use wicofe_bootloader_uefi::convert_kernel_page_mappings;
use wicofe_bootloader_uefi::{
    KERNEL_PHYSICAL_ALIGNMENT, KernelPageMapping, UEFI_PAGE_SIZE, UefiMemoryDescriptor,
    decode_uefi_memory_descriptors, kernel_allocation_layout, page_table_allocation_layout,
    plan_kernel_page_mappings, translate_uefi_memory_map,
};

type Status = usize;
type Handle = *mut c_void;

const EFI_ERROR_BIT: usize = 1usize << (usize::BITS - 1);
const EFI_BUFFER_TOO_SMALL: Status = EFI_ERROR_BIT | 5;
const EFI_INVALID_PARAMETER: Status = EFI_ERROR_BIT | 2;
const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;
const MAX_MEMORY_MAP_ATTEMPTS: usize = 4;
const EFI_LOADER_DATA: u32 = 2;
const EFI_FILE_MODE_READ: u64 = 1;
const MAX_KERNEL_SIZE: usize = 64 * 1024 * 1024;
const KERNEL_PATH: &[u16] = &[
    0x005c, 0x0045, 0x0046, 0x0049, 0x005c, 0x0057, 0x0049, 0x0043, 0x004f, 0x0046, 0x0045, 0x005c,
    0x004b, 0x0045, 0x0052, 0x004e, 0x0045, 0x004c, 0x002e, 0x0045, 0x004c, 0x0046, 0,
];

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}
const LOADED_IMAGE_GUID: Guid = Guid {
    data1: 0x5b1b31a1,
    data2: 0x9562,
    data3: 0x11d2,
    data4: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
const SIMPLE_FS_GUID: Guid = Guid {
    data1: 0x964e5b22,
    data2: 0x6459,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
const FILE_INFO_GUID: Guid = Guid {
    data1: 0x09576e92,
    data2: 0x6d3f,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

#[repr(C)]
struct TableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}
#[repr(C)]
struct SimpleTextOutputProtocol {
    reset: usize,
    output_string: Option<unsafe extern "efiapi" fn(*mut Self, *const u16) -> Status>,
    remaining_functions: [usize; 8],
}
#[repr(C)]
struct SystemTable {
    header: TableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: Handle,
    console_in: *mut c_void,
    console_out_handle: Handle,
    console_out: *mut SimpleTextOutputProtocol,
    standard_error_handle: Handle,
    standard_error: *mut SimpleTextOutputProtocol,
    runtime_services: *mut c_void,
    boot_services: *mut BootServices,
    number_of_table_entries: usize,
    configuration_table: *mut c_void,
}

type HandleProtocolFn = unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status;
type AllocatePagesFn = unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status;
type FreePagesFn = unsafe extern "efiapi" fn(u64, usize) -> Status;
type GetMemoryMapFn =
    unsafe extern "efiapi" fn(*mut usize, *mut c_void, *mut usize, *mut usize, *mut u32) -> Status;
type AllocatePoolFn = unsafe extern "efiapi" fn(u32, usize, *mut *mut c_void) -> Status;
type FreePoolFn = unsafe extern "efiapi" fn(*mut c_void) -> Status;
#[repr(C)]
struct BootServices {
    header: TableHeader,
    before_pages: [usize; 2],
    allocate_pages: Option<AllocatePagesFn>,
    free_pages: Option<FreePagesFn>,
    get_memory_map: Option<GetMemoryMapFn>,
    allocate_pool: Option<AllocatePoolFn>,
    free_pool: Option<FreePoolFn>,
    between_pool_and_handle: [usize; 9],
    handle_protocol: Option<HandleProtocolFn>,
}

#[repr(C)]
struct LoadedImageProtocol {
    revision: u32,
    parent_handle: Handle,
    system_table: *mut SystemTable,
    device_handle: Handle,
    file_path: *mut c_void,
    reserved: *mut c_void,
    load_options_size: u32,
    load_options: *mut c_void,
    image_base: *mut c_void,
    image_size: u64,
    image_code_type: u32,
    image_data_type: u32,
    unload: usize,
}
type OpenVolumeFn =
    unsafe extern "efiapi" fn(*mut SimpleFileSystemProtocol, *mut *mut FileProtocol) -> Status;
#[repr(C)]
struct SimpleFileSystemProtocol {
    revision: u64,
    open_volume: Option<OpenVolumeFn>,
}
type FileOpenFn = unsafe extern "efiapi" fn(
    *mut FileProtocol,
    *mut *mut FileProtocol,
    *const u16,
    u64,
    u64,
) -> Status;
type FileCloseFn = unsafe extern "efiapi" fn(*mut FileProtocol) -> Status;
type FileReadFn = unsafe extern "efiapi" fn(*mut FileProtocol, *mut usize, *mut c_void) -> Status;
type FileGetInfoFn =
    unsafe extern "efiapi" fn(*mut FileProtocol, *const Guid, *mut usize, *mut c_void) -> Status;
#[repr(C)]
struct FileProtocol {
    revision: u64,
    open: Option<FileOpenFn>,
    close: Option<FileCloseFn>,
    delete: usize,
    read: Option<FileReadFn>,
    write: usize,
    get_position: usize,
    set_position: usize,
    get_info: Option<FileGetInfoFn>,
    remaining_functions: [usize; 7],
}

fn is_error(status: Status) -> bool {
    status & EFI_ERROR_BIT != 0
}

unsafe fn protocol<T>(
    services: &BootServices,
    handle: Handle,
    guid: &Guid,
) -> Result<*mut T, Status> {
    let function = services.handle_protocol.ok_or(EFI_INVALID_PARAMETER)?;
    let mut interface = core::ptr::null_mut();
    // SAFETY: caller supplies a firmware handle and a valid protocol GUID.
    let status = unsafe { function(handle, guid, &mut interface) };
    if is_error(status) || interface.is_null() {
        return Err(if is_error(status) {
            status
        } else {
            EFI_INVALID_PARAMETER
        });
    }
    Ok(interface.cast())
}
unsafe fn allocate_pool(services: &BootServices, size: usize) -> Result<*mut c_void, Status> {
    let function = services.allocate_pool.ok_or(EFI_INVALID_PARAMETER)?;
    let mut buffer = core::ptr::null_mut();
    // SAFETY: firmware AllocatePool receives a valid output pointer.
    let status = unsafe { function(EFI_LOADER_DATA, size, &mut buffer) };
    if is_error(status) || buffer.is_null() {
        return Err(if is_error(status) {
            status
        } else {
            EFI_INVALID_PARAMETER
        });
    }
    Ok(buffer)
}
unsafe fn free_pool(services: &BootServices, buffer: *mut c_void) {
    if !buffer.is_null() {
        if let Some(function) = services.free_pool {
            // SAFETY: buffer was allocated by this boot-services table.
            let _ = unsafe { function(buffer) };
        }
    }
}

/// Persistent storage for the canonical memory map and its boot metadata.
///
/// Scratch allocations are intentionally retained: freeing or allocating pool
/// memory after the final GetMemoryMap call would invalidate that snapshot.
struct PreparedBootInfo {
    info: *mut BootInfo,
    regions: *mut MemoryRegion,
    region_count: usize,
    _raw_map: *mut c_void,
    _descriptors: *mut UefiMemoryDescriptor,
}

/// Allocate all storage first, then take and translate the final map without
/// making any further firmware allocation calls.
unsafe fn prepare_boot_info(
    services: &BootServices,
    kernel: LoadedKernel,
) -> Result<PreparedBootInfo, Status> {
    let get_memory_map = services.get_memory_map.ok_or(EFI_INVALID_PARAMETER)?;
    let mut required_size = 0usize;
    let mut map_key = 0usize;
    let mut descriptor_size = 0usize;
    let mut descriptor_version = 0u32;

    // SAFETY: null buffer and zero size request the required map capacity.
    let status = unsafe {
        get_memory_map(
            &mut required_size,
            core::ptr::null_mut(),
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };
    if status != EFI_BUFFER_TOO_SMALL
        || required_size == 0
        || descriptor_size < 40
        || descriptor_size % 8 != 0
        || descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION
    {
        return Err(if is_error(status) {
            status
        } else {
            EFI_INVALID_PARAMETER
        });
    }

    let mut capacity = required_size
        .checked_add(
            descriptor_size
                .checked_mul(8)
                .ok_or(EFI_INVALID_PARAMETER)?,
        )
        .ok_or(EFI_INVALID_PARAMETER)?;

    for _ in 0..MAX_MEMORY_MAP_ATTEMPTS {
        let descriptor_capacity = capacity
            .checked_add(descriptor_size - 1)
            .ok_or(EFI_INVALID_PARAMETER)?
            / descriptor_size;
        let raw_map = unsafe { allocate_pool(services, capacity)? };
        let descriptors = match unsafe {
            allocate_array::<UefiMemoryDescriptor>(services, descriptor_capacity)
        } {
            Ok(pointer) => pointer,
            Err(error) => {
                unsafe { free_pool(services, raw_map) };
                return Err(error);
            }
        };
        let regions = match unsafe { allocate_array::<MemoryRegion>(services, descriptor_capacity) }
        {
            Ok(pointer) => pointer,
            Err(error) => {
                unsafe { free_pool(services, descriptors.cast()) };
                unsafe { free_pool(services, raw_map) };
                return Err(error);
            }
        };
        let info = match unsafe { allocate_array::<BootInfo>(services, 1) } {
            Ok(pointer) => pointer,
            Err(error) => {
                unsafe { free_pool(services, regions.cast()) };
                unsafe { free_pool(services, descriptors.cast()) };
                unsafe { free_pool(services, raw_map) };
                return Err(error);
            }
        };

        let mut map_size = capacity;
        map_key = 0;
        descriptor_size = 0;
        descriptor_version = 0;
        // SAFETY: raw_map spans capacity writable bytes; output pointers are valid.
        let status = unsafe {
            get_memory_map(
                &mut map_size,
                raw_map,
                &mut map_key,
                &mut descriptor_size,
                &mut descriptor_version,
            )
        };

        if status == EFI_BUFFER_TOO_SMALL {
            unsafe { free_pool(services, info.cast()) };
            unsafe { free_pool(services, regions.cast()) };
            unsafe { free_pool(services, descriptors.cast()) };
            unsafe { free_pool(services, raw_map) };
            if descriptor_size < 40
                || descriptor_size % 8 != 0
                || descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION
            {
                return Err(EFI_INVALID_PARAMETER);
            }
            capacity = map_size
                .checked_add(
                    descriptor_size
                        .checked_mul(8)
                        .ok_or(EFI_INVALID_PARAMETER)?,
                )
                .ok_or(EFI_INVALID_PARAMETER)?;
            continue;
        }
        if is_error(status) {
            unsafe { free_pool(services, info.cast()) };
            unsafe { free_pool(services, regions.cast()) };
            unsafe { free_pool(services, descriptors.cast()) };
            unsafe { free_pool(services, raw_map) };
            return Err(status);
        }
        if map_size == 0
            || map_size > capacity
            || descriptor_size < 40
            || descriptor_size % 8 != 0
            || descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION
            || map_size % descriptor_size != 0
        {
            unsafe { free_pool(services, info.cast()) };
            unsafe { free_pool(services, regions.cast()) };
            unsafe { free_pool(services, descriptors.cast()) };
            unsafe { free_pool(services, raw_map) };
            return Err(EFI_INVALID_PARAMETER);
        }

        let descriptor_count = map_size / descriptor_size;
        // SAFETY: firmware wrote map_size bytes into raw_map.
        let raw_bytes = unsafe { core::slice::from_raw_parts(raw_map.cast::<u8>(), map_size) };
        // SAFETY: descriptors and regions each have descriptor_capacity aligned entries.
        let decoded = unsafe { core::slice::from_raw_parts_mut(descriptors, descriptor_capacity) };
        let decoded_count =
            match decode_uefi_memory_descriptors(raw_bytes, descriptor_size, decoded) {
                Ok(count) if count == descriptor_count => count,
                _ => {
                    unsafe { free_pool(services, info.cast()) };
                    unsafe { free_pool(services, regions.cast()) };
                    unsafe { free_pool(services, descriptors.cast()) };
                    unsafe { free_pool(services, raw_map) };
                    return Err(EFI_INVALID_PARAMETER);
                }
            };
        // SAFETY: only decoded_count descriptor slots were initialized.
        let decoded = unsafe { core::slice::from_raw_parts(descriptors, decoded_count) };
        // SAFETY: regions has descriptor_capacity writable entries.
        let output = unsafe { core::slice::from_raw_parts_mut(regions, descriptor_capacity) };
        let region_count = match translate_uefi_memory_map(decoded, output) {
            Ok(count) if count != 0 => count,
            _ => {
                unsafe { free_pool(services, info.cast()) };
                unsafe { free_pool(services, regions.cast()) };
                unsafe { free_pool(services, descriptors.cast()) };
                unsafe { free_pool(services, raw_map) };
                return Err(EFI_INVALID_PARAMETER);
            }
        };

        let boot_info = BootInfo {
            magic: BOOT_INFO_MAGIC,
            version: BOOT_INFO_VERSION,
            struct_size: core::mem::size_of::<BootInfo>() as u32,
            architecture: if cfg!(target_arch = "x86_64") {
                architecture::X86_64
            } else {
                architecture::AARCH64
            },
            flags: 0,
            memory_map_address: regions as u64,
            memory_map_entries: region_count as u64,
            memory_map_entry_size: core::mem::size_of::<MemoryRegion>() as u32,
            reserved: 0,
            kernel_physical_base: kernel.physical_base,
            kernel_virtual_base: kernel.virtual_base,
            kernel_image_size: kernel.image_size,
            kernel_entry: kernel.entry,
            acpi_rsdp_address: 0,
        };
        // SAFETY: info is aligned storage for one BootInfo value.
        unsafe { info.write(boot_info) };
        // SAFETY: map slice covers exactly the translated, initialized entries.
        let map = unsafe { core::slice::from_raw_parts(regions, region_count) };
        if validate_boot_info(&boot_info, map).is_err() {
            unsafe { free_pool(services, info.cast()) };
            unsafe { free_pool(services, regions.cast()) };
            unsafe { free_pool(services, descriptors.cast()) };
            unsafe { free_pool(services, raw_map) };
            return Err(EFI_INVALID_PARAMETER);
        }

        return Ok(PreparedBootInfo {
            info,
            regions,
            region_count,
            _raw_map: raw_map,
            _descriptors: descriptors,
        });
    }

    Err(EFI_BUFFER_TOO_SMALL)
}

unsafe fn read_kernel(
    services: &BootServices,
    image_handle: Handle,
) -> Result<(*mut u8, usize), Status> {
    // SAFETY: protocol handle and GUID are supplied by UEFI.
    let loaded =
        unsafe { protocol::<LoadedImageProtocol>(services, image_handle, &LOADED_IMAGE_GUID)? };
    // SAFETY: loaded-image protocol was returned successfully.
    let device = unsafe { (*loaded).device_handle };
    if device.is_null() {
        return Err(EFI_INVALID_PARAMETER);
    }
    // SAFETY: device handle belongs to the loaded image.
    let filesystem =
        unsafe { protocol::<SimpleFileSystemProtocol>(services, device, &SIMPLE_FS_GUID)? };
    // SAFETY: protocol pointer is valid for the lifetime of boot services.
    let open_volume = unsafe { (*filesystem).open_volume }.ok_or(EFI_INVALID_PARAMETER)?;
    let mut root = core::ptr::null_mut();
    // SAFETY: open_volume writes the root directory handle on success.
    let status = unsafe { open_volume(filesystem, &mut root) };
    if is_error(status) || root.is_null() {
        return Err(if is_error(status) {
            status
        } else {
            EFI_INVALID_PARAMETER
        });
    }

    let result = (|| {
        // SAFETY: root is an open EFI_FILE_PROTOCOL handle.
        let open = unsafe { (*root).open }.ok_or(EFI_INVALID_PARAMETER)?;
        let mut file = core::ptr::null_mut();
        // SAFETY: path is NUL-terminated UTF-16 and output pointer is valid.
        let status = unsafe { open(root, &mut file, KERNEL_PATH.as_ptr(), EFI_FILE_MODE_READ, 0) };
        if is_error(status) || file.is_null() {
            return Err(if is_error(status) {
                status
            } else {
                EFI_INVALID_PARAMETER
            });
        }

        let file_result = (|| {
            // SAFETY: file is an open EFI_FILE_PROTOCOL handle.
            let get_info = unsafe { (*file).get_info }.ok_or(EFI_INVALID_PARAMETER)?;
            let mut info_size = 0usize;
            // SAFETY: null buffer requests the required EFI_FILE_INFO size.
            let status =
                unsafe { get_info(file, &FILE_INFO_GUID, &mut info_size, core::ptr::null_mut()) };
            if status != EFI_BUFFER_TOO_SMALL || info_size < 16 {
                return Err(if is_error(status) {
                    status
                } else {
                    EFI_INVALID_PARAMETER
                });
            }
            // SAFETY: metadata buffer is allocated from the UEFI pool.
            let info = unsafe { allocate_pool(services, info_size)? };
            // SAFETY: info points to info_size writable bytes.
            let status = unsafe { get_info(file, &FILE_INFO_GUID, &mut info_size, info) };
            if is_error(status) {
                // SAFETY: info was allocated above.
                unsafe { free_pool(services, info) };
                return Err(status);
            }
            // EFI_FILE_INFO.FileSize is the u64 at byte offset 8.
            // SAFETY: successful GetInfo returned at least the validated 16-byte structure.
            let file_size_u64 =
                unsafe { core::ptr::read_unaligned((info as *const u8).add(8).cast::<u64>()) };
            // SAFETY: release metadata before allocating the image buffer.
            unsafe { free_pool(services, info) };

            let file_size = usize::try_from(file_size_u64).map_err(|_| EFI_INVALID_PARAMETER)?;
            if file_size == 0 || file_size > MAX_KERNEL_SIZE {
                return Err(EFI_INVALID_PARAMETER);
            }
            let read = unsafe { (*file).read }.ok_or(EFI_INVALID_PARAMETER)?;
            // SAFETY: bounded file size; AllocatePool returns writable storage.
            let image = unsafe { allocate_pool(services, file_size)? };
            let mut read_size = file_size;
            // SAFETY: image points to file_size writable bytes.
            let status = unsafe { read(file, &mut read_size, image) };
            if is_error(status) || read_size != file_size {
                // SAFETY: image was allocated above.
                unsafe { free_pool(services, image) };
                return Err(if is_error(status) {
                    status
                } else {
                    EFI_INVALID_PARAMETER
                });
            }
            Ok((image.cast::<u8>(), file_size))
        })();

        // SAFETY: file was successfully opened.
        if let Some(close) = unsafe { (*file).close } {
            let _ = unsafe { close(file) };
        }
        file_result
    })();

    // SAFETY: root was successfully opened.
    if let Some(close) = unsafe { (*root).close } {
        let _ = unsafe { close(root) };
    }
    result
}

#[derive(Clone, Copy)]
struct LoadedKernel {
    physical_base: u64,
    virtual_base: u64,
    image_size: u64,
    entry: u64,
}

unsafe fn free_pages(services: &BootServices, address: u64, pages: usize) {
    if pages != 0 {
        if let Some(function) = services.free_pages {
            // SAFETY: the range is a page-aligned subrange of our AllocatePages result.
            let _ = unsafe { function(address, pages) };
        }
    }
}

unsafe fn load_segments(
    services: &BootServices,
    file_image: &[u8],
    parsed: &ElfImage<'_>,
) -> Result<LoadedKernel, Status> {
    let layout = kernel_allocation_layout(parsed.image_size()).ok_or(EFI_INVALID_PARAMETER)?;
    let allocate = services.allocate_pages.ok_or(EFI_INVALID_PARAMETER)?;
    let release = services.free_pages.ok_or(EFI_INVALID_PARAMETER)?;
    let mut raw_base = 0_u64;
    // AllocateAnyPages, EfiLoaderData.
    // SAFETY: AllocatePages receives a valid output pointer and bounded page count.
    let status = unsafe { allocate(0, EFI_LOADER_DATA, layout.allocation_pages, &mut raw_base) };
    if is_error(status) {
        return Err(status);
    }
    if raw_base == 0 {
        // SAFETY: release the allocation returned by firmware.
        let _ = unsafe { release(raw_base, layout.allocation_pages) };
        return Err(EFI_INVALID_PARAMETER);
    }

    let allocation_end = match raw_base.checked_add(layout.allocation_size) {
        Some(value) => value,
        None => {
            // SAFETY: release the complete allocation returned by firmware.
            let _ = unsafe { release(raw_base, layout.allocation_pages) };
            return Err(EFI_INVALID_PARAMETER);
        }
    };
    let aligned_base = match raw_base
        .checked_add(KERNEL_PHYSICAL_ALIGNMENT - 1)
        .map(|value| value & !(KERNEL_PHYSICAL_ALIGNMENT - 1))
    {
        Some(value) => value,
        None => {
            // SAFETY: release the complete allocation returned by firmware.
            let _ = unsafe { release(raw_base, layout.allocation_pages) };
            return Err(EFI_INVALID_PARAMETER);
        }
    };
    let image_end = match aligned_base.checked_add(layout.rounded_image_size) {
        Some(value) if value <= allocation_end => value,
        _ => {
            // SAFETY: release the complete allocation returned by firmware.
            let _ = unsafe { release(raw_base, layout.allocation_pages) };
            return Err(EFI_INVALID_PARAMETER);
        }
    };
    let image_address = match usize::try_from(aligned_base) {
        Ok(value) => value,
        Err(_) => {
            // SAFETY: release the complete allocation returned by firmware.
            let _ = unsafe { release(raw_base, layout.allocation_pages) };
            return Err(EFI_INVALID_PARAMETER);
        }
    };
    let image_length = match usize::try_from(layout.rounded_image_size) {
        Ok(value) => value,
        Err(_) => {
            // SAFETY: release the complete allocation returned by firmware.
            let _ = unsafe { release(raw_base, layout.allocation_pages) };
            return Err(EFI_INVALID_PARAMETER);
        }
    };

    let destination = image_address as *mut u8;
    // SAFETY: destination spans the rounded image size inside our allocated pages.
    unsafe { core::ptr::write_bytes(destination, 0, image_length) };

    let populate_result = (|| {
        for index in 0..parsed.program_header_count() {
            let Some(segment) = parsed.load_segment(index) else {
                continue;
            };
            copy_segment(
                file_image,
                destination,
                image_length,
                parsed.image_base(),
                segment,
            )?;
        }
        Ok(())
    })();

    if let Err(status) = populate_result {
        // SAFETY: no subranges have been released yet; free the full allocation.
        let _ = unsafe { release(raw_base, layout.allocation_pages) };
        return Err(status);
    }

    let prefix_pages = ((aligned_base - raw_base) / UEFI_PAGE_SIZE) as usize;
    let suffix_pages = ((allocation_end - image_end) / UEFI_PAGE_SIZE) as usize;
    // SAFETY: these page-aligned ranges lie outside the copied kernel image.
    unsafe { free_pages(services, raw_base, prefix_pages) };
    unsafe { free_pages(services, image_end, suffix_pages) };

    Ok(LoadedKernel {
        physical_base: aligned_base,
        virtual_base: parsed.image_base(),
        image_size: parsed.image_size(),
        entry: parsed.entry(),
    })
}

#[derive(Clone, Copy)]
struct PreparedPageTables {
    root_physical_address: u64,
    used_table_count: usize,
}

unsafe fn allocate_array<T>(services: &BootServices, count: usize) -> Result<*mut T, Status> {
    let size = core::mem::size_of::<T>()
        .checked_mul(count)
        .filter(|size| *size != 0)
        .ok_or(EFI_INVALID_PARAMETER)?;
    // SAFETY: the requested byte size is nonzero and checked for overflow.
    let buffer = unsafe { allocate_pool(services, size)? };
    if (buffer as usize) % core::mem::align_of::<T>() != 0 {
        // SAFETY: buffer was returned by this boot-services table.
        unsafe { free_pool(services, buffer) };
        return Err(EFI_INVALID_PARAMETER);
    }
    Ok(buffer.cast())
}

unsafe fn allocate_page_table_pool(
    services: &BootServices,
    table_count: usize,
) -> Result<u64, Status> {
    let layout = page_table_allocation_layout(table_count).ok_or(EFI_INVALID_PARAMETER)?;
    let allocate = services.allocate_pages.ok_or(EFI_INVALID_PARAMETER)?;
    let release = services.free_pages.ok_or(EFI_INVALID_PARAMETER)?;
    let mut base = 0_u64;
    // SAFETY: AllocatePages receives a checked page count and valid output pointer.
    let status = unsafe { allocate(0, EFI_LOADER_DATA, layout.allocation_pages, &mut base) };
    if is_error(status) {
        return Err(status);
    }
    if base == 0
        || base % UEFI_PAGE_SIZE != 0
        || base.checked_add(layout.allocation_size).is_none()
        || usize::try_from(base).is_err()
    {
        // SAFETY: release the complete allocation returned by firmware.
        let _ = unsafe { release(base, layout.allocation_pages) };
        return Err(EFI_INVALID_PARAMETER);
    }
    Ok(base)
}

#[cfg(target_arch = "x86_64")]
unsafe fn build_architecture_page_tables(
    services: &BootServices,
    mappings: &[KernelPageMapping],
) -> Result<PreparedPageTables, Status> {
    let architecture_mappings = unsafe {
        allocate_array::<wicofe_kernel_x86_64::paging::PageMapping>(services, mappings.len())?
    };
    let result = (|| {
        // SAFETY: architecture_mappings contains mappings.len() aligned writable entries.
        let output =
            unsafe { core::slice::from_raw_parts_mut(architecture_mappings, mappings.len()) };
        convert_kernel_page_mappings(mappings, output).map_err(|_| EFI_INVALID_PARAMETER)?;
        let converted =
            unsafe { core::slice::from_raw_parts(architecture_mappings, mappings.len()) };
        let table_count = wicofe_kernel_x86_64::paging::required_table_capacity(converted)
            .map_err(|_| EFI_INVALID_PARAMETER)?;
        // SAFETY: the pool is retained on success and released on any builder failure.
        let table_base = unsafe { allocate_page_table_pool(services, table_count)? };
        let build_result = (|| {
            let addresses = unsafe { allocate_array::<u64>(services, table_count)? };
            let address_result = (|| {
                for index in 0..table_count {
                    let offset = u64::try_from(index)
                        .ok()
                        .and_then(|value| value.checked_mul(UEFI_PAGE_SIZE))
                        .ok_or(EFI_INVALID_PARAMETER)?;
                    let address = table_base
                        .checked_add(offset)
                        .ok_or(EFI_INVALID_PARAMETER)?;
                    // SAFETY: addresses points to table_count initialized allocation slots.
                    unsafe { addresses.add(index).write(address) };
                }
                let table_pointer = usize::try_from(table_base)
                    .map_err(|_| EFI_INVALID_PARAMETER)?
                    as *mut [u64; 512];
                if (table_pointer as usize) % core::mem::align_of::<[u64; 512]>() != 0 {
                    return Err(EFI_INVALID_PARAMETER);
                }
                // UEFI page allocations are dedicated to this pool; explicitly clear every
                // table page so all unused descriptors are guaranteed invalid.
                // SAFETY: table_pointer spans table_count writable, page-aligned pages.
                unsafe { core::ptr::write_bytes(table_pointer, 0, table_count) };
                // SAFETY: UEFI allocated table_count contiguous, page-aligned pages.
                let tables = unsafe { core::slice::from_raw_parts_mut(table_pointer, table_count) };
                // SAFETY: addresses contains the physical address of each table page.
                let physical_addresses =
                    unsafe { core::slice::from_raw_parts(addresses, table_count) };
                let used = wicofe_kernel_x86_64::paging::build_page_tables(
                    tables,
                    physical_addresses,
                    converted,
                )
                .map_err(|_| EFI_INVALID_PARAMETER)?;
                Ok(PreparedPageTables {
                    root_physical_address: table_base,
                    used_table_count: used,
                })
            })();
            // SAFETY: addresses was allocated above.
            unsafe { free_pool(services, addresses.cast()) };
            address_result
        })();
        if build_result.is_err() {
            let pages = table_count;
            // SAFETY: release the page-table allocation after failed construction.
            unsafe { free_pages(services, table_base, pages) };
        }
        build_result
    })();
    // SAFETY: scratch architecture mappings are no longer needed after building.
    unsafe { free_pool(services, architecture_mappings.cast()) };
    result
}

#[cfg(target_arch = "aarch64")]
unsafe fn build_architecture_page_tables(
    services: &BootServices,
    mappings: &[KernelPageMapping],
) -> Result<PreparedPageTables, Status> {
    let architecture_mappings = unsafe {
        allocate_array::<wicofe_kernel_aarch64::paging::PageMapping>(services, mappings.len())?
    };
    let result = (|| {
        // Attribute index 0 is a provisional normal-memory slot. WBL does not
        // program MAIR_EL1 here, so these tables must remain inactive.
        // SAFETY: architecture_mappings contains mappings.len() aligned writable entries.
        let output =
            unsafe { core::slice::from_raw_parts_mut(architecture_mappings, mappings.len()) };
        convert_kernel_page_mappings(mappings, 0, output).map_err(|_| EFI_INVALID_PARAMETER)?;
        let converted =
            unsafe { core::slice::from_raw_parts(architecture_mappings, mappings.len()) };
        let table_count = wicofe_kernel_aarch64::paging::required_table_capacity(converted)
            .map_err(|_| EFI_INVALID_PARAMETER)?;
        // SAFETY: the pool is retained on success and released on any builder failure.
        let table_base = unsafe { allocate_page_table_pool(services, table_count)? };
        let build_result = (|| {
            let addresses = unsafe { allocate_array::<u64>(services, table_count)? };
            let address_result = (|| {
                for index in 0..table_count {
                    let offset = u64::try_from(index)
                        .ok()
                        .and_then(|value| value.checked_mul(UEFI_PAGE_SIZE))
                        .ok_or(EFI_INVALID_PARAMETER)?;
                    let address = table_base
                        .checked_add(offset)
                        .ok_or(EFI_INVALID_PARAMETER)?;
                    // SAFETY: addresses points to table_count initialized allocation slots.
                    unsafe { addresses.add(index).write(address) };
                }
                let table_pointer = usize::try_from(table_base)
                    .map_err(|_| EFI_INVALID_PARAMETER)?
                    as *mut [u64; 512];
                if (table_pointer as usize) % core::mem::align_of::<[u64; 512]>() != 0 {
                    return Err(EFI_INVALID_PARAMETER);
                }
                // UEFI page allocations are dedicated to this pool; explicitly clear every
                // table page so all unused descriptors are guaranteed invalid.
                // SAFETY: table_pointer spans table_count writable, page-aligned pages.
                unsafe { core::ptr::write_bytes(table_pointer, 0, table_count) };
                // SAFETY: UEFI allocated table_count contiguous, page-aligned pages.
                let tables = unsafe { core::slice::from_raw_parts_mut(table_pointer, table_count) };
                // SAFETY: addresses contains the physical address of each table page.
                let physical_addresses =
                    unsafe { core::slice::from_raw_parts(addresses, table_count) };
                let used = wicofe_kernel_aarch64::paging::build_page_tables(
                    tables,
                    physical_addresses,
                    converted,
                )
                .map_err(|_| EFI_INVALID_PARAMETER)?;
                Ok(PreparedPageTables {
                    root_physical_address: table_base,
                    used_table_count: used,
                })
            })();
            // SAFETY: addresses was allocated above.
            unsafe { free_pool(services, addresses.cast()) };
            address_result
        })();
        if build_result.is_err() {
            let pages = table_count;
            // SAFETY: release the page-table allocation after failed construction.
            unsafe { free_pages(services, table_base, pages) };
        }
        build_result
    })();
    // SAFETY: scratch architecture mappings are no longer needed after building.
    unsafe { free_pool(services, architecture_mappings.cast()) };
    result
}

unsafe fn prepare_page_tables(
    services: &BootServices,
    parsed: &ElfImage<'_>,
    kernel: LoadedKernel,
) -> Result<PreparedPageTables, Status> {
    let segment_capacity = usize::from(parsed.program_header_count());
    let segments = unsafe { allocate_array::<LoadSegment>(services, segment_capacity)? };
    let result = (|| {
        let mut segment_count = 0usize;
        for index in 0..parsed.program_header_count() {
            if let Some(segment) = parsed.load_segment(index) {
                // SAFETY: segments has capacity for every program header.
                unsafe { segments.add(segment_count).write(segment) };
                segment_count += 1;
            }
        }
        if segment_count == 0 {
            return Err(EFI_INVALID_PARAMETER);
        }
        // SAFETY: the first segment_count entries were initialized above.
        let segment_slice = unsafe { core::slice::from_raw_parts(segments, segment_count) };
        let mappings = unsafe { allocate_array::<KernelPageMapping>(services, segment_count)? };
        let mapping_result = (|| {
            // SAFETY: mappings has segment_count aligned writable entries.
            let output = unsafe { core::slice::from_raw_parts_mut(mappings, segment_count) };
            let mapping_count = plan_kernel_page_mappings(
                kernel.physical_base,
                kernel.virtual_base,
                segment_slice,
                output,
            )
            .map_err(|_| EFI_INVALID_PARAMETER)?;
            // SAFETY: only the first mapping_count entries were initialized.
            let mapping_slice = unsafe { core::slice::from_raw_parts(mappings, mapping_count) };
            unsafe { build_architecture_page_tables(services, mapping_slice) }
        })();
        // SAFETY: mappings was allocated above.
        unsafe { free_pool(services, mappings.cast()) };
        mapping_result
    })();
    // SAFETY: segments was allocated above.
    unsafe { free_pool(services, segments.cast()) };
    result
}

fn copy_segment(
    file_image: &[u8],
    destination: *mut u8,
    destination_length: usize,
    image_base: u64,
    segment: LoadSegment,
) -> Result<(), Status> {
    let source_start = usize::try_from(segment.file_offset).map_err(|_| EFI_INVALID_PARAMETER)?;
    let source_length = usize::try_from(segment.file_size).map_err(|_| EFI_INVALID_PARAMETER)?;
    let destination_start = usize::try_from(
        segment
            .virtual_address
            .checked_sub(image_base)
            .ok_or(EFI_INVALID_PARAMETER)?,
    )
    .map_err(|_| EFI_INVALID_PARAMETER)?;
    let destination_size =
        usize::try_from(segment.memory_size).map_err(|_| EFI_INVALID_PARAMETER)?;
    let source_end = source_start
        .checked_add(source_length)
        .ok_or(EFI_INVALID_PARAMETER)?;
    let destination_end = destination_start
        .checked_add(destination_size)
        .ok_or(EFI_INVALID_PARAMETER)?;
    if source_end > file_image.len() || destination_end > destination_length {
        return Err(EFI_INVALID_PARAMETER);
    }
    // The destination was zeroed before copying; the remainder of p_memsz is BSS.
    // SAFETY: parser and explicit bounds checks validated both non-overlapping ranges.
    unsafe {
        core::ptr::copy_nonoverlapping(
            file_image.as_ptr().add(source_start),
            destination.add(destination_start),
            source_length,
        )
    };
    Ok(())
}

fn print_message(system_table: *mut SystemTable, message: &'static [u16]) -> Status {
    if system_table.is_null() {
        return EFI_INVALID_PARAMETER;
    }
    // SAFETY: UEFI supplies a valid system table to the image entry point.
    let console = unsafe { (*system_table).console_out };
    if console.is_null() {
        return EFI_INVALID_PARAMETER;
    }
    // SAFETY: console pointer belongs to the supplied system table.
    let output = unsafe { (*console).output_string };
    let Some(output) = output else {
        return EFI_INVALID_PARAMETER;
    };
    // SAFETY: message is NUL-terminated UTF-16 and remains valid for the call.
    unsafe { output(console, message.as_ptr()) }
}

const START_MESSAGE: &[u16] = &[
    0x0057, 0x0069, 0x0063, 0x006f, 0x0066, 0x0065, 0x0020, 0x0042, 0x006f, 0x006f, 0x0074, 0x006c,
    0x006f, 0x0061, 0x0064, 0x0065, 0x0072, 0x003a, 0x0020, 0x0055, 0x0045, 0x0046, 0x0049, 0x0020,
    0x0065, 0x006e, 0x0074, 0x0072, 0x0079, 0x0020, 0x0072, 0x0065, 0x0061, 0x0063, 0x0068, 0x0065,
    0x0064, 0x002e, 0x000d, 0x000a, 0,
];
const VALID_MESSAGE: &[u16] = &[
    0x004b, 0x0045, 0x0052, 0x004e, 0x0045, 0x004c, 0x002e, 0x0045, 0x004c, 0x0046, 0x0020, 0x0072,
    0x0065, 0x0061, 0x0064, 0x0020, 0x0061, 0x006e, 0x0064, 0x0020, 0x0045, 0x004c, 0x0046, 0x0036,
    0x0034, 0x0020, 0x0076, 0x0061, 0x006c, 0x0069, 0x0064, 0x0061, 0x0074, 0x0065, 0x0064, 0x002e,
    0x000d, 0x000a, 0,
];
const LOADED_MESSAGE: &[u16] = &[
    0x0050, 0x0054, 0x005f, 0x004c, 0x004f, 0x0041, 0x0044, 0x0020, 0x0073, 0x0075, 0x0063, 0x0063,
    0x0065, 0x0073, 0x0073, 0x0066, 0x0075, 0x006c, 0x003b, 0x0020, 0x006e, 0x006f, 0x0020, 0x0068,
    0x0061, 0x006e, 0x0064, 0x006f, 0x0066, 0x0066, 0x0020, 0x0079, 0x0065, 0x0074, 0x002e, 0x000d,
    0x000a, 0,
];
const ERROR_MESSAGE: &[u16] = &[
    0x0057, 0x0042, 0x004c, 0x003a, 0x0020, 0x006b, 0x0065, 0x0072, 0x006e, 0x0065, 0x006c, 0x0020,
    0x006c, 0x006f, 0x0061, 0x0064, 0x0020, 0x006f, 0x0072, 0x0020, 0x0045, 0x004c, 0x0046, 0x0020,
    0x0076, 0x0061, 0x006c, 0x0069, 0x0064, 0x0061, 0x0074, 0x0069, 0x006f, 0x006e, 0x0020, 0x0066,
    0x0061, 0x0069, 0x006c, 0x0065, 0x0064, 0x002e, 0x000d, 0x000a, 0,
];

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    let _ = print_message(system_table, START_MESSAGE);
    if system_table.is_null() {
        return EFI_INVALID_PARAMETER;
    }
    // SAFETY: system table was checked and is supplied by UEFI.
    let boot_services = unsafe { (*system_table).boot_services };
    if boot_services.is_null() {
        return EFI_INVALID_PARAMETER;
    }
    // SAFETY: boot-services table is supplied by firmware for this image lifetime.
    let loaded = unsafe { read_kernel(&*boot_services, image_handle) };
    let (image, image_size) = match loaded {
        Ok(value) => value,
        Err(status) => {
            let _ = print_message(system_table, ERROR_MESSAGE);
            return status;
        }
    };

    #[cfg(target_arch = "x86_64")]
    let expected_machine = EM_X86_64;
    #[cfg(target_arch = "aarch64")]
    let expected_machine = EM_AARCH64;

    // SAFETY: image is a live buffer of image_size bytes allocated by UEFI.
    let loaded_kernel = {
        // SAFETY: image is a live buffer of image_size bytes allocated by UEFI.
        let file_image = unsafe { core::slice::from_raw_parts(image, image_size) };
        match ElfImage::parse(file_image, expected_machine) {
            Ok(parsed) => {
                // SAFETY: parsed references file_image, and boot services are still active.
                match unsafe { load_segments(&*boot_services, file_image, &parsed) } {
                    Ok(kernel) => {
                        // SAFETY: firmware services remain active and the loaded image is valid.
                        match unsafe { prepare_page_tables(&*boot_services, &parsed, kernel) } {
                            Ok(tables) => Ok((kernel, tables)),
                            Err(status) => {
                                let pages = kernel
                                    .image_size
                                    .checked_add(UEFI_PAGE_SIZE - 1)
                                    .and_then(|size| usize::try_from(size / UEFI_PAGE_SIZE).ok())
                                    .unwrap_or(0);
                                // SAFETY: load_segments retained this exact aligned image range.
                                unsafe { free_pages(&*boot_services, kernel.physical_base, pages) };
                                Err(status)
                            }
                        }
                    }
                    Err(status) => Err(status),
                }
            }
            Err(_) => Err(EFI_INVALID_PARAMETER),
        }
    };
    // SAFETY: release the temporary source file after parsing and copying finish.
    unsafe { free_pool(&*boot_services, image.cast()) };

    match loaded_kernel {
        Ok((kernel, tables)) => {
            // SAFETY: boot services remain active. The prepared allocations are
            // retained and no firmware allocations occur after the final map call.
            let prepared = match unsafe { prepare_boot_info(&*boot_services, kernel) } {
                Ok(value) => value,
                Err(status) => {
                    let _ = print_message(system_table, ERROR_MESSAGE);
                    return status;
                }
            };
            let _kernel_handoff_metadata = (
                prepared.info as u64,
                prepared.regions as u64,
                prepared.region_count,
                kernel.physical_base,
                kernel.virtual_base,
                kernel.image_size,
                kernel.entry,
                tables.root_physical_address,
                tables.used_table_count,
            );
            print_message(system_table, LOADED_MESSAGE)
        }
        Err(_) => {
            let _ = print_message(system_table, ERROR_MESSAGE);
            EFI_INVALID_PARAMETER
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
