#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;
use wicofe_bootloader_common::{
    BOOT_INFO_MAGIC, BOOT_INFO_VERSION, BOOTSTRAP_STACK_LAYOUT, BootInfo, MemoryRegion,
    architecture, bootstrap_stack_top, memory_kind, validate_boot_info,
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
    IdentityMappingRange, KERNEL_PHYSICAL_ALIGNMENT, KernelPageMapping, MAP_READ, MAP_WRITE,
    MAX_PE_IDENTITY_MAPPINGS, UEFI_PAGE_SIZE, UefiMemoryDescriptor,
    coalesce_identity_mapping_ranges, coalesce_memory_reservations, decode_uefi_memory_descriptors,
    kernel_allocation_layout, page_table_allocation_layout, page_table_pool_capacity,
    plan_combined_page_mappings, plan_kernel_page_mappings, plan_pe_identity_mappings,
    translate_uefi_memory_map, validate_active_stack_mapping,
};

type Status = usize;
type Handle = *mut c_void;

const EFI_ERROR_BIT: usize = 1usize << (usize::BITS - 1);
const EFI_BUFFER_TOO_SMALL: Status = EFI_ERROR_BIT | 5;
const EFI_INVALID_PARAMETER: Status = EFI_ERROR_BIT | 2;
const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;
const MAX_MEMORY_MAP_ATTEMPTS: usize = 4;
const MEMORY_MAP_DESCRIPTOR_SLACK: usize = 32;
const EFI_LOADER_DATA: u32 = 2;
const EFI_BOOT_SERVICES_DATA: u32 = 4;
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
type ExitBootServicesFn = unsafe extern "efiapi" fn(Handle, usize) -> Status;
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
    // Reserved through UnloadImage; ExitBootServices is the next UEFI table slot.
    between_handle_and_exit_boot_services: [usize; 9],
    exit_boot_services: Option<ExitBootServicesFn>,
}

// UEFI Boot Services table layout: ExitBootServices is pointer slot 26
// (24-byte header plus 26 eight-byte function-pointer slots).
const _: () = assert!(core::mem::size_of::<usize>() == 8);
const _: () = assert!(core::mem::offset_of!(BootServices, exit_boot_services) == 24 + 26 * 8);

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
    raw_map: *mut c_void,
    raw_map_capacity: usize,
    descriptors: *mut UefiMemoryDescriptor,
    descriptor_capacity: usize,
    region_capacity: usize,
    descriptor_count: usize,
    kernel_reservation: wicofe_bootloader_uefi::MemoryReservation,
    map_key: usize,
}

/// Release retained BootInfo allocations when page-table preparation fails.
unsafe fn free_prepared_boot_info(services: &BootServices, prepared: PreparedBootInfo) {
    // SAFETY: each pointer is a distinct allocation retained by prepare_boot_info.
    unsafe { free_pool(services, prepared.info.cast()) };
    unsafe { free_pool(services, prepared.regions.cast()) };
    unsafe { free_pool(services, prepared.descriptors.cast()) };
    unsafe { free_pool(services, prepared.raw_map) };
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
                .checked_mul(MEMORY_MAP_DESCRIPTOR_SLACK)
                .ok_or(EFI_INVALID_PARAMETER)?,
        )
        .ok_or(EFI_INVALID_PARAMETER)?;

    for _ in 0..MAX_MEMORY_MAP_ATTEMPTS {
        let descriptor_capacity = capacity
            .checked_add(descriptor_size - 1)
            .ok_or(EFI_INVALID_PARAMETER)?
            / descriptor_size;
        let raw_map = unsafe { allocate_pool(services, capacity)? };
        // Seven independent reservations can each split one canonical region
        // into at most three pieces, requiring up to fourteen extra entries.
        let region_capacity = descriptor_capacity
            .checked_add(14)
            .ok_or(EFI_INVALID_PARAMETER)?;
        let descriptors = match unsafe {
            allocate_array::<UefiMemoryDescriptor>(services, descriptor_capacity)
        } {
            Ok(pointer) => pointer,
            Err(error) => {
                unsafe { free_pool(services, raw_map) };
                return Err(error);
            }
        };
        let regions = match unsafe { allocate_array::<MemoryRegion>(services, region_capacity) } {
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
                        .checked_mul(MEMORY_MAP_DESCRIPTOR_SLACK)
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
        // SAFETY: regions has region_capacity writable entries.
        let output = unsafe { core::slice::from_raw_parts_mut(regions, region_capacity) };
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
            raw_map,
            raw_map_capacity: capacity,
            descriptors,
            descriptor_capacity,
            region_capacity,
            descriptor_count,
            kernel_reservation: wicofe_bootloader_uefi::MemoryReservation {
                physical_start: kernel.physical_base,
                length: kernel.image_allocation_size,
                kind: memory_kind::KERNEL,
            },
            map_key,
        });
    }

    Err(EFI_BUFFER_TOO_SMALL)
}

/// Refresh the retained canonical map and capture a new firmware map key.
///
/// This function performs no allocation and makes no firmware calls after
/// GetMemoryMap. Call it immediately before ExitBootServices; any intervening
/// Boot Services call may invalidate the returned key.
unsafe fn refresh_prepared_boot_info(
    services: &BootServices,
    prepared: &mut PreparedBootInfo,
    tables: &PreparedPageTables,
) -> Result<(), Status> {
    let get_memory_map = services.get_memory_map.ok_or(EFI_INVALID_PARAMETER)?;
    let mut map_size = prepared.raw_map_capacity;
    let mut map_key = 0usize;
    let mut descriptor_size = 0usize;
    let mut descriptor_version = 0u32;

    // SAFETY: the retained raw map allocation spans raw_map_capacity bytes.
    let status = unsafe {
        get_memory_map(
            &mut map_size,
            prepared.raw_map,
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };
    if is_error(status) {
        return Err(status);
    }
    if map_size == 0
        || map_size > prepared.raw_map_capacity
        || descriptor_size < 40
        || descriptor_size % 8 != 0
        || descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION
        || map_size % descriptor_size != 0
    {
        return Err(EFI_INVALID_PARAMETER);
    }

    let descriptor_count = map_size / descriptor_size;
    if descriptor_count > prepared.descriptor_capacity {
        return Err(EFI_INVALID_PARAMETER);
    }

    // SAFETY: firmware wrote exactly map_size bytes into the retained buffer.
    let raw_bytes = unsafe { core::slice::from_raw_parts(prepared.raw_map.cast::<u8>(), map_size) };
    // SAFETY: descriptor storage has descriptor_capacity aligned entries.
    let descriptor_output = unsafe {
        core::slice::from_raw_parts_mut(prepared.descriptors, prepared.descriptor_capacity)
    };
    let decoded_count =
        decode_uefi_memory_descriptors(raw_bytes, descriptor_size, descriptor_output)
            .map_err(|_| EFI_INVALID_PARAMETER)?;
    if decoded_count != descriptor_count {
        return Err(EFI_INVALID_PARAMETER);
    }

    // Verify that allocations made after the original snapshot did not split
    // or otherwise change the descriptor containing the active firmware stack.
    // SAFETY: decoder initialized exactly descriptor_count entries.
    let decoded = unsafe { core::slice::from_raw_parts(prepared.descriptors, decoded_count) };
    validate_active_stack_mapping(
        decoded,
        tables.active_stack_mapping.physical_start,
        tables.active_stack_mapping.length,
        current_stack_pointer(),
    )
    .map_err(|_| EFI_INVALID_PARAMETER)?;

    // SAFETY: decoder initialized exactly descriptor_count entries.
    let decoded = unsafe { core::slice::from_raw_parts(prepared.descriptors, decoded_count) };
    // SAFETY: region storage has region_capacity writable entries.
    let region_output =
        unsafe { core::slice::from_raw_parts_mut(prepared.regions, prepared.region_capacity) };
    let translated_count = translate_uefi_memory_map(decoded, region_output)
        .ok()
        .filter(|count| *count != 0)
        .ok_or(EFI_INVALID_PARAMETER)?;

    let regions_size = prepared
        .region_capacity
        .checked_mul(core::mem::size_of::<MemoryRegion>())
        .and_then(|size| u64::try_from(size).ok())
        .ok_or(EFI_INVALID_PARAMETER)?;
    let descriptors_size = prepared
        .descriptor_capacity
        .checked_mul(core::mem::size_of::<UefiMemoryDescriptor>())
        .and_then(|size| u64::try_from(size).ok())
        .ok_or(EFI_INVALID_PARAMETER)?;
    let stack_length = u64::try_from(tables.bootstrap_stack_pages)
        .ok()
        .and_then(|pages| pages.checked_mul(UEFI_PAGE_SIZE))
        .ok_or(EFI_INVALID_PARAMETER)?;
    let table_length = u64::try_from(tables.table_pool_pages)
        .ok()
        .and_then(|pages| pages.checked_mul(UEFI_PAGE_SIZE))
        .ok_or(EFI_INVALID_PARAMETER)?;

    // Keep each retained allocation reserved independently. Pool allocations
    // can be far apart; reserving their min/max span would claim unrelated pages.
    let reservations = [
        prepared.kernel_reservation,
        wicofe_bootloader_uefi::MemoryReservation {
            physical_start: tables.root_physical_address,
            length: table_length,
            kind: memory_kind::BOOT_INFO,
        },
        wicofe_bootloader_uefi::MemoryReservation {
            physical_start: tables.bootstrap_stack_allocation_base,
            length: stack_length,
            kind: memory_kind::BOOT_INFO,
        },
        wicofe_bootloader_uefi::MemoryReservation {
            physical_start: prepared.info as u64,
            length: core::mem::size_of::<BootInfo>() as u64,
            kind: memory_kind::BOOT_INFO,
        },
        wicofe_bootloader_uefi::MemoryReservation {
            physical_start: prepared.regions as u64,
            length: regions_size,
            kind: memory_kind::BOOT_INFO,
        },
        wicofe_bootloader_uefi::MemoryReservation {
            physical_start: prepared.descriptors as u64,
            length: descriptors_size,
            kind: memory_kind::BOOT_INFO,
        },
        wicofe_bootloader_uefi::MemoryReservation {
            physical_start: prepared.raw_map as u64,
            length: u64::try_from(prepared.raw_map_capacity).map_err(|_| EFI_INVALID_PARAMETER)?,
            kind: memory_kind::BOOT_INFO,
        },
    ];
    let mut normalized_reservations = [wicofe_bootloader_uefi::MemoryReservation {
        physical_start: 0,
        length: 0,
        kind: memory_kind::BOOT_INFO,
    }; 7];
    let normalized_count =
        coalesce_memory_reservations(&reservations, &mut normalized_reservations)
            .map_err(|_| EFI_INVALID_PARAMETER)?;
    let region_count = wicofe_bootloader_uefi::apply_memory_reservations_in_place(
        region_output,
        translated_count,
        &normalized_reservations[..normalized_count],
    )
    .map_err(|_| EFI_INVALID_PARAMETER)?;

    // SAFETY: info points to the retained, aligned BootInfo allocation.
    let boot_info = unsafe { &mut *prepared.info };
    boot_info.memory_map_address = prepared.regions as u64;
    boot_info.memory_map_entries = region_count as u64;
    // SAFETY: the overlaid region slice contains region_count initialized entries.
    let map = unsafe { core::slice::from_raw_parts(prepared.regions, region_count) };
    validate_boot_info(boot_info, map).map_err(|_| EFI_INVALID_PARAMETER)?;

    prepared.region_count = region_count;
    prepared.descriptor_count = decoded_count;
    prepared.map_key = map_key;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn preflight_firmware_cpu_state() -> Result<(), Status> {
    // Capture the live firmware state, but do not apply the kernel-entry
    // validator: UEFI may legitimately enter with interrupts enabled.
    // SAFETY: UEFI x86_64 executes this image at CPL 0.
    let state = unsafe { wicofe_kernel_x86_64::capture_handoff_cpu_state() };
    // Capture GDTR and the live selectors before any future transition work.
    // This validates selector bounds only; WBL must install its own GDT before
    // transferring control and must not retain firmware descriptor pointers.
    // SAFETY: UEFI x86_64 executes this image at CPL 0.
    let descriptor_table =
        unsafe { wicofe_kernel_x86_64::capture_descriptor_table_state() };
    wicofe_kernel_x86_64::validate_descriptor_table_state(descriptor_table)
        .map_err(|_| EFI_INVALID_PARAMETER)?;
    const CR0_PG: u64 = 1 << 31;
    const CR4_PAE: u64 = 1 << 5;
    const EFER_LMA: u64 = 1 << 10;

    if state.cr0 & CR0_PG == 0
        || state.cr4 & CR4_PAE == 0
        || state.efer & EFER_LMA == 0
        || state.cs & 0b11 != 0
    {
        return Err(EFI_INVALID_PARAMETER);
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn preflight_firmware_cpu_state() -> Result<(), Status> {
    // The current WBL can only proceed from EL1. EL2 -> EL1 transition
    // support must be implemented explicitly before accepting EL2 firmware.
    // SAFETY: UEFI supplies privileged AArch64 execution.
    let state = unsafe { wicofe_kernel_aarch64::capture_handoff_cpu_state() }
        .map_err(|_| EFI_INVALID_PARAMETER)?;
    if state.current_el != (1 << 2) || !state.aarch64_state {
        return Err(EFI_INVALID_PARAMETER);
    }
    // Do not run the kernel-entry validator here: firmware DAIF, MMU and
    // translation settings are not yet the final ABI v2 entry state.
    Ok(())
}
#[cfg(target_arch = "x86_64")]
fn current_stack_pointer() -> u64 {
    let stack_pointer: u64;
    // SAFETY: reading RSP does not modify machine state.
    unsafe {
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) stack_pointer,
            options(nomem, nostack, preserves_flags)
        )
    };
    stack_pointer
}

#[cfg(target_arch = "aarch64")]
fn current_stack_pointer() -> u64 {
    let stack_pointer: u64;
    // SAFETY: reading SP does not modify machine state.
    unsafe {
        core::arch::asm!(
            "mov {}, sp",
            out(reg) stack_pointer,
            options(nomem, nostack, preserves_flags)
        )
    };
    stack_pointer
}

fn active_stack_mapping(prepared: &PreparedBootInfo) -> Result<IdentityMappingRange, Status> {
    // SAFETY: descriptor_count entries were initialized by GetMemoryMap decoding.
    let descriptors =
        unsafe { core::slice::from_raw_parts(prepared.descriptors, prepared.descriptor_count) };
    let stack_pointer = current_stack_pointer();
    let descriptor = descriptors
        .iter()
        .find(|descriptor| {
            let Some(length) = descriptor.number_of_pages.checked_mul(UEFI_PAGE_SIZE) else {
                return false;
            };
            let Some(end) = descriptor.physical_start.checked_add(length) else {
                return false;
            };
            descriptor.number_of_pages != 0
                && stack_pointer >= descriptor.physical_start
                && stack_pointer < end
        })
        .ok_or(EFI_INVALID_PARAMETER)?;

    // UEFI's active image stack must reside in loader or boot-services data.
    // Other memory types are rejected rather than mapped with guessed semantics.
    if descriptor.memory_type != EFI_LOADER_DATA && descriptor.memory_type != EFI_BOOT_SERVICES_DATA
    {
        return Err(EFI_INVALID_PARAMETER);
    }
    let length = descriptor
        .number_of_pages
        .checked_mul(UEFI_PAGE_SIZE)
        .ok_or(EFI_INVALID_PARAMETER)?;
    Ok(IdentityMappingRange {
        physical_start: descriptor.physical_start,
        length,
        permissions: MAP_READ | MAP_WRITE,
    })
}

unsafe fn loaded_image_layout(
    services: &BootServices,
    image_handle: Handle,
) -> Result<(*mut u8, usize), Status> {
    // SAFETY: the image handle and protocol GUID are supplied by UEFI.
    let loaded =
        unsafe { protocol::<LoadedImageProtocol>(services, image_handle, &LOADED_IMAGE_GUID)? };
    // SAFETY: Loaded Image Protocol remains valid while Boot Services are active.
    let image_base = unsafe { (*loaded).image_base.cast::<u8>() };
    // SAFETY: Loaded Image Protocol remains valid while Boot Services are active.
    let image_size =
        usize::try_from(unsafe { (*loaded).image_size }).map_err(|_| EFI_INVALID_PARAMETER)?;
    if image_base.is_null() || image_size == 0 {
        return Err(EFI_INVALID_PARAMETER);
    }
    Ok((image_base, image_size))
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
    image_allocation_size: u64,
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
        image_allocation_size: layout.rounded_image_size,
        entry: parsed.entry(),
    })
}

#[derive(Clone, Copy)]
struct PreparedPageTables {
    root_physical_address: u64,
    used_table_count: usize,
    bootstrap_stack_base: u64,
    bootstrap_stack_top: u64,
    bootstrap_stack_pages: usize,
    bootstrap_stack_allocation_base: u64,
    table_pool_pages: usize,
    active_stack_mapping: IdentityMappingRange,
}

#[derive(Clone, Copy)]
struct BootstrapStackAllocation {
    stack_base: u64,
    stack_top: u64,
    allocation_base: u64,
    allocation_pages: usize,
}

unsafe fn allocate_bootstrap_stack(
    services: &BootServices,
) -> Result<BootstrapStackAllocation, Status> {
    let allocation_size = BOOTSTRAP_STACK_LAYOUT.allocation_size;
    let page_count = allocation_size
        .checked_div(UEFI_PAGE_SIZE)
        .filter(|_| allocation_size % UEFI_PAGE_SIZE == 0)
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count != 0)
        .ok_or(EFI_INVALID_PARAMETER)?;
    let allocate = services.allocate_pages.ok_or(EFI_INVALID_PARAMETER)?;
    let release = services.free_pages.ok_or(EFI_INVALID_PARAMETER)?;
    let mut base = 0_u64;
    // SAFETY: AllocatePages receives a checked page count and valid output pointer.
    let status = unsafe { allocate(0, EFI_LOADER_DATA, page_count, &mut base) };
    if is_error(status) {
        return Err(status);
    }
    let stack_top = match bootstrap_stack_top(base) {
        Some(value) => value,
        None => {
            // SAFETY: release the complete allocation returned by firmware.
            let _ = unsafe { release(base, page_count) };
            return Err(EFI_INVALID_PARAMETER);
        }
    };
    let stack_base = match base.checked_add(BOOTSTRAP_STACK_LAYOUT.guard_size) {
        Some(value) if value < stack_top => value,
        _ => {
            // SAFETY: release the complete allocation returned by firmware.
            let _ = unsafe { release(base, page_count) };
            return Err(EFI_INVALID_PARAMETER);
        }
    };
    let allocation_bytes = match usize::try_from(allocation_size) {
        Ok(value) => value,
        Err(_) => {
            // SAFETY: release the complete allocation returned by firmware.
            let _ = unsafe { release(base, page_count) };
            return Err(EFI_INVALID_PARAMETER);
        }
    };
    let base_pointer = match usize::try_from(base) {
        Ok(value) => value as *mut u8,
        Err(_) => {
            // SAFETY: release the complete allocation returned by firmware.
            let _ = unsafe { release(base, page_count) };
            return Err(EFI_INVALID_PARAMETER);
        }
    };
    // SAFETY: the complete page allocation is writable and exclusively owned by WBL.
    unsafe { core::ptr::write_bytes(base_pointer, 0, allocation_bytes) };
    Ok(BootstrapStackAllocation {
        stack_base,
        stack_top,
        allocation_base: base,
        allocation_pages: page_count,
    })
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
    let mapping_capacity = mappings.len().checked_add(1).ok_or(EFI_INVALID_PARAMETER)?;
    let architecture_mappings = unsafe {
        allocate_array::<wicofe_kernel_x86_64::paging::PageMapping>(services, mapping_capacity)?
    };
    let result = (|| {
        // SAFETY: architecture_mappings contains mapping_capacity aligned writable entries.
        let output =
            unsafe { core::slice::from_raw_parts_mut(architecture_mappings, mapping_capacity) };
        convert_kernel_page_mappings(mappings, &mut output[..mappings.len()])
            .map_err(|_| EFI_INVALID_PARAMETER)?;
        let base_mappings = &output[..mappings.len()];
        let base_table_count = wicofe_kernel_x86_64::paging::required_table_capacity(base_mappings)
            .map_err(|_| EFI_INVALID_PARAMETER)?;
        let table_count =
            page_table_pool_capacity(base_table_count).ok_or(EFI_INVALID_PARAMETER)?;
        // SAFETY: the pool is retained on success and released on any builder failure.
        let table_base = unsafe { allocate_page_table_pool(services, table_count)? };
        output[mappings.len()] = wicofe_kernel_x86_64::paging::PageMapping {
            virtual_start: table_base,
            physical_start: table_base,
            page_count: u64::try_from(table_count).map_err(|_| EFI_INVALID_PARAMETER)?,
            writable: true,
            executable: false,
        };
        let converted = &output[..mapping_capacity];
        let required = wicofe_kernel_x86_64::paging::required_table_capacity(converted)
            .map_err(|_| EFI_INVALID_PARAMETER)?;
        if required > table_count {
            unsafe { free_pages(services, table_base, table_count) };
            return Err(EFI_INVALID_PARAMETER);
        }
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
                    bootstrap_stack_base: 0,
                    bootstrap_stack_top: 0,
                    bootstrap_stack_pages: 0,
                    bootstrap_stack_allocation_base: 0,
                    table_pool_pages: table_count,
                    active_stack_mapping: IdentityMappingRange::default(),
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
    let mapping_capacity = mappings.len().checked_add(1).ok_or(EFI_INVALID_PARAMETER)?;
    let architecture_mappings = unsafe {
        allocate_array::<wicofe_kernel_aarch64::paging::PageMapping>(services, mapping_capacity)?
    };
    let result = (|| {
        // Attribute index 0 is a provisional normal-memory slot. WBL does not
        // program MAIR_EL1 here, so these tables must remain inactive.
        // SAFETY: architecture_mappings contains mapping_capacity aligned writable entries.
        let output =
            unsafe { core::slice::from_raw_parts_mut(architecture_mappings, mapping_capacity) };
        convert_kernel_page_mappings(mappings, 0, &mut output[..mappings.len()])
            .map_err(|_| EFI_INVALID_PARAMETER)?;
        let base_mappings = &output[..mappings.len()];
        let base_table_count =
            wicofe_kernel_aarch64::paging::required_table_capacity(base_mappings)
                .map_err(|_| EFI_INVALID_PARAMETER)?;
        let table_count =
            page_table_pool_capacity(base_table_count).ok_or(EFI_INVALID_PARAMETER)?;
        // SAFETY: the pool is retained on success and released on any builder failure.
        let table_base = unsafe { allocate_page_table_pool(services, table_count)? };
        output[mappings.len()] = wicofe_kernel_aarch64::paging::PageMapping {
            virtual_start: table_base,
            physical_start: table_base,
            page_count: u64::try_from(table_count).map_err(|_| EFI_INVALID_PARAMETER)?,
            writable: true,
            executable: false,
            attribute_index: 0,
        };
        let converted = &output[..mapping_capacity];
        let required = wicofe_kernel_aarch64::paging::required_table_capacity(converted)
            .map_err(|_| EFI_INVALID_PARAMETER)?;
        if required > table_count {
            unsafe { free_pages(services, table_base, table_count) };
            return Err(EFI_INVALID_PARAMETER);
        }
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
                    bootstrap_stack_base: 0,
                    bootstrap_stack_top: 0,
                    bootstrap_stack_pages: 0,
                    bootstrap_stack_allocation_base: 0,
                    table_pool_pages: table_count,
                    active_stack_mapping: IdentityMappingRange::default(),
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
    loader_image_base: *mut u8,
    loader_image_size: usize,
    prepared_boot_info: &PreparedBootInfo,
) -> Result<PreparedPageTables, Status> {
    // Capture the active firmware stack descriptor before allocations below
    // can split its memory-map entry.
    let active_stack = active_stack_mapping(prepared_boot_info)?;
    let segment_capacity = usize::from(parsed.program_header_count());
    let segments = unsafe { allocate_array::<LoadSegment>(services, segment_capacity)? };
    let bootstrap_stack = match unsafe { allocate_bootstrap_stack(services) } {
        Ok(stack) => stack,
        Err(status) => {
            // SAFETY: segments was allocated immediately above.
            unsafe { free_pool(services, segments.cast()) };
            return Err(status);
        }
    };
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
            let kernel_mapping_count = plan_kernel_page_mappings(
                kernel.physical_base,
                kernel.virtual_base,
                segment_slice,
                output,
            )
            .map_err(|_| EFI_INVALID_PARAMETER)?;
            // SAFETY: only the initialized kernel mapping entries are exposed.
            let kernel_mappings =
                unsafe { core::slice::from_raw_parts(mappings, kernel_mapping_count) };

            let pe_mappings =
                unsafe { allocate_array::<KernelPageMapping>(services, MAX_PE_IDENTITY_MAPPINGS)? };
            let pe_result = (|| {
                // SAFETY: the loaded image protocol supplies a live image allocation.
                let loader_image =
                    unsafe { core::slice::from_raw_parts(loader_image_base, loader_image_size) };
                // SAFETY: PE mapping storage has MAX_PE_IDENTITY_MAPPINGS writable entries.
                let pe_output = unsafe {
                    core::slice::from_raw_parts_mut(pe_mappings, MAX_PE_IDENTITY_MAPPINGS)
                };
                let pe_mapping_count =
                    plan_pe_identity_mappings(loader_image_base as u64, loader_image, pe_output)
                        .map_err(|_| EFI_INVALID_PARAMETER)?;
                // SAFETY: only the initialized PE mapping entries are exposed.
                let pe_mapping_slice =
                    unsafe { core::slice::from_raw_parts(pe_mappings, pe_mapping_count) };

                let identity_capacity = pe_mapping_count
                    .checked_add(4)
                    .ok_or(EFI_INVALID_PARAMETER)?;
                let identity_ranges =
                    unsafe { allocate_array::<IdentityMappingRange>(services, identity_capacity)? };
                let identity_result = (|| {
                    // SAFETY: identity_ranges has identity_capacity writable entries.
                    let ranges = unsafe {
                        core::slice::from_raw_parts_mut(identity_ranges, identity_capacity)
                    };
                    for (index, mapping) in pe_mapping_slice.iter().enumerate() {
                        let length = mapping
                            .page_count
                            .checked_mul(UEFI_PAGE_SIZE)
                            .ok_or(EFI_INVALID_PARAMETER)?;
                        ranges[index] = IdentityMappingRange {
                            physical_start: mapping.physical_start,
                            length,
                            permissions: mapping.permissions,
                        };
                    }

                    // BootInfo and the canonical region array are the only pool
                    // allocations needed after ExitBootServices. Normalize their
                    // page ranges and merge only when rounding makes them overlap.
                    let info_range = IdentityMappingRange {
                        physical_start: prepared_boot_info.info as u64,
                        length: core::mem::size_of::<BootInfo>() as u64,
                        permissions: MAP_READ,
                    };
                    let regions_size = prepared_boot_info
                        .region_capacity
                        .checked_mul(core::mem::size_of::<MemoryRegion>())
                        .and_then(|size| u64::try_from(size).ok())
                        .ok_or(EFI_INVALID_PARAMETER)?;
                    let regions_range = IdentityMappingRange {
                        physical_start: prepared_boot_info.regions as u64,
                        length: regions_size,
                        permissions: MAP_READ,
                    };
                    let mut metadata_ranges = [IdentityMappingRange::default(); 2];
                    let metadata_count = coalesce_identity_mapping_ranges(
                        &[info_range, regions_range],
                        &mut metadata_ranges,
                    )
                    .map_err(|_| EFI_INVALID_PARAMETER)?;
                    let metadata_end = pe_mapping_count + metadata_count;
                    ranges[pe_mapping_count..metadata_end]
                        .copy_from_slice(&metadata_ranges[..metadata_count]);
                    ranges[metadata_end] = active_stack;
                    ranges[metadata_end + 1] = IdentityMappingRange {
                        physical_start: bootstrap_stack.stack_base,
                        length: BOOTSTRAP_STACK_LAYOUT.stack_size,
                        permissions: MAP_READ | MAP_WRITE,
                    };
                    let identity_count = metadata_end + 2;

                    let combined_capacity = kernel_mapping_count
                        .checked_add(identity_capacity)
                        .ok_or(EFI_INVALID_PARAMETER)?;
                    let combined = unsafe {
                        allocate_array::<KernelPageMapping>(services, combined_capacity)?
                    };
                    let combined_result = (|| {
                        // SAFETY: combined has combined_capacity writable entries.
                        let combined_output =
                            unsafe { core::slice::from_raw_parts_mut(combined, combined_capacity) };
                        let combined_count = plan_combined_page_mappings(
                            kernel_mappings,
                            &ranges[..identity_count],
                            combined_output,
                        )
                        .map_err(|_| EFI_INVALID_PARAMETER)?;
                        // SAFETY: only the initialized combined mappings are exposed.
                        let combined_slice =
                            unsafe { core::slice::from_raw_parts(combined, combined_count) };
                        unsafe { build_architecture_page_tables(services, combined_slice) }
                    })();
                    // SAFETY: combined was allocated above.
                    unsafe { free_pool(services, combined.cast()) };
                    combined_result
                })();
                // SAFETY: identity_ranges was allocated above.
                unsafe { free_pool(services, identity_ranges.cast()) };
                identity_result
            })();
            // SAFETY: pe_mappings was allocated above.
            unsafe { free_pool(services, pe_mappings.cast()) };
            pe_result
        })();
        // SAFETY: mappings was allocated above.
        unsafe { free_pool(services, mappings.cast()) };
        mapping_result
    })();
    // SAFETY: segments was allocated above.
    unsafe { free_pool(services, segments.cast()) };
    match result {
        Ok(mut tables) => {
            tables.bootstrap_stack_base = bootstrap_stack.stack_base;
            tables.bootstrap_stack_top = bootstrap_stack.stack_top;
            tables.bootstrap_stack_pages = bootstrap_stack.allocation_pages;
            tables.bootstrap_stack_allocation_base = bootstrap_stack.allocation_base;
            tables.active_stack_mapping = active_stack;
            Ok(tables)
        }
        Err(status) => {
            // SAFETY: release the complete stack allocation after page-table preparation failed.
            unsafe {
                free_pages(
                    services,
                    bootstrap_stack.allocation_base,
                    bootstrap_stack.allocation_pages,
                )
            };
            Err(status)
        }
    }
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

    // SAFETY: query the firmware-owned image allocation before constructing its slice.
    let (loader_image_base, loader_image_size) =
        match unsafe { loaded_image_layout(&*boot_services, image_handle) } {
            Ok(layout) => layout,
            Err(status) => {
                unsafe { free_pool(&*boot_services, image.cast()) };
                let _ = print_message(system_table, ERROR_MESSAGE);
                return status;
            }
        };

    // SAFETY: image is a live buffer of image_size bytes allocated by UEFI.
    let loaded_kernel = {
        // SAFETY: image is a live buffer of image_size bytes allocated by UEFI.
        let file_image = unsafe { core::slice::from_raw_parts(image, image_size) };
        match ElfImage::parse(file_image, expected_machine) {
            Ok(parsed) => {
                // SAFETY: parsed references file_image, and boot services are still active.
                match unsafe { load_segments(&*boot_services, file_image, &parsed) } {
                    Ok(kernel) => match unsafe { prepare_boot_info(&*boot_services, kernel) } {
                        Ok(prepared) => match unsafe {
                            prepare_page_tables(
                                &*boot_services,
                                &parsed,
                                kernel,
                                loader_image_base,
                                loader_image_size,
                                &prepared,
                            )
                        } {
                            Ok(tables) => Ok((kernel, tables, prepared)),
                            Err(status) => {
                                let pages = kernel
                                    .image_size
                                    .checked_add(UEFI_PAGE_SIZE - 1)
                                    .and_then(|size| usize::try_from(size / UEFI_PAGE_SIZE).ok())
                                    .unwrap_or(0);
                                // SAFETY: load_segments retained this exact aligned image range.
                                unsafe { free_pages(&*boot_services, kernel.physical_base, pages) };
                                unsafe { free_prepared_boot_info(&*boot_services, prepared) };
                                Err(status)
                            }
                        },
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
                    },
                    Err(status) => Err(status),
                }
            }
            Err(_) => Err(EFI_INVALID_PARAMETER),
        }
    };
    // SAFETY: release the temporary source file after parsing and copying finish.
    unsafe { free_pool(&*boot_services, image.cast()) };

    match loaded_kernel {
        Ok((kernel, tables, mut prepared)) => {
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
                tables.bootstrap_stack_base,
                tables.bootstrap_stack_top,
                tables.bootstrap_stack_pages,
            );
            if let Err(status) = preflight_firmware_cpu_state() {
                let _ = print_message(system_table, ERROR_MESSAGE);
                return status;
            }
            let console_status = print_message(system_table, LOADED_MESSAGE);
            // SAFETY: all storage is retained; this refresh performs no allocation.
            if let Err(status) =
                unsafe { refresh_prepared_boot_info(&*boot_services, &mut prepared, &tables) }
            {
                return status;
            }
            let _refreshed_map_key = prepared.map_key;
            console_status
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
