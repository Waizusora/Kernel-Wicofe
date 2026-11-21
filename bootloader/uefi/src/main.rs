#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;
use wicofe_bootloader_elf::ElfImage;
#[cfg(target_arch = "aarch64")]
use wicofe_bootloader_elf::EM_AARCH64;
#[cfg(target_arch = "x86_64")]
use wicofe_bootloader_elf::EM_X86_64;

type Status = usize;
type Handle = *mut c_void;

const EFI_ERROR_BIT: usize = 1usize << (usize::BITS - 1);
const EFI_BUFFER_TOO_SMALL: Status = EFI_ERROR_BIT | 5;
const EFI_INVALID_PARAMETER: Status = EFI_ERROR_BIT | 2;
const EFI_LOADER_DATA: u32 = 2;
const EFI_FILE_MODE_READ: u64 = 1;
const MAX_KERNEL_SIZE: usize = 64 * 1024 * 1024;
const KERNEL_PATH: &[u16] = &[
    0x005c, 0x0045, 0x0046, 0x0049, 0x005c, 0x0057, 0x0049, 0x0043, 0x004f, 0x0046,
    0x0045, 0x005c, 0x004b, 0x0045, 0x0052, 0x004e, 0x0045, 0x004c, 0x002e, 0x0045,
    0x004c, 0x0046, 0,
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
    data1: 0x5b1b31a1, data2: 0x9562, data3: 0x11d2,
    data4: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
const SIMPLE_FS_GUID: Guid = Guid {
    data1: 0x964e5b22, data2: 0x6459, data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
const FILE_INFO_GUID: Guid = Guid {
    data1: 0x09576e92, data2: 0x6d3f, data3: 0x11d2,
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
type AllocatePoolFn = unsafe extern "efiapi" fn(u32, usize, *mut *mut c_void) -> Status;
type FreePoolFn = unsafe extern "efiapi" fn(*mut c_void) -> Status;
#[repr(C)]
struct BootServices {
    header: TableHeader,
    before_pool: [usize; 5],
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
type OpenVolumeFn = unsafe extern "efiapi" fn(*mut SimpleFileSystemProtocol, *mut *mut FileProtocol) -> Status;
#[repr(C)]
struct SimpleFileSystemProtocol {
    revision: u64,
    open_volume: Option<OpenVolumeFn>,
}
type FileOpenFn = unsafe extern "efiapi" fn(*mut FileProtocol, *mut *mut FileProtocol, *const u16, u64, u64) -> Status;
type FileCloseFn = unsafe extern "efiapi" fn(*mut FileProtocol) -> Status;
type FileReadFn = unsafe extern "efiapi" fn(*mut FileProtocol, *mut usize, *mut c_void) -> Status;
type FileGetInfoFn = unsafe extern "efiapi" fn(*mut FileProtocol, *const Guid, *mut usize, *mut c_void) -> Status;
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

unsafe fn protocol<T>(services: &BootServices, handle: Handle, guid: &Guid) -> Result<*mut T, Status> {
    let function = services.handle_protocol.ok_or(EFI_INVALID_PARAMETER)?;
    let mut interface = core::ptr::null_mut();
    // SAFETY: caller supplies a firmware handle and a valid protocol GUID.
    let status = unsafe { function(handle, guid, &mut interface) };
    if is_error(status) || interface.is_null() {
        return Err(if is_error(status) { status } else { EFI_INVALID_PARAMETER });
    }
    Ok(interface.cast())
}
unsafe fn allocate_pool(services: &BootServices, size: usize) -> Result<*mut c_void, Status> {
    let function = services.allocate_pool.ok_or(EFI_INVALID_PARAMETER)?;
    let mut buffer = core::ptr::null_mut();
    // SAFETY: firmware AllocatePool receives a valid output pointer.
    let status = unsafe { function(EFI_LOADER_DATA, size, &mut buffer) };
    if is_error(status) || buffer.is_null() {
        return Err(if is_error(status) { status } else { EFI_INVALID_PARAMETER });
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

unsafe fn read_kernel(services: &BootServices, image_handle: Handle) -> Result<(*mut u8, usize), Status> {
    // SAFETY: protocol handle and GUID are supplied by UEFI.
    let loaded = unsafe { protocol::<LoadedImageProtocol>(services, image_handle, &LOADED_IMAGE_GUID)? };
    // SAFETY: loaded-image protocol was returned successfully.
    let device = unsafe { (*loaded).device_handle };
    if device.is_null() {
        return Err(EFI_INVALID_PARAMETER);
    }
    // SAFETY: device handle belongs to the loaded image.
    let filesystem = unsafe { protocol::<SimpleFileSystemProtocol>(services, device, &SIMPLE_FS_GUID)? };
    // SAFETY: protocol pointer is valid for the lifetime of boot services.
    let open_volume = unsafe { (*filesystem).open_volume }.ok_or(EFI_INVALID_PARAMETER)?;
    let mut root = core::ptr::null_mut();
    // SAFETY: open_volume writes the root directory handle on success.
    let status = unsafe { open_volume(filesystem, &mut root) };
    if is_error(status) || root.is_null() {
        return Err(if is_error(status) { status } else { EFI_INVALID_PARAMETER });
    }

    let result = (|| {
        // SAFETY: root is an open EFI_FILE_PROTOCOL handle.
        let open = unsafe { (*root).open }.ok_or(EFI_INVALID_PARAMETER)?;
        let mut file = core::ptr::null_mut();
        // SAFETY: path is NUL-terminated UTF-16 and output pointer is valid.
        let status = unsafe { open(root, &mut file, KERNEL_PATH.as_ptr(), EFI_FILE_MODE_READ, 0) };
        if is_error(status) || file.is_null() {
            return Err(if is_error(status) { status } else { EFI_INVALID_PARAMETER });
        }

        let file_result = (|| {
            // SAFETY: file is an open EFI_FILE_PROTOCOL handle.
            let get_info = unsafe { (*file).get_info }.ok_or(EFI_INVALID_PARAMETER)?;
            let mut info_size = 0usize;
            // SAFETY: null buffer requests the required EFI_FILE_INFO size.
            let status = unsafe { get_info(file, &FILE_INFO_GUID, &mut info_size, core::ptr::null_mut()) };
            if status != EFI_BUFFER_TOO_SMALL || info_size < 16 {
                return Err(if is_error(status) { status } else { EFI_INVALID_PARAMETER });
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
            let file_size_u64 = unsafe { core::ptr::read_unaligned((info as *const u8).add(8).cast::<u64>()) };
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
                return Err(if is_error(status) { status } else { EFI_INVALID_PARAMETER });
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
    let Some(output) = output else { return EFI_INVALID_PARAMETER; };
    // SAFETY: message is NUL-terminated UTF-16 and remains valid for the call.
    unsafe { output(console, message.as_ptr()) }
}

const START_MESSAGE: &[u16] = &[
    0x0057,0x0069,0x0063,0x006f,0x0066,0x0065,0x0020,0x0042,0x006f,0x006f,0x0074,0x006c,0x006f,0x0061,0x0064,0x0065,0x0072,0x003a,0x0020,0x0055,0x0045,0x0046,0x0049,0x0020,0x0065,0x006e,0x0074,0x0072,0x0079,0x0020,0x0072,0x0065,0x0061,0x0063,0x0068,0x0065,0x0064,0x002e,0x000d,0x000a,0,
];
const VALID_MESSAGE: &[u16] = &[
    0x004b,0x0045,0x0052,0x004e,0x0045,0x004c,0x002e,0x0045,0x004c,0x0046,0x0020,0x0072,0x0065,0x0061,0x0064,0x0020,0x0061,0x006e,0x0064,0x0020,0x0045,0x004c,0x0046,0x0036,0x0034,0x0020,0x0076,0x0061,0x006c,0x0069,0x0064,0x0061,0x0074,0x0065,0x0064,0x002e,0x000d,0x000a,0,
];
const ERROR_MESSAGE: &[u16] = &[
    0x0057,0x0042,0x004c,0x003a,0x0020,0x006b,0x0065,0x0072,0x006e,0x0065,0x006c,0x0020,0x006c,0x006f,0x0061,0x0064,0x0020,0x006f,0x0072,0x0020,0x0045,0x004c,0x0046,0x0020,0x0076,0x0061,0x006c,0x0069,0x0064,0x0061,0x0074,0x0069,0x006f,0x006e,0x0020,0x0066,0x0061,0x0069,0x006c,0x0065,0x0064,0x002e,0x000d,0x000a,0,
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
    let parsed = unsafe {
        ElfImage::parse(core::slice::from_raw_parts(image, image_size), expected_machine)
    };
    // SAFETY: release the file buffer after validation; no pointer into it is retained.
    unsafe { free_pool(&*boot_services, image.cast()) };

    match parsed {
        Ok(_) => print_message(system_table, VALID_MESSAGE),
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
