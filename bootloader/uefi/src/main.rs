#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

type Status = usize;
type Handle = *mut c_void;

const EFI_INVALID_PARAMETER: Status = 2;

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SimpleTextOutputProtocol {
    pub reset: usize,
    pub output_string:
        Option<unsafe extern "efiapi" fn(*mut SimpleTextOutputProtocol, *const u16) -> Status>,
    pub remaining_functions: [usize; 8],
}

#[repr(C)]
pub struct SystemTable {
    pub header: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub console_in: *mut c_void,
    pub console_out_handle: Handle,
    pub console_out: *mut SimpleTextOutputProtocol,
    pub standard_error_handle: Handle,
    pub standard_error: *mut SimpleTextOutputProtocol,
    pub runtime_services: *mut c_void,
    pub boot_services: *mut c_void,
    pub number_of_table_entries: usize,
    pub configuration_table: *mut c_void,
}

const fn ascii_to_utf16<const N: usize>(input: &[u8; N]) -> [u16; N] {
    let mut output = [0_u16; N];
    let mut index = 0;
    while index < N {
        output[index] = input[index] as u16;
        index += 1;
    }
    output
}

const MESSAGE: &[u16] =
    &ascii_to_utf16(b"Wicofe Bootloader: UEFI entry reached.\r\nELF validation core ready.\r\n\0");

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    if system_table.is_null() {
        return EFI_INVALID_PARAMETER;
    }

    // SAFETY: UEFI passes a valid system-table pointer to an image entry point.
    let console = unsafe { (*system_table).console_out };
    if console.is_null() {
        return EFI_INVALID_PARAMETER;
    }

    // SAFETY: the console protocol pointer is supplied by the system table.
    let output_string = unsafe { (*console).output_string };
    let Some(output_string) = output_string else {
        return EFI_INVALID_PARAMETER;
    };

    // SAFETY: MESSAGE is NUL-terminated UTF-16 and remains valid for this call.
    unsafe { output_string(console, MESSAGE.as_ptr()) }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
