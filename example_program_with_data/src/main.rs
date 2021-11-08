#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, Ordering};

#[panic_handler]
fn panic(_panic_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// BSS example
#[no_mangle]
pub static BSSTHING: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub extern fn _start() -> *const u8 {
    BSSTHING.store(true, Ordering::Relaxed);
    "asdf".as_ptr()
}

