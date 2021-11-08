#![no_std]
#![no_main]

#[panic_handler]
fn panic(_panic_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern fn _start(x: u64, y: u64) -> u64 {
    x.wrapping_add(y)
}

