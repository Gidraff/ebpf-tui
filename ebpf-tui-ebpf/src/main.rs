#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action, 
    macros::{xdp, map}, 
    maps::PerCpuArray, 
    programs::XdpContext
};

#[map]
static PACKET_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[xdp]
pub fn ebpf_tui(ctx: XdpContext) -> u32 {
    match try_ebpf_tui(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ebpf_tui(_ctx: XdpContext) -> Result<u32, u32> {
    if let Some(count) = unsafe { PACKET_COUNT.get_ptr_mut(0)} {
        unsafe { *count += 1};
    }
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
