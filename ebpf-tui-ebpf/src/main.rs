#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{PerCpuArray, RingBuf},
    programs::XdpContext,
};
use ebpf_tui_common::PacketInfo;

#[map]
static PACKET_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PACKET_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[xdp]
pub fn ebpf_tui(ctx: XdpContext) -> u32 {
    match try_ebpf_tui(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_ebpf_tui(ctx: XdpContext) -> Result<u32, u32> {
    if let Some(count) = unsafe { PACKET_COUNT.get_ptr_mut(0) } {
        unsafe { *count += 1 };
    }

    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + 14 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_proto = u16::from_be_bytes([unsafe { *(data as *const u8).add(12) }, unsafe {
        *(data as *const u8).add(13)
    }]);

    let mut packet = PacketInfo {
        src_ip: [0; 16],
        dst_ip: [0; 16],
        src_port: 0,
        dst_port: 0,
        ip_version: 0,
        protocol: 0,
    };

    match eth_proto {
        0x0800 => {
            parse_ipv4(data + 14, data_end, &mut packet)?;
        }
        0x86dd => {
            parse_ipv6(data + 14, data_end, &mut packet)?;
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    if let Some(mut entry) = PACKET_EVENTS.reserve::<PacketInfo>(0) {
        entry.write(packet);
        entry.submit(0);
    }

    Ok(xdp_action::XDP_PASS)
}

fn parse_ipv4(ip: usize, data_end: usize, packet: &mut PacketInfo) -> Result<u32, u32> {
    if ip + 20 > data_end {
        return Err(1);
    }

    let version_ihl = unsafe { *(ip as *const u8) };
    if version_ihl >> 4 != 4 {
        return Err(1);
    }

    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 || ip + ihl > data_end {
        return Err(1);
    }

    let protocol = unsafe { *((ip + 9) as *const u8) };
    packet.ip_version = 4;
    packet.protocol = protocol;

    for i in 0..4 {
        packet.src_ip[12 + i] = unsafe { *((ip + 12 + i) as *const u8) };
        packet.dst_ip[12 + i] = unsafe { *((ip + 16 + i) as *const u8) };
    }

    parse_ports(ip + ihl, data_end, protocol, packet)
}

fn parse_ipv6(ip: usize, data_end: usize, packet: &mut PacketInfo) -> Result<u32, u32> {
    if ip + 40 > data_end {
        return Err(1);
    }

    if unsafe { *(ip as *const u8) } >> 4 != 6 {
        return Err(1);
    }

    let next_header = unsafe { *((ip + 6) as *const u8) };
    packet.ip_version = 6;
    packet.protocol = next_header;

    for i in 0..16 {
        packet.src_ip[i] = unsafe { *((ip + 8 + i) as *const u8) };
        packet.dst_ip[i] = unsafe { *((ip + 24 + i) as *const u8) };
    }

    parse_ports(ip + 40, data_end, next_header, packet)
}

fn parse_ports(
    transport: usize,
    data_end: usize,
    protocol: u8,
    packet: &mut PacketInfo,
) -> Result<u32, u32> {
    if protocol != 6 && protocol != 17 {
        return Ok(xdp_action::XDP_PASS);
    }
    if transport + 4 > data_end {
        return Err(1);
    }

    packet.src_port = u16::from_be_bytes([unsafe { *(transport as *const u8) }, unsafe {
        *((transport + 1) as *const u8)
    }]);
    packet.dst_port = u16::from_be_bytes([unsafe { *((transport + 2) as *const u8) }, unsafe {
        *((transport + 3) as *const u8)
    }]);
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
