#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketInfo {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_version: u8,
    pub protocol: u8,
}
