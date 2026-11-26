// use anyhow::{Context as _, Ok};
use std::ffi::CString;

use anyhow::Context as _;
use aya::{
    maps::PerCpuArray,
    programs::{Xdp, xdp::XdpMode},
};
use clap::Parser;

#[rustfmt::skip]
use log::{debug, warn};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::TryFrom,
    fs, io,
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use aya::maps::ring_buf::RingBuf;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ebpf_tui_common::PacketInfo;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-tui"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = unsafe {
                tokio::io::unix::AsyncFd::register_with_interest(
                    logger,
                    tokio::io::Interest::READABLE,
                )?
            };
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // ── XDP attach ───
    let Opt { iface } = opt;

    let program: &mut Xdp = ebpf.program_mut("ebpf_tui").unwrap().try_into()?;
    program.load()?;

    let c_iface =
        CString::new(iface.clone()).context("Invalid interface name contains null bytes")?;

    program.attach(c_iface.as_c_str(), XdpMode::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut packet_events = RingBuf::<aya::maps::MapData>::try_from(
        ebpf.take_map("PACKET_EVENTS")
            .context("PACKET_EVENTS ring buffer not found")?,
    )?;
    let mut packets = VecDeque::<PacketInfo>::with_capacity(200);
    let mut open_ports = read_open_ports();
    let mut open_port_packets = HashMap::<(u8, u16), u64>::new();
    let mut last_open_ports_refresh = Instant::now();

    loop {
        while let Some(item) = packet_events.next() {
            if item.len() == std::mem::size_of::<PacketInfo>() {
                let packet =
                    unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<PacketInfo>()) };
                let src_open = open_ports.contains(&(packet.protocol, packet.src_port));
                let dst_open = open_ports.contains(&(packet.protocol, packet.dst_port));
                if src_open {
                    *open_port_packets
                        .entry((packet.protocol, packet.src_port))
                        .or_default() += 1;
                }
                if dst_open {
                    *open_port_packets
                        .entry((packet.protocol, packet.dst_port))
                        .or_default() += 1;
                }
                if packets.len() == 200 {
                    packets.pop_front();
                }
                packets.push_back(packet);
            }
        }

        if last_open_ports_refresh.elapsed() >= Duration::from_secs(2) {
            open_ports = read_open_ports();
            last_open_ports_refresh = Instant::now();
        }

        let packet_count = read_packet_count(&mut ebpf);

        terminal.draw(|frame| {
            let area = frame.area();

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(5),
                    Constraint::Min(0),
                ])
                .split(area);

            let title = Paragraph::new(Line::from(vec![
                Span::styled(" ebpf-tui ", Style::default().fg(Color::Green)),
                Span::raw("│ XDP on: "),
                Span::styled(iface.as_str(), Style::default().fg(Color::Yellow)),
                Span::raw("  │  q to quit"),
            ]))
            .block(Block::default().borders(Borders::ALL));
            frame.render_widget(title, chunks[0]);

            let count_text = match packet_count {
                Ok(n) => format!("{n}"),
                Err(_) => " map read error ".to_string(),
            };

            let counter = Paragraph::new(Line::from(vec![
                Span::raw(" Total Packets: "),
                Span::styled(
                    count_text,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            ]))
            .block(Block::default().borders(Borders::ALL).title(" Packets "));
            frame.render_widget(counter, chunks[1]);

            let body = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
                .split(chunks[2]);

            let traffic_lines = packets
                .iter()
                .rev()
                .take(12)
                .map(|packet| {
                    let src = format_ip(&packet.src_ip, packet.ip_version);
                    let dst = format_ip(&packet.dst_ip, packet.ip_version);
                    let src_port = if packet.src_port == 0 {
                        "-".to_string()
                    } else {
                        packet.src_port.to_string()
                    };
                    let dst_port = if packet.dst_port == 0 {
                        "-".to_string()
                    } else {
                        packet.dst_port.to_string()
                    };
                    let open = open_ports.contains(&(packet.protocol, packet.src_port))
                        || open_ports.contains(&(packet.protocol, packet.dst_port));
                    Line::from(vec![
                        Span::raw(format!(
                            "{} {}:{} -> {}:{}",
                            protocol_name(packet.protocol),
                            src,
                            src_port,
                            dst,
                            dst_port,
                        )),
                        if open {
                            Span::styled("  OPEN", Style::default().fg(Color::Green))
                        } else {
                            Span::raw("")
                        },
                    ])
                })
                .collect::<Vec<_>>();
            let traffic = Paragraph::new(traffic_lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Source / Destination "),
            );
            frame.render_widget(traffic, body[0]);

            let mut open_lines = open_ports
                .iter()
                .map(|(protocol, port)| {
                    let packets = open_port_packets
                        .get(&(*protocol, *port))
                        .copied()
                        .unwrap_or(0);
                    format!(
                        "{} {:>5}  packets: {}",
                        protocol_name(*protocol),
                        port,
                        packets,
                    )
                })
                .collect::<Vec<_>>();
            open_lines.sort();
            open_lines.truncate(12);

            let open_panel =
                Paragraph::new(open_lines.into_iter().map(Line::from).collect::<Vec<_>>()).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Listening / Open Ports "),
                );
            frame.render_widget(open_panel, body[1]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

fn read_packet_count(ebpf: &mut aya::Ebpf) -> anyhow::Result<u64> {
    let map = PerCpuArray::<_, u64>::try_from(
        ebpf.map_mut("PACKET_COUNT")
            .context("PACKET_COUNT map not found")?,
    )?;

    let counts = map.get(&0, 0)?;
    Ok(counts.iter().sum())
}

fn format_ip(bytes: &[u8; 16], version: u8) -> String {
    if version == 4 {
        Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]).to_string()
    } else {
        Ipv6Addr::from(*bytes).to_string()
    }
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => "OTHER",
    }
}

fn read_open_ports() -> HashSet<(u8, u16)> {
    let mut ports = HashSet::new();

    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(contents) = fs::read_to_string(path) {
            for line in contents.lines().skip(1) {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() >= 4
                    && fields[3].eq_ignore_ascii_case("0A")
                    && let Some((_, port)) = fields[1].rsplit_once(':')
                    && let Ok(port) = u16::from_str_radix(port, 16)
                {
                    ports.insert((6, port));
                }
            }
        }
    }

    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(contents) = fs::read_to_string(path) {
            for line in contents.lines().skip(1) {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() >= 4
                    && let Some((_, port)) = fields[1].rsplit_once(':')
                    && let Ok(port) = u16::from_str_radix(port, 16)
                {
                    ports.insert((17, port));
                }
            }
        }
    }

    ports
}
