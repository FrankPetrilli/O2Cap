#![feature(i128_type)]

/* Frank Petrilli | frank@petril.li | frank.petril.li
 * Packet capture
 * NOTE: When run with sudo, use the -E flag to detect and ignore SSH packets automatically.
 */

extern crate pcap;
extern crate users;

mod ipv4;
mod ipv6;

use std::io::Write;

fn main() {
    // Get our program name
	let args: Vec<String> = std::env::args().collect();
	let ref program_name = args[0];

	// Check our permissions
	let uid = users::get_current_uid();
	if uid != 0 {
		println!("\t{} must be run as root. Exiting.", program_name);
		std::process::exit(1);
	}

	// Get all devices
	let mut device_list;
	match pcap::Device::list() {
		Ok(list) => device_list = list,
		Err(err) => panic!("Error getting interfaces: {}", err)
	}

	if device_list.len() == 0 {
		println!("We were unable to find any devices. Exiting.");
        std::process::exit(1);
	}


	// List all devices
	println!("Select a device:");
	for (i, dev) in device_list.iter().enumerate() {
		println!("\t{}: {}", i, dev.name);
	}
	let choice = prompt_for_choice(0, device_list.len() as u32);
	let dev = device_list.remove(choice as usize);

    // Open that device
    let mut cap;
    match dev.open() {
        Ok(device) => cap = device,
        Err(err) => panic!("Error opening device: {}", err)
    }

    // Keep grabbing packets and analyzing them
    loop {
        analyze_packet(cap.next().unwrap());
    }
}

fn analyze_packet(packet: pcap::Packet) {
    // A packet can't be under 64 bytes by standard
    if packet.header.caplen < 64 { return; }
    let ethernet_type: u16 = ((packet.data[12] as u16) << 8) + packet.data[13] as u16;
    let output = match ethernet_type {
        // IPoE traffic
        0x0800 => handle_ipv4(packet),
        0x86DD => handle_ipv6(packet),
        0x0806 => handle_arp(packet),

        // PPPoE
        0x8863 => handle_pad(packet), // PPPoE Discovery
        0x8864 => handle_pas(packet), // PPPoE Session

        // L2 OAM
        0x88CC => handle_lldp(packet),
        _ => {format!("")}
    };
    // Ignore traffic we don't want to output.
    if output.len() != 0 { println!("{}", output); }
}

// Layer 3

fn handle_ipv4(packet: pcap::Packet) -> String {
    if (packet.data[14] >> 4) != 0x4 {
        return format!("Invalid IPv4") // Not IPv4
    }
    let header_length_bytes = (packet.data[14] & 0b00001111 * 4);
    let dscp = packet.data[15];
    let ttl = packet.data[22];
    let l4 = packet.data[23];
    // Use offset to change between source and dest IP Addr
    let mut offset = 26;
    let saddr = ipv4::IPv4Addr::from_u32(
        ((packet.data[offset + 0] as u32) << 24) + 
        ((packet.data[offset + 1] as u32) << 16) +
        ((packet.data[offset + 2] as u32) << 8) +
        ((packet.data[offset + 3] as u32) << 0) 
    );
    offset = 30;
    let daddr = ipv4::IPv4Addr::from_u32(
        ((packet.data[offset + 0] as u32) << 24) + 
        ((packet.data[offset + 1] as u32) << 16) +
        ((packet.data[offset + 2] as u32) << 8) +
        ((packet.data[offset + 3] as u32) << 0) 
    );
    // How we ignore SSH
    if is_ssh() && l4 == 0x6 && packet_is_ssh(&packet) { return format!(""); }
    format!("IPv4: {} -> {} (TTL: {}, DSCP: {}) {{\n\t{}\n}}", saddr, daddr, ttl, dscp, handle_l4(packet, l4, header_length_bytes))
}
fn handle_ipv6(packet: pcap::Packet) -> String{
    if (packet.data[14] >> 4) != 0x6 {
        return format!("Invalid IPv6")
    }
    let l4 = packet.data[20];
    let ttl = packet.data[21];
    let mut offset = 22; // Saddr
    let init: u128 = 0;
    let mut byte_index = 0;
    let saddr = ipv6::IPv6Addr::from_u128(*(&packet.data[offset..offset + 16].iter().fold(init, |mut res, byte| {
        res += (*byte as u128) << ((15 - byte_index) * 8);
        byte_index += 1;
        res
    })));
    byte_index = 0;
    offset = 38; // Daddr
    let daddr = ipv6::IPv6Addr::from_u128(*(&packet.data[offset..offset + 16].iter().fold(init, |mut res, byte| {
        res += (*byte as u128) << ((15 - byte_index) * 8);
        byte_index += 1;
        res
    })));
    format!("IPv6: {} -> {} (TTL: {}) {{\n\t{}\n}}", saddr, daddr, ttl, handle_l4(packet, l4, 40 /* IPv6 is always 40 bytes */))
}
fn handle_arp(packet: pcap::Packet) -> String {
    format!("ARP")
}
fn handle_pad(packet: pcap::Packet) -> String {
    format!("PPPoE discovery")
}
fn handle_pas(packet: pcap::Packet) -> String {
    format!("PPPoE Session")
}
fn handle_lldp(packet: pcap::Packet) -> String {
    format!("LLDP")
}

// ========== Layer 4 ==========
fn handle_l4(packet: pcap::Packet, l4protocol: u8, offset: u32) -> String {
    match l4protocol {
        0x3a => handle_icmpv6(packet, offset),
        0x06 => handle_tcp(packet, offset),
        0x11 => handle_udp(packet, offset),
        _ => {format!("")}
    }
}

fn handle_tcp(packet: pcap::Packet) -> String {
    let sport: u16 = ((packet.data[0x22] as u16) << 8) + packet.data[0x23] as u16;
    let dport: u16 = ((packet.data[0x24] as u16) << 8) + packet.data[0x25] as u16;
    let flags: u16 = ((packet.data[0x2f] as u16) << 8) + packet.data[0x30] as u16;
    let syn = (flags & 0b000000000010) > 0;
    let ack = (flags & 0b000000001000) > 0;
    let fin = (flags & 0b000000000001) > 0;
    let mut flag_string = String::new();
    if syn { flag_string.push_str(" SYN"); }
    if ack { flag_string.push_str(" ACK"); }
    if fin { flag_string.push_str(" FIN"); }

    format!("TCP {} -> {} (Flags:{})", sport, dport, flag_string)
}

fn handle_udp(packet: pcap::Packet) -> String {
    let sport: u16 = ((packet.data[0x22] as u16) << 8) + packet.data[0x23] as u16;
    let dport: u16 = ((packet.data[0x24] as u16) << 8) + packet.data[0x25] as u16;
    format!("UDP {} -> {}", sport, dport)
}

fn handle_icmpv6(packet: pcap::Packet) -> String {
    let icmp_type = packet.data[0x36];
    let icmp_type_string = match icmp_type {
        128 => "Echo Request",
        129 => "Echo Reply",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        _ => "Unknown ICMPv6 Type",
    };
    format!("ICMPv6 (Type: {})", icmp_type_string)
}

// ========== Helpers ==========

// Note: this won't work with sudo, as it won't pass the SSH_CLIENT variable
// unless the -E flag is passed.
fn is_ssh() -> bool {
    match std::env::var("SSH_CLIENT") {
        Ok(val) => true,
        Err(e) => false
    }
}

fn packet_is_ssh(packet: &pcap::Packet) -> bool {
    if packet.data.len() < 0x25 { return false; }
    ((((packet.data[0x22] as u16) << 8) + packet.data[0x23] as u16) == 22 || 
     (((packet.data[0x24] as u16) << 8) + packet.data[0x25] as u16) == 22)
}

fn prompt_for_choice(min: u32, max: u32) -> u32 {
	println!();
    let mut done = false;
	loop {
        let mut input_str = String::new();
        print!("Enter your choice ({} - {}): ", min, max);
        std::io::stdout().flush().ok().expect("Could not flush stdout");
		match std::io::stdin().read_line(&mut input_str) {
			Ok(_) => {
				let mut input: u32 = 1;
				match input_str.trim().parse::<u32>() {
					Ok(i) => { input = i; done = true },
					Err(err) => println!("Error parsing input number: {}", err)
				}
				if done && input <= max && input >= min {
					return input;
				} else {
                    println!("Your input was not in the acceptable range of values.");
                }
			},
			Err(err) => panic!(err)
		}
	}
}
