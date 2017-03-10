#![feature(i128_type)]

/* Frank Petrilli | frank@petril.li | frank.petril.li
 * Packet capture
 */

extern crate pcap;
extern crate users;

extern crate analysis;

use std::io::Write;


fn main() {
    print_header();
    let mut filter = Vec::<analysis::filters::Filter>::new();
    // Get our program name
	let args: Vec<String> = std::env::args().collect();
	let ref program_name = args[0];

    prompt_for_filters(&mut filter);

    let mut write_to_file = false;

    let mut input_str = String::new();
    print!("Output filename (none): ");
    std::io::stdout().flush().ok().expect("Could not flush stdout");
    input_str.clear();
    let mut output: std::fs::File = match std::io::stdin().read_line(&mut input_str) {
        Ok(bytes) => {
            let mut f = std::fs::File::open("/dev/null").expect("Failed to get default output");
            if bytes > 1 {
                write_to_file = true;
                f = std::fs::File::create(input_str.trim()).expect("Unable to create file");
            }
            f
        },
        Err(err) => panic!(err)
    };
    match args.get(1) {
        Some(filename) => {
            let path = std::path::Path::new(filename);
            let mut cap = match pcap::Capture::from_file(path) {
                Ok(input) => input,
                Err(err) => { println!("Error opening pcap file: {}", err); std::process::exit(1); }
            };
            loop {
                let p = match cap.next() {
                    Ok(n) => n,
                    Err(err) => { 
                        match err {
                            pcap::Error::NoMorePackets => {
                                std::process::exit(0);
                            },
                            _ => {
                                println!("Error reading file: {}", err);
                                std::process::exit(1);
                            }
                        }
                    }
                };
                analyze_packet(p, &filter);
            }
        },
        None => {
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
            let mut cap = match dev.open() {
                Ok(device) => device,
                Err(err) => panic!("Error opening device: {}", err)
            };
            loop {
                let out = analyze_packet(cap.next().unwrap(), &filter);
                if write_to_file {
                    output.write(out.as_bytes()).expect("Failed to write to file");
                    output.write("\n".as_bytes()).expect("Failed to write to file");
                    output.flush().expect("Unable to flush output file");
                } else {
                    println!("{}", out);
                }
            }
        }
    };
}

// Analyze a given ethernet header
fn analyze_packet(packet: pcap::Packet, filter: &Vec<analysis::filters::Filter>) -> String {
    // A packet can't be under 64 bytes by standard, but sometimes they are 
    // (PPPoE Discovery, for example)
    // if packet.header.caplen < 64 { return; }


    // Skip filtered packets
    for fil in filter {
        if fil.matches(&packet) { return String::from(""); } 
    }

    // Extract the src/dst MAC
    let dst_mac = analysis::ether::MACAddr::from_u8(&packet.data[0..6]);
    let src_mac = analysis::ether::MACAddr::from_u8(&packet.data[6..12]);
    let ethernet_type: u16 = ((packet.data[12] as u16) << 8) + packet.data[13] as u16;
    // TODO: Allow for Q-in-Q, etc, but for now...
    let offset = 14;
    let output = match ethernet_type {
        // IPoE traffic
        0x0800 => handle_ipv4(packet, offset),
        0x86DD => handle_ipv6(packet, offset),
        0x0806 => handle_arp(packet, offset),

        // MPLS
        0x8847 => handle_mpls(packet, offset), // MPLS Packet

        // PPPoE
        0x8863 => handle_pad(packet, offset), // PPPoE Discovery
        0x8864 => handle_pas(packet, offset), // PPPoE Session

        // L2 OAM
        0x88CC => handle_lldp(packet, offset),
        _ => {format!("{:#x}", ethernet_type)}
    };
    return format!("Ethernet: {} -> {} {{\n{}\n}}", src_mac, dst_mac, indent(output, 1));
}

// Layer 3

fn handle_mpls(packet: pcap::Packet, offset: usize) -> String {
    let mut label: u32 = packet.data[offset + 0..offset + 2].iter().fold(0, |mut res, sec| {
        res = res << 8;
        res |= *sec as u32;
        res
    });
    label = label << 4;
    label |= packet.data[offset + 2] as u32 >> 4;
    let exp = packet.data[offset + 2] as u32 >> 5;
    let bottom_of_stack = packet.data[offset + 2] as u32 & 0x1 == 1;
    let ttl = packet.data[offset + 3];
    // Checking what protocol the next packet is can be difficult... We assume IPv4 or IPv6 here,
    // and ignore EoMPLS just like Cisco and Brocade did. >.<
    // See this NANOG message: https://lists.gt.net/nanog/users/192741
    let output = match packet.data[offset + 4] >> 4 {
        0x4 => handle_ipv4(packet, offset + 4),
        0x6 => handle_ipv6(packet, offset + 4),
        _ => format!("Unknown MPLS sub-header: {}", packet.data[offset + 4])
    };
    format!("MPLS (Label: {}, Exp: {}, TTL: {}) {{\n{}\n}}", label, exp, ttl, 
            if bottom_of_stack { indent(output, 1) } else { indent(format!("Stacked MPLS not yet implemented."), 1) }
    )
}

fn handle_ipv4(packet: pcap::Packet, offset: usize) -> String {
    if (packet.data[0 + offset] >> 4) != 0x4 {
        return format!("Invalid IPv4") // Not IPv4
    }
    let header_length_bytes: usize = ((packet.data[0 + offset] & 0b00001111) * 4) as usize;
    let dscp = packet.data[1 + offset];
    let ttl = packet.data[8 + offset];
    let l4 = packet.data[9 + offset];
    // Use offset to change between source and dest IP Addr
    let mut addr_offset = offset + 12;
    let saddr = analysis::ipv4::IPv4Addr::from_u32(
        ((packet.data[addr_offset + 0] as u32) << 24) + 
        ((packet.data[addr_offset + 1] as u32) << 16) +
        ((packet.data[addr_offset + 2] as u32) << 8) +
        ((packet.data[addr_offset + 3] as u32) << 0) 
    );
    addr_offset += 4;
    let daddr = analysis::ipv4::IPv4Addr::from_u32(
        ((packet.data[addr_offset + 0] as u32) << 24) + 
        ((packet.data[addr_offset + 1] as u32) << 16) +
        ((packet.data[addr_offset + 2] as u32) << 8) +
        ((packet.data[addr_offset + 3] as u32) << 0) 
    );
    // How we ignore SSH
    format!("IPv4: {} -> {} (TTL: {}, DSCP: {}) {{\n{}\n}}", saddr, daddr, ttl, dscp, indent(handle_l4(packet, l4, header_length_bytes + offset), 1))
}

fn handle_ipv6(packet: pcap::Packet, offset: usize) -> String{
    if (packet.data[0 + offset] >> 4) != 0x6 {
        return format!("Invalid IPv6")
    }
    let l4 = packet.data[6 + offset];
    let ttl = packet.data[7 + offset];
    let addr_offset = offset + 8; // Saddr
    let saddr = analysis::ipv6::IPv6Addr::from_u8((&packet.data[addr_offset..addr_offset + 16]));
    let daddr = analysis::ipv6::IPv6Addr::from_u8((&packet.data[addr_offset + 128/8..addr_offset + 16 + 128/8]));
    let header_length_bytes = 40;
    format!("IPv6: {} -> {} (TTL: {}) {{\n{}\n}}", saddr, daddr, ttl, indent(handle_l4(packet, l4, header_length_bytes + offset), 1))
}

fn handle_arp(packet: pcap::Packet, offset: usize) -> String {
    let hardware_type = match (packet.data[0 + offset] as u16) << 8 | packet.data[1 + offset] as u16 {
        0x0001 => "Ethernet",
        _ => "Unknown"
    };
    let proto_type = match (packet.data[2 + offset] as u16) << 8 | packet.data[3 + offset] as u16 {
        0x0800 => "IPv4",
        _ => "Unknown"
    };
    let hardware_size = packet.data[4 + offset] as usize;
    let protocol_size = packet.data[5 + offset] as usize;
    let opcode = match ((packet.data[6 + offset] as u16) << 8) + packet.data[7 + offset] as u16 {
        0x01 => "ARP Request",
        0x02 => "ARP Reply",
        _ => "Unknown Opcode"
    };

    // We don't know how to analyze anything else.
    if hardware_type != "Ethernet" && proto_type != "IPv4" {
        return format!("ARP: Hardware Type: {}, Protocol: {}, Opcode: {}", hardware_type, proto_type, opcode);
    }
    let sender_mac_end: usize = 8 + offset + hardware_size;
    let sender_ip_end = sender_mac_end + protocol_size;

    let target_mac_end: usize = sender_ip_end + hardware_size;
    let target_ip_end = target_mac_end  + protocol_size;


    let sender_mac = &packet.data[8 + offset..sender_mac_end].iter().fold(String::new(), |mut res, sec| { res.push_str(&format!("{:x}", sec)); res });
    let target_mac = &packet.data[sender_ip_end..target_mac_end].iter().fold(String::new(), |mut res, sec| { res.push_str(&format!("{:x}", sec)); res });

    let sender_ip = analysis::ipv4::IPv4Addr::from_u8(&packet.data[sender_mac_end..sender_ip_end]);
    let target_ip = analysis::ipv4::IPv4Addr::from_u8(&packet.data[target_mac_end..target_ip_end]);
    format!("ARP: Protocol: {}, Opcode: {} {{\n\tSender: ({}, {})\n\tTarget: ({}, {})\n}}", proto_type, opcode, sender_mac, sender_ip, target_mac, target_ip)
}

fn handle_pad(packet: pcap::Packet, offset: usize) -> String {
    let code = packet.data[1 + offset];
    let code_name = match code {
        0x09 => "Discovery Initiation",
        0x07 => "Discovery Offer",
        0x19 => "Discovery Request",
        0x65 => "Discovery Session Confirmation",
        _ => "Unknown Type"
    };
    let session_id: u16 = ((packet.data[2 + offset] as u16) << 8) | packet.data[3 + offset] as u16;
    let plength_index = 4;
    let payload_length: usize = ((packet.data[4 + offset] as usize) << 8) | packet.data[5 + offset] as usize;
    let mut tlv_offset: usize = offset + 6;

    // We have a tag section
    let mut tlvs = format!("");
    // Initialize a tag hashmap
    let mut tags = std::collections::HashMap::new();
    // Keep going through TLVs
    while tlv_offset < offset + plength_index + payload_length {
        let tlv_type: u16 = ((packet.data[tlv_offset + 0] as u16) << 8) | packet.data[tlv_offset + 1] as u16;
        let tlv_length: usize = ((packet.data[tlv_offset + 2] as usize) << 8) | packet.data[tlv_offset + 3] as usize;
        match tlv_type {
            0x0101 => tags.insert("Service Name", std::str::from_utf8(&packet.data[tlv_offset + 4..tlv_offset + 4 + tlv_length]).unwrap_or("Unknown")),
            0x0102 => tags.insert("AC-Name", std::str::from_utf8(&packet.data[tlv_offset + 4..tlv_offset + 4 + tlv_length]).unwrap_or("Unknown")),
            _ => std::option::Option::None
        };
        tlv_offset += tlv_length + 4;

    }
    for (tag, value) in &tags {
        tlvs.push_str(&format!("{}: {}\n", tag, value));
    }

    format!("PPPoE discovery (Code: {}, Session ID: {:#x}) {{\n{}}}", code_name, session_id, indent(tlvs, 1))
}

fn handle_pas(packet: pcap::Packet, offset: usize) -> String {
    let code = packet.data[1 + offset];
    let session_id: u16 = ((packet.data[2 + offset] as u16) << 8) | packet.data[3 + offset] as u16;
    let output = match code {
        0x00 /* session data */ => handle_ppp(packet, 6 + offset),
        _ => format!("")
    };
    format!("PPPoE session (Code: {}, Session ID: {:#x}) {{\n{}\n}}", code, session_id, indent(output, 1))
}

fn handle_ppp(packet: pcap::Packet, offset: usize) -> String {
    let proto = ((packet.data[offset + 0] as u16) << 8) | packet.data[offset + 1] as u16;
    let output = match proto {
        0x0057 => handle_ipv6(packet, offset + 2),
        0x0021 => handle_ipv4(packet, offset + 2),
        0x0281 => handle_mpls(packet, offset + 2),
        0xC021 => handle_lcp(packet, offset + 2),
        0x8021 => format!("IP Control Protocol"),
        0x8057 => format!("IPv6 Control Protocol"),
        0xC023 => handle_pap(packet, offset + 2),
        0xC227 => format!("EAP Authentication"),
        0xC223 => format!("CHAP Authentication"),
        _ => format!("Unknown PPP Subprotocol"),
    };
    format!("PPP (Protocol: {:#x}) {{\n{}}}", proto, indent(output, 1))
}

fn handle_lcp(packet: pcap::Packet, offset: usize) -> String {
    let code = match packet.data[offset + 0] {
        1 => "Configure-Request",
        2 => "Configure-Ack",
        3 => "Configure-Nack",
        4 => "Configure-Reject",
        5 => "Terminate-Request",
        6 => "Terminate-Ack",
        7 => "Code-Reject",
        8 => "Protocol-Reject",
        9 => "Echo-Request",
        10 => "Echo-Reply",
        11 => "Discard-Request",
        _ => "Unknown",
    };
    format!("LCP (Code: {})", code)
}

// So long as the password is in plain text, may as well just show it...
fn handle_pap(packet: pcap::Packet, offset: usize) -> String {
    let code = packet.data[offset + 0];
    // Authentication Request
    if code == 1 {
        let _id = packet.data[offset + 1];
        let _length = (packet.data[offset + 2] as u16) << 8 | packet.data[offset + 3] as u16;
        // Note that this length includes the two preceding bytes and itself at 2 bytes.
        let username_length: usize = packet.data[offset + 4] as usize;
        let username_index = offset + 5;
        let username = std::str::from_utf8(&packet.data[username_index..username_index + username_length]).unwrap_or("Unknown");

        let password_length_index = username_index + username_length;
        let password_length: usize = packet.data[password_length_index] as usize;
        let password = std::str::from_utf8(&packet.data[password_length_index + 1..password_length_index + 1 + password_length]).unwrap_or("Unknown");
        format!("PAP (Username: {}, Password: {})", username, password)
    } else {
        format!("PAP")
    }
}

fn handle_lldp(_: pcap::Packet, _offset: usize) -> String {
    format!("LLDP")
}

// ========== Layer 4 ==========
fn handle_l4(packet: pcap::Packet, l4protocol: u8, offset: usize) -> String {
    match l4protocol {
        0x3a => handle_icmpv6(packet, offset),
        0x01 => handle_icmp(packet, offset),
        0x06 => handle_tcp(packet, offset),
        0x11 => handle_udp(packet, offset),
        _ => {format!("")}
    }
}

fn handle_tcp(packet: pcap::Packet, offset: usize) -> String {
    let sport: u16 = ((packet.data[0x0 + offset as usize] as u16) << 8) + packet.data[0x1 + offset as usize] as u16;
    let dport: u16 = ((packet.data[0x2 + offset as usize] as u16) << 8) + packet.data[0x3 + offset as usize] as u16;
    let flags: u16 = ((packet.data[20 + offset as usize] as u16) << 8) + packet.data[21 + offset as usize] as u16;
    let syn = (flags & 0b000000000010) > 0;
    let ack = (flags & 0b000000001000) > 0;
    let fin = (flags & 0b000000000001) > 0;
    let mut flag_string = String::new();
    if syn { flag_string.push_str(" SYN"); }
    if ack { flag_string.push_str(" ACK"); }
    if fin { flag_string.push_str(" FIN"); }

    format!("TCP {} -> {} (Flags:{})", sport, dport, flag_string)
}

fn handle_udp(packet: pcap::Packet, offset: usize) -> String {
    let sport: u16 = ((packet.data[0x0 + offset as usize] as u16) << 8) + packet.data[0x1 + offset as usize] as u16;
    let dport: u16 = ((packet.data[0x2 + offset as usize] as u16) << 8) + packet.data[0x3 + offset as usize] as u16;
    format!("UDP {} -> {}", sport, dport)
}

fn handle_icmpv6(packet: pcap::Packet, offset: usize) -> String {
    let icmp_type = packet.data[0x0 + offset as usize];
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

fn handle_icmp(packet: pcap::Packet, offset: usize) -> String {
    let icmp_type = packet.data[0x0 + offset as usize];
    let icmp_type_string = match icmp_type {
        0 => "Echo Reply",
        8 => "Echo Request",
        3 => "Destination Unreachable",
        11 => "TTL Exceeded",
        _ => "",
    };
    let icmp_code = packet.data[0x1 + offset as usize];
    format!("ICMP (Type: {}, Code: {})", icmp_type_string, icmp_code)
}

// ========== Helpers ==========


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

fn prompt_for_filters(filter: &mut Vec<analysis::filters::Filter>) {
    //let mut filter = Vec::<analysis::filters::Filter>::new();
	println!();
    let mut input_str = String::new();
    let mut done = false;

	while !done {
        println!();
        let word = match filter.len() {
            0 => "a filter",
            _ => "another filter"
        };
        print!("Enter {}? (y / N): ", word);
        std::io::stdout().flush().ok().expect("Could not flush stdout");
        input_str.clear();
        std::io::stdin().read_line(&mut input_str).expect("Could not read line");
        match input_str.to_lowercase().chars().next().unwrap_or('n') {
            'y' => {
                print!("IPv4/IPv6 (IPv4): ");
                std::io::stdout().flush().ok().expect("Could not flush stdout");
                input_str.clear();
                std::io::stdin().read_line(&mut input_str).expect("Could not read line");
                let l3 = match input_str.trim().to_lowercase().as_str() {
                    "ipv6" => 0x86DD,
                        _ => 0x0800
                };

                print!("Port # (0-65535): ");
                std::io::stdout().flush().ok().expect("Could not flush stdout");
                input_str.clear();
                std::io::stdin().read_line(&mut input_str).expect("Could not read line");
                let port = input_str.trim().to_lowercase().parse::<u16>().unwrap_or(0);

                print!("TCP/UDP (TCP): ");
                std::io::stdout().flush().ok().expect("Could not flush stdout");
                input_str.clear();
                std::io::stdin().read_line(&mut input_str).expect("Could not read line");
                let fil = match input_str.trim().to_lowercase().as_str() {
                    "udp" => analysis::filters::Filter::new(l3, analysis::filters::L4Filter::UDP(port)),
                        _ => analysis::filters::Filter::new(l3, analysis::filters::L4Filter::TCP(port)),
                };
                filter.push(fil);
            }
            _ => { 
                done = true;
            }
        };
	}
}

fn indent(input: String, index: usize) -> String{
    input.lines().fold(String::new(), |mut res, sec| {
        for _ in 0..index {
            res += "\t";
        }
        res += sec;
        res += "\n";
        res
    })
}

fn print_header() {
    println!("    ___       ___       ___       ___       ___   ");
    println!("   /\\  \\     /\\  \\     /\\  \\     /\\  \\     /\\  \\   ");
    println!("  /::\\  \\   /\\:\\  \\   /::\\  \\   /::\\  \\   /::\\  \\   ");
    println!(" /:/\\:\\__\\ /::\\:\\__\\ /:/\\:\\__\\ /::\\:\\__\\ /::\\:\\__\\");
    println!(" \\:\\/:/  / \\:\\::/__/ \\:\\ \\/__/ \\/\\::/  / \\/\\::/  /");
    println!("  \\::/  /   \\:\\/_\\    \\:\\__\\     /:/  /     \\/__/ ");
    println!("   \\/__/     \\/__/     \\/__/     \\/__/             ");
    for _ in 1..5 { println!(""); }
    println!("O2Cap | Oxidized Packet Capture");
    for _ in 1..5 { println!(""); }
}


