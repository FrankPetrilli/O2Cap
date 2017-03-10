extern crate pcap;

pub struct Filter {
    l3proto: u16, // Filter on EtherType
    l4proto: L4Proto,
}

enum L4Proto {
    TCP ( u16, u16 ),
    UDP ( u16, u16 ),
}

pub enum L4Filter {
    TCP (u16),
    UDP (u16),
}

impl Filter {

    pub fn new(l3proto: u16, l4filter: L4Filter) -> Filter {
        let internal_proto = match l4filter {
            L4Filter::TCP(port) => {
                L4Proto::TCP (port, port)
            },
            L4Filter::UDP(port) => {
                L4Proto::UDP (port, port)
            }
        };
        Filter { l3proto: l3proto, l4proto: internal_proto}
    }

    pub fn matches(&self, packet: &pcap::Packet) -> bool {
        let etype_1 = 12 as usize;
        let etype_2 = 13 as usize;
        let etype = (packet.data[etype_1] as u16) << 8 | packet.data[etype_2] as u16;
        // Check l3proto
        if etype != self.l3proto { 
            return false;
        }
        // Check port, work with variable-length v4 packet -.-
        let proto = match etype {
            0x0800 => match extract_ipv4(&packet, 14) {
                Ok(proto) => proto,
                Err(_) => { return false; }
            },
            0x86dd => match extract_ipv6(&packet, 14) {
                Ok(proto) => proto,
                Err(_) => { return false; }
            },
            _ => return false
        };
        match self.l4proto {
            L4Proto::TCP(_spt, port) => {
                match proto {
                    L4Proto::TCP(obs_spt, obs_dpt) => {
                        return obs_spt == port || obs_dpt == port;
                    },
                    L4Proto::UDP(_obs_spt, _obs_dpt) => {
                        return false;
                    }
                }
            },
            L4Proto::UDP(_spt, port) => {
                match proto {
                    L4Proto::TCP(_obs_spt, _obs_dpt) => {
                        return false;
                    },
                    L4Proto::UDP(obs_spt, obs_dpt) => {
                        return obs_spt == port || obs_dpt == port;
                    }
                }
            },
        };
    }
}

enum ExtractError {
    WrongVersion,
    UnknownProtocol,
}

// Will return the port number and protocol
fn extract_ipv4(packet: &pcap::Packet, offset: usize) -> Result<L4Proto, ExtractError> {
    if (packet.data[0 + offset] >> 4) != 0x4 {
        return Err(ExtractError::WrongVersion);
    }
    let header_length_bytes: usize = ((packet.data[0 + offset] & 0b00001111) * 4) as usize;
    // Change on L4 Protocol
    match packet.data[9 + offset] {
        0x06 => {
            let sport: u16 = ((packet.data[0x0 + offset + header_length_bytes as usize] as u16) << 8) + packet.data[0x1 + offset + header_length_bytes as usize] as u16;
            let dport: u16 = ((packet.data[0x2 + offset + header_length_bytes as usize] as u16) << 8) + packet.data[0x3 + offset + header_length_bytes as usize] as u16;
            Ok(L4Proto::TCP ( sport, dport ))
        },
        0x11 => {
            let sport: u16 = ((packet.data[0x0 + offset + header_length_bytes as usize] as u16) << 8) + packet.data[0x1 + offset + header_length_bytes as usize] as u16;
            let dport: u16 = ((packet.data[0x2 + offset + header_length_bytes as usize] as u16) << 8) + packet.data[0x3 + offset + header_length_bytes as usize] as u16;
            Ok(L4Proto::UDP ( sport, dport ))
        },
        _ => Err(ExtractError::UnknownProtocol),
    }
}

// Will return the port number and protocol
fn extract_ipv6(packet: &pcap::Packet, offset: usize) -> Result<L4Proto, ExtractError> {
    if (packet.data[0 + offset] >> 4) != 0x6 {
        return Err(ExtractError::WrongVersion);
    }
    let header_length_bytes = 40;
    // Change on L4 Protocol
    match packet.data[6 + offset] {
        0x06 => {
            let sport: u16 = ((packet.data[0x0 + offset + header_length_bytes as usize] as u16) << 8) + packet.data[0x1 + offset + header_length_bytes as usize] as u16;
            let dport: u16 = ((packet.data[0x2 + offset + header_length_bytes as usize] as u16) << 8) + packet.data[0x3 + offset + header_length_bytes as usize] as u16;
            Ok(L4Proto::TCP ( sport, dport ))
        },
        0x11 => {
            let sport: u16 = ((packet.data[0x0 + offset + header_length_bytes as usize] as u16) << 8) + packet.data[0x1 + offset + header_length_bytes as usize] as u16;
            let dport: u16 = ((packet.data[0x2 + offset + header_length_bytes as usize] as u16) << 8) + packet.data[0x3 + offset + header_length_bytes as usize] as u16;
            Ok(L4Proto::UDP ( sport, dport ))
        },
        _ => Err(ExtractError::UnknownProtocol),
    }
}

