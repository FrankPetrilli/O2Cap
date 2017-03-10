use std::fmt;


pub struct IPv4Addr {
	value: u32
}

pub struct IPv4Mask {
	value: u32
}

impl fmt::Display for IPv4Mask {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let val = 32 - self.value.trailing_zeros();
		write!(f, "/{}", val)
	}
}

impl IPv4Mask {
	pub fn new(input: u8) -> IPv4Mask {
		let mut val : u32 = 0;
		if input > 32 {
			// TODO: Fail
		}
		for i in 0..32 {
			val = val << 1;
			if i < input { val += 1; } 
		}
		return IPv4Mask { value: val };
	}
	pub fn as_ip(&self) -> IPv4Addr {
		IPv4Addr { value: self.value }
	}
}

impl fmt::Display for IPv4Addr {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let section1 = self.value >> 24 & 0xFF;
		let section2 = self.value >> 16 & 0xFF;
		let section3 = self.value >> 8 & 0xFF;
		let section4 = self.value >> 0 & 0xFF;
		write!(f, "{}.{}.{}.{}", section1, section2, section3, section4)
	}
}
impl IPv4Addr {
	pub fn new(input: &str) -> IPv4Addr {
		let mut split = input.split(".");
		let val = (split.nth(0).unwrap().parse::<u32>().unwrap() << 24) |
			(split.nth(0).unwrap().parse::<u32>().unwrap() << 16) |
			(split.nth(0).unwrap().parse::<u32>().unwrap() << 8) |
			(split.nth(0).unwrap().parse::<u32>().unwrap() << 0);
		return IPv4Addr { value: val };
	}
    pub fn from_u32(input: u32) -> IPv4Addr {
        IPv4Addr { value: input }
    }
    pub fn from_u8(input: &[u8]) -> IPv4Addr {
        let val = (input[0] as u32) << 24 |
             (input[1] as u32) << 16 |
             (input[2] as u32) << 8 |
             (input[3] as u32) << 0;
        IPv4Addr { value: val }
    }
	pub fn get_network(&self, mask: &IPv4Mask) -> IPv4Addr {
		IPv4Addr { value: self.value & mask.value }
	}
	pub fn get_hosts(&self, mask: &IPv4Mask) -> (IPv4Addr, IPv4Addr, IPv4Addr, u32) {
		let net = self.get_network(&mask);
		let broadcast = IPv4Addr { value: (self.value | (mask.value ^ 0xFFFFFFFF)) };
		let max_host = IPv4Addr { value: broadcast.value - 1 };
		let count = max_host.value - net.value;
		(IPv4Addr { value: net.value + 1 }, max_host, broadcast, count)
	}
}
