use std::fmt;


pub struct IPv6Addr {
	value: u128
}

pub struct IPv6Mask {
	value: u128
}

impl fmt::Display for IPv6Mask {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let val = 128 - self.value.trailing_zeros();
		write!(f, "/{}", val)
	}
}

impl IPv6Mask {
	pub fn new(input: u8) -> IPv6Mask {
		let mut val : u128 = 0;
		if input > 128 {
			// TODO: Fail
		}
		for i in 0..128 {
			val = val << 1;
			if i < input { val += 1; } 
		}
		return IPv6Mask { value: val };
	}
	pub fn as_ip(&self) -> IPv6Addr {
		IPv6Addr { value: self.value }
	}
}

impl fmt::Display for IPv6Addr {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let mut result = Vec::new();
		for i in 1..(128/4 + 1) {
			let section = self.value >> (128 - i * 4) & 0xF;
			result.push(section)
		}
		let mut num_placed = 0;
		let as_str = result.iter().fold(String::new(), |mut res, sec| { 
			let char = format!("{:x}", sec);
			let char_str = char.as_str();
			res.push_str(char_str);
			num_placed += 1;
			if num_placed % 4 == 0 && num_placed < 128 / 4 {
				res.push_str(":");
			}
			res
		});
		write!(f, "{}", as_str)
	}
}
impl IPv6Addr {
	pub fn new(input: &str) -> IPv6Addr {
		// Remove the colons.
		let split = input.split(":").fold(String::new(), |mut res, sec| { 
			res.push_str(sec); res
		});
		let mut val : u128 = 0;
		// For each character, parse it as hex, shift the val, add the char
		for char in split.chars() {
			let mut num: u128 = 0;
			let mut s = String::new();
			s.push(char);
			match u128::from_str_radix(&s, 16) {
				Err(_) => println!("Error has occurred: {}", char),
				Ok(a) => num = a
			}
			val = val << 4;
			val += num;
		}
		return IPv6Addr { value: val };
	}
    pub fn from_u128(input: u128) -> IPv6Addr {
        IPv6Addr { value: input }
    }
    pub fn from_u8(input: &[u8]) -> IPv6Addr {
        let init: u128 = 0;
        let mut byte_index = 0;
        let val = input.iter().fold(init, |mut res, byte| { 
            res += (*byte as u128) << ((15 - byte_index) * 8);
            byte_index += 1;
            res
        });
        IPv6Addr::from_u128(val)
    }
	pub fn get_network(&self, mask: &IPv6Mask) -> IPv6Addr {
		IPv6Addr { value: self.value & mask.value }
	}
	pub fn get_hosts(&self, mask: &IPv6Mask) -> (IPv6Addr, IPv6Addr, IPv6Addr, u128) {
		let net = self.get_network(&mask);
		let broadcast = IPv6Addr { value: (self.value | (mask.value ^ 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)) };
		let max_host = IPv6Addr { value: broadcast.value - 1 };
		let count = max_host.value - net.value;
		(IPv6Addr { value: net.value + 1 }, max_host, broadcast, count)
	}
}
