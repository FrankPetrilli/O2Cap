use std::fmt;

pub struct MACAddr {
	value: u64
}

impl fmt::Display for MACAddr {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        for i in 0..6 {
            output.push_str(&format!("{:X}{}", self.value >> (40 - (i * 8)) & 0xFF, if i != 5 { ":" } else { "" }));
        }
		write!(f, "{}", output)
	}
}
impl MACAddr {
    pub fn from_u64(input: u64) -> MACAddr {
        MACAddr { value: input }
    }
    pub fn from_u8(input: &[u8]) -> MACAddr {
        let value = (input[0] as u64) << 40 |
            (input[1] as u64) << 32 |
            (input[2] as u64) << 24 |
            (input[3] as u64) << 16 |
            (input[4] as u64) << 8 |
            (input[5] as u64) << 0;
        MACAddr::from_u64(value)
    }
}
