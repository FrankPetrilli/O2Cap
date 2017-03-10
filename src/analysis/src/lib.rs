#![feature(i128_type)]

pub mod ipv4;
pub mod ipv6;
pub mod ether;
pub mod filters;

#[test]
fn construct_ipv4() {
    let addr = ipv4::IPv4Addr::from_u8(&[192, 168, 0, 0]);
    assert_eq!(format!("{}", addr), "192.168.0.0");
}

