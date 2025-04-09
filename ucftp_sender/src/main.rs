use clap::Parser;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;

mod arguments;

const RECEIVER_PORT: u16 = 4321;
const UDP_HEADER_SIZE: u16 = 8;
const IP4_HEADER_SIZE: u16 = 20;
const SAFE_IP4_PACKET_SIZE: u16 = 1280 - IP4_HEADER_SIZE - UDP_HEADER_SIZE;

fn main() {
    let args = arguments::Cli::parse();
    dbg!(args);

    let mut rng = SmallRng::from_os_rng();

    let sock = loop {
        let port: u16 = rng.random_range(1024..=u16::MAX);
        match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)) {
            Ok(sock) => {
                eprintln!("Bound to: {}:{}", Ipv4Addr::UNSPECIFIED, port);
                break sock;
            }
            Err(_) => continue,
        }
    };

    let packet = [8u8; SAFE_IP4_PACKET_SIZE as usize];
    sock.send_to(
        &packet,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, RECEIVER_PORT),
    )
    .unwrap();
}
