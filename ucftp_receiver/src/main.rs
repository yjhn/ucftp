use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;

const RECEIVER_PORT: u16 = 4321;
const UDP_HEADER_SIZE: u16 = 8;
// This assumes no IP options are used
const IP4_HEADER_SIZE: u16 = 20;
const MAX_PACKET_SIZE: u16 = 1518;

fn main() {
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RECEIVER_PORT))
        .expect("Failed to bind to port 4321");

    let mut packet = [0u8; MAX_PACKET_SIZE as usize];
    eprintln!("Listening on {}:{}", Ipv4Addr::UNSPECIFIED, RECEIVER_PORT);
    match sock.recv_from(&mut packet) {
        Ok((len, addr)) => {
            println!("{}", addr);
            assert!(packet[0..len].iter().all(|x| *x == 8));
        }
        Err(_) => todo!(),
    }
}
