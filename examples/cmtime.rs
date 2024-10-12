use std::{net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4}, ptr::null_mut};

use sideway::cm::communication_manager::{EventChannel, CommunicationManager, PortSpace};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut channel = EventChannel::new()?;

    let mut id = channel.create_id(PortSpace::Tcp)?;

    id.bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 18515))?;

    Ok(())
}
