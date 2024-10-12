use sideway::cm::communication_manager::{ConnectionParameter, EventChannel, PortSpace};
use sideway::verbs::queue_pair::{QueuePair, QueuePairAttribute, QueuePairState};
use sideway::verbs::AccessFlags;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use clap::Parser;

#[derive(Debug, Parser)]
#[clap(name = "cmtime", version = "0.1.0")]
pub struct Args {
    /// Listen on / connect to port
    #[clap(long, short = 'p', default_value_t = 18515)]
    port: u16,
    /// Bind address
    #[clap(long, short = 'b')]
    bind_address: Option<String>,
    /// If no value provided, start a server and wait for connection, otherwise, connect to server at [host]
    #[clap(long, short = 's')]
    server_address: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut channel = EventChannel::new()?;

    let id = channel.create_id(PortSpace::Tcp)?;

    if args.server_address.is_some() {
        let ip = IpAddr::from_str(&args.server_address.unwrap()).expect("Invalid IP address");
        let server_addr = SocketAddr::from((ip, args.port));

        let ip = IpAddr::from_str(&args.bind_address.unwrap()).expect("Invalid IP address");
        let client_addr = SocketAddr::from((ip, 0));

        id.resolve_addr(Some(client_addr), Some(server_addr), 2000)?;

        let event = channel.get_cm_event()?;
        println!("Event is {:?}", event.event_type());

        id.resolve_route(2000)?;

        let event = channel.get_cm_event()?;
        println!("Event is {:?}", event.event_type());

        let context = id.get_device_context()?;

        let pd = context.alloc_pd().unwrap_or_else(|_| panic!("Couldn't allocate PD"));

        let cq = context.create_cq_builder().setup_cqe(1).build().unwrap();

        let mut builder = pd.create_qp_builder();

        let mut qp = builder
            .setup_max_inline_data(0)
            .setup_send_cq(&cq)
            .setup_recv_cq(&cq)
            .setup_max_send_wr(1)
            .setup_max_recv_wr(1)
            .build()
            .unwrap_or_else(|_| panic!("Couldn't create QP"));

        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::Init)
            .setup_pkey_index(0)
            .setup_port(1)
            .setup_access_flags(AccessFlags::LocalWrite | AccessFlags::RemoteWrite);
        qp.modify(&attr).unwrap();

        let mut conn_param = ConnectionParameter::new();
        conn_param.setup_qp_number(qp.qp_number());

        id.connect(&mut conn_param).unwrap();

        let event = channel.get_cm_event()?;

        println!("Event is {:?}, status {}", event.event_type(), event.status());
        // event.ack()?;

        let attr = id.get_qp_attr()?;
        qp.modify(&attr).unwrap();

        let attr = id.get_qp_attr()?;
        qp.modify(&attr).unwrap();

        id.establish()?;
    } else {
        id.bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), args.port))?;

        id.listen(1024)?;

        let event = channel.get_cm_event()?;

        println!("Event is {:?}", event.event_type());

        let new_id = event.cm_id().unwrap();

        let context = new_id.get_device_context()?;

        let pd = context.alloc_pd().unwrap_or_else(|_| panic!("Couldn't allocate PD"));

        let cq = context.create_cq_builder().setup_cqe(1).build().unwrap();

        let mut builder = pd.create_qp_builder();

        let mut qp = builder
            .setup_max_inline_data(0)
            .setup_send_cq(&cq)
            .setup_recv_cq(&cq)
            .setup_max_send_wr(1)
            .setup_max_recv_wr(1)
            .build()
            .unwrap_or_else(|_| panic!("Couldn't create QP"));

        let attr = new_id.get_qp_attr()?;
        qp.modify(&attr).unwrap();

        let attr = new_id.get_qp_attr()?;
        qp.modify(&attr).unwrap();

        let attr = new_id.get_qp_attr()?;
        qp.modify(&attr).unwrap();

        let mut conn_param = ConnectionParameter::new();
        conn_param.setup_qp_number(qp.qp_number());

        new_id.accept(&mut conn_param).unwrap();

        let event = channel.get_cm_event()?;

        println!("Event is {:?}, status {}", event.event_type(), event.status());
        event.ack()?;
    }

    Ok(())
}
