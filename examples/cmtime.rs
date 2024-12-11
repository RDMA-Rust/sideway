#![allow(static_mut_refs)]

use sideway::cm::communication_manager::{ConnectionParameter, Event, EventChannel, Identifier, PortSpace};
use sideway::verbs::completion::GenericCompletionQueue;
use sideway::verbs::device_context::DeviceContext;
use sideway::verbs::protection_domain::ProtectionDomain;
use sideway::verbs::queue_pair::{GenericQueuePair, QueuePair, QueuePairState};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::Duration;
use tabled::settings::object::Columns;

use clap::Parser;
use lazy_static::lazy_static;
use quanta::Instant;
use tabled::{
    settings::{object::Segment, Alignment, Modify, Style},
    Table, Tabled,
};

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
    // Use self-created, self-modified QP
    #[arg(long, short = 'q', default_value_t = false)]
    self_modify: bool,
    // Number of connections
    #[arg(long, short = 'c', default_value_t = 100)]
    connections: u32,
}

#[repr(usize)]
#[derive(Debug)]
pub enum Step {
    CreateId,
    Bind,
    ResolveAddr,
    ResolveRoute,
    CreateQueuePair,
    Connect,
    ModifyToInit,
    ModifyToRTR,
    ModifyToRTS,
    Disconnect,
    Destroy,
    Count,
}

static mut CTX: Option<Arc<DeviceContext>> = None;
static mut PD: Option<Arc<ProtectionDomain>> = None;
static mut CQ: Option<Arc<GenericCompletionQueue>> = None;

static OPEN_VERBS: Once = Once::new();

struct Node<'a> {
    id: Option<Arc<Identifier>>,
    qp: Option<GenericQueuePair<'a>>,
    times: [(Instant, Instant); Step::Count as usize],
}

#[derive(Tabled)]
struct StageResult {
    #[tabled(rename = "Step")]
    stage: String,
    #[tabled(rename = "Total (ms)", format = "{:.2}")]
    total: f64,
    #[tabled(rename = "Max (us)", format = "{:.2}")]
    max: f64,
    #[tabled(rename = "Min (us)", format = "{:.2}")]
    min: f64,
}

lazy_static! {
    static ref STARTED: [AtomicU32; Step::Count as usize] = [const { AtomicU32::new(0) }; Step::Count as usize];
    static ref COMPLETED: [AtomicU32; Step::Count as usize] = [const { AtomicU32::new(0) }; Step::Count as usize];
    static ref TIMES: Mutex<[(Instant, Instant); Step::Count as usize]> =
        Mutex::new([(Instant::recent(), Instant::recent()); Step::Count as usize]);
    static ref CHANNEL: Mutex<EventChannel> =
        Mutex::new(EventChannel::new().expect("Failed to create rdma cm event channel"));
    static ref NODE_IDX: AtomicU32 = AtomicU32::new(0);
}

macro_rules! start_perf {
    ($node:expr, $step:expr) => {{
        $node.lock().unwrap().times[$step as usize].0 = Instant::now();
    }};
}

macro_rules! end_perf {
    ($node:expr, $step:expr) => {{
        $node.lock().unwrap().times[$step as usize].1 = Instant::now();
    }};
}

macro_rules! start_time {
    ($step:expr) => {{
        {
            let mut times = TIMES.lock().unwrap();
            times[$step as usize].0 = Instant::now();
        }
    }};
}

macro_rules! end_time {
    ($step:expr, $results:expr, $nodes:expr) => {{
        {
            let mut times = TIMES.lock().unwrap();
            times[$step as usize].1 = Instant::now();

            // Calculate min/max from individual node times
            let mut max_us = 0.0f64;
            let mut min_us = f64::MAX;

            for node in $nodes {
                let node = node.lock().unwrap();
                let duration = node.times[$step as usize]
                    .1
                    .duration_since(node.times[$step as usize].0)
                    .as_secs_f64()
                    * 1_000_000.0; // Convert to microseconds

                max_us = max_us.max(duration);
                min_us = min_us.min(duration);
            }

            // Handle case where no valid measurements exist
            if min_us == f64::MAX {
                min_us = 0.0;
            }

            $results.push(StageResult {
                stage: format!("{:?}", $step),
                total: times[$step as usize]
                    .1
                    .duration_since(times[$step as usize].0)
                    .as_secs_f64()
                    * 1000.0, // Keep total in milliseconds
                max: max_us,
                min: min_us,
            });
        }
    }};
}

fn cma_handler(
    id: Arc<Identifier>, event: Event, resp_wq: Option<Sender<Arc<Identifier>>>,
    req_wq: Option<Sender<Arc<Identifier>>>, disc_wq: Option<Sender<Arc<Identifier>>>,
) {
    use sideway::cm::communication_manager::EventType::*;
    let node: Option<Arc<Mutex<Node>>> = id.get_context();

    match event.event_type() {
        AddressResolved => {
            end_perf!(node.unwrap(), Step::ResolveAddr);
            COMPLETED[Step::ResolveAddr as usize].fetch_add(1, Ordering::Relaxed);
        },
        RouteResolved => {
            end_perf!(node.unwrap(), Step::ResolveRoute);
            COMPLETED[Step::ResolveRoute as usize].fetch_add(1, Ordering::Relaxed);
        },
        ConnectRequest => {
            let cm_id = event.cm_id().clone().unwrap();
            OPEN_VERBS.call_once(|| unsafe {
                CTX = Some(cm_id.get_device_context().unwrap().clone());
                PD = Some(Arc::new(CTX.as_ref().unwrap().alloc_pd().unwrap()));
                CQ = Some(Arc::new(
                    CTX.as_ref()
                        .unwrap()
                        .create_cq_builder()
                        .setup_cqe(1)
                        .build_ex()
                        .unwrap()
                        .into(),
                ));
            });
            req_wq.unwrap().send(cm_id).unwrap();
        },
        ConnectResponse => {
            if let Some(wq) = resp_wq {
                wq.send(id).unwrap();
            } else {
                end_perf!(node.unwrap(), Step::Connect);
            }
        },
        Established => {
            if let Some(node) = node {
                end_perf!(node, Step::Connect);
                COMPLETED[Step::Connect as usize].fetch_add(1, Ordering::Relaxed);
            }
        },
        Disconnected => {
            if let Some(wq) = disc_wq {
                wq.send(id).unwrap();
            } else {
                end_perf!(node.unwrap(), Step::Disconnect);
            }
            COMPLETED[Step::Disconnect as usize].fetch_add(1, Ordering::Relaxed);
        },
        AddressError => {
            println!("Event: {:?}, error: {}", event.event_type(), event.status());
        },
        ConnectError | Unreachable | Rejected => {
            println!("Event: {:?}, error: {}", event.event_type(), event.status());
        },
        TimewaitExit => {},
        _ => {
            println!("Other events: {:?}", event.event_type());
        },
    }
    let _ = event.ack();
}

impl Node<'_> {
    fn create_qp(&mut self) {
        unsafe {
            let pd = PD.as_ref().unwrap();
            let cq = CQ.as_ref().unwrap();

            let mut qp_builder = pd.create_qp_builder();

            qp_builder
                .setup_max_send_wr(1)
                .setup_max_send_sge(1)
                .setup_max_recv_wr(1)
                .setup_max_recv_sge(1)
                .setup_send_cq(cq.as_ref())
                .setup_recv_cq(cq.as_ref());

            let qp = qp_builder.build_ex().unwrap().into();

            self.qp = Some(qp);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut results: Vec<StageResult> = Vec::new();

    if args.server_address.is_some() {
        let (resp_tx, resp_rx) = channel();

        let _resp_handler = thread::spawn(move || loop {
            let cm_id: Arc<Identifier> = resp_rx.recv().expect("Failed to receive cm_id");

            let node: Arc<Mutex<Node>> = cm_id.get_context().unwrap();

            {
                let mut guard = node.lock().unwrap();
                let qp = guard.qp.as_mut().unwrap();

                let attr = cm_id.get_qp_attr(QueuePairState::Init).unwrap();
                qp.modify(&attr).unwrap();

                let attr = cm_id.get_qp_attr(QueuePairState::ReadyToReceive).unwrap();
                qp.modify(&attr).unwrap();

                let attr = cm_id.get_qp_attr(QueuePairState::ReadyToSend).unwrap();
                qp.modify(&attr).unwrap();

                cm_id.establish().unwrap();
            }

            end_perf!(node, Step::Connect);
            COMPLETED[Step::Connect as usize].fetch_add(1, Ordering::Relaxed);
        });

        let mut nodes = Vec::with_capacity(args.connections as usize);

        start_time!(Step::CreateId);
        for _i in 0..args.connections {
            let node = Mutex::new(Node {
                id: None,
                qp: None,
                times: [(Instant::recent(), Instant::recent()); Step::Count as usize],
            });
            start_perf!(node, Step::CreateId);
            let id = CHANNEL.lock().unwrap().create_id(PortSpace::Tcp)?;
            end_perf!(node, Step::CreateId);
            node.lock().unwrap().id = Some(id.clone());
            id.setup_context(node);
            let node: Arc<Mutex<Node>> = id.get_context().unwrap();
            nodes.push(node);
        }
        end_time!(Step::CreateId, results, &nodes);

        let _dispatcher = thread::spawn(move || loop {
            match CHANNEL.lock().unwrap().get_cm_event() {
                Ok(event) => cma_handler(event.cm_id().unwrap(), event, Some(resp_tx.clone()), None, None),
                Err(err) => {
                    eprintln!("{err}");
                    break;
                },
            }
        });

        let ip = IpAddr::from_str(&args.server_address.unwrap()).expect("Invalid IP address");
        let server_addr = SocketAddr::from((ip, args.port));

        let ip = IpAddr::from_str(&args.bind_address.unwrap()).expect("Invalid IP address");
        let client_addr = SocketAddr::from((ip, 0));

        start_time!(Step::ResolveAddr);
        for node in &nodes {
            start_perf!(node, Step::ResolveAddr);
            if let Some(ref id) = node.lock().unwrap().id {
                id.resolve_addr(Some(client_addr), server_addr, Duration::new(2, 0))?;
                STARTED[Step::ResolveAddr as usize].fetch_add(1, Ordering::Relaxed);
            }
        }

        while STARTED[Step::ResolveAddr as usize].load(Ordering::Acquire)
            != COMPLETED[Step::ResolveAddr as usize].load(Ordering::Acquire)
        {
            thread::yield_now();
        }
        end_time!(Step::ResolveAddr, results, &nodes);

        start_time!(Step::ResolveRoute);
        for node in &nodes {
            start_perf!(node, Step::ResolveRoute);
            if let Some(ref id) = node.lock().unwrap().id {
                id.resolve_route(Duration::new(2, 0))?;
                STARTED[Step::ResolveRoute as usize].fetch_add(1, Ordering::Relaxed);
            }
        }

        while STARTED[Step::ResolveRoute as usize].load(Ordering::Acquire)
            != COMPLETED[Step::ResolveRoute as usize].load(Ordering::Acquire)
        {
            thread::yield_now();
        }
        end_time!(Step::ResolveRoute, results, &nodes);

        start_time!(Step::CreateQueuePair);
        for node in &nodes {
            start_perf!(node, Step::CreateQueuePair);
            {
                let mut guard = node.lock().unwrap();
                if let Some(ref id) = guard.id {
                    OPEN_VERBS.call_once(|| unsafe {
                        CTX = Some(id.get_device_context().unwrap().clone());
                        PD = Some(Arc::new(CTX.as_ref().unwrap().alloc_pd().unwrap()));
                        CQ = Some(Arc::new(
                            CTX.as_ref()
                                .unwrap()
                                .create_cq_builder()
                                .setup_cqe(1)
                                .build_ex()
                                .unwrap()
                                .into(),
                        ));
                    });
                    guard.create_qp();
                }
            }
            end_perf!(node, Step::CreateQueuePair);
        }
        end_time!(Step::CreateQueuePair, results, &nodes);

        start_time!(Step::Connect);
        for node in &nodes {
            start_perf!(node, Step::Connect);
            let guard = node.lock().unwrap();
            if let Some(ref id) = guard.id {
                let qp = guard.qp.as_ref().unwrap();

                let mut conn_param = ConnectionParameter::default();
                conn_param.setup_qp_number(qp.qp_number());

                id.connect(conn_param)?;

                STARTED[Step::Connect as usize].fetch_add(1, Ordering::Relaxed);
            }
        }

        while STARTED[Step::Connect as usize].load(Ordering::Acquire)
            != COMPLETED[Step::Connect as usize].load(Ordering::Acquire)
        {
            thread::yield_now();
        }
        end_time!(Step::Connect, results, &nodes);

        start_time!(Step::Disconnect);
        for node in &nodes {
            start_perf!(node, Step::Disconnect);
            if let Some(ref id) = node.lock().unwrap().id {
                id.disconnect()?;
                STARTED[Step::Disconnect as usize].fetch_add(1, Ordering::Relaxed);
            }
        }

        while STARTED[Step::Disconnect as usize].load(Ordering::Acquire)
            != COMPLETED[Step::Disconnect as usize].load(Ordering::Acquire)
        {
            thread::yield_now();
        }
        end_time!(Step::Disconnect, results, &nodes);

        let style = Style::psql().remove_verticals();

        let table = Table::new(results)
            .with(Modify::new(Segment::all()).with(Alignment::right()))
            .with(style)
            .modify(Columns::first(), Alignment::left())
            .to_string();

        println!("{}", table);
    } else {
        let id = CHANNEL.lock().unwrap().create_id(PortSpace::Tcp)?;
        id.bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), args.port))?;
        id.listen(1024)?;

        let mut nodes = vec![None; args.connections as usize];

        let (req_tx, req_rx) = channel();
        let (disc_tx, disc_rx) = channel();

        let _dispatcher = thread::spawn(move || loop {
            match CHANNEL.lock().unwrap().get_cm_event() {
                Ok(event) => cma_handler(
                    event.cm_id().unwrap(),
                    event,
                    None,
                    Some(req_tx.clone()),
                    Some(disc_tx.clone()),
                ),
                Err(err) => {
                    eprintln!("{err}");
                    break;
                },
            }
        });

        let _req_handler = thread::spawn(move || loop {
            let cm_id: Arc<Identifier> = req_rx.recv().expect("Failed to receive cm_id");

            let node = Arc::new(Mutex::new(Node {
                id: Some(cm_id.clone()),
                qp: None,
                times: [(Instant::recent(), Instant::recent()); Step::Count as usize],
            }));

            let mut conn_param = ConnectionParameter::default();

            {
                let mut guard = node.lock().unwrap();

                guard.create_qp();

                let qp = guard.qp.as_mut().unwrap();

                let attr = cm_id.get_qp_attr(QueuePairState::Init).unwrap();
                qp.modify(&attr).unwrap();

                let attr = cm_id.get_qp_attr(QueuePairState::ReadyToReceive).unwrap();
                qp.modify(&attr).unwrap();

                let attr = cm_id.get_qp_attr(QueuePairState::ReadyToSend).unwrap();
                qp.modify(&attr).unwrap();

                conn_param.setup_qp_number(qp.qp_number());
            }

            cm_id.setup_context(node.clone());
            nodes[(NODE_IDX.fetch_add(1, Ordering::Relaxed)) as usize] = Some(node);

            cm_id.accept(conn_param).unwrap();
        });

        let _disc_handler = thread::spawn(move || loop {
            let cm_id: Arc<Identifier> = disc_rx.recv().expect("Failed to receive cm_id");
            cm_id.disconnect().unwrap();
            NODE_IDX.fetch_add(1, Ordering::Relaxed);
        });

        while NODE_IDX.load(Ordering::Acquire) != args.connections * 2 {
            thread::yield_now();
        }
    }

    Ok(())
}
