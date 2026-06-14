//! InfiniBand Reliable Connection (RC) Transport Test Program - Split Architecture Version
//!
//! This program is inspired by the `ibv_rc_pingpong` example from the rdma-core project:
//! https://github.com/linux-rdma/rdma-core/blob/master/libibverbs/examples/rc_pingpong.c
//!
//! Key Features and Differences from rc_pingpong.rs:
//! 1. Split Architecture: Implements a separation of functions and context, mirroring the
//!    original C implementation more closely.
//! 2. Arc-Managed Resources: Wraps verbs resources (`DeviceContext`, `ProtectionDomain`,
//!    `MemoryRegion`) in `Arc` to simplify ownership compared to rc_pingpong.rs.
//! 3. Modular Design: Breaks down functionality into smaller, more manageable functions,
//!    improving code readability and maintainability.
//! 4. Context Encapsulation: Encapsulates more state within the `PingPongContext` struct,
//!    reducing the number of global variables compared to rc_pingpong.rs.
//! 5. Enhanced Error Handling: Implements more robust error handling and propagation
//!    throughout the program.
//!
//! This split version demonstrates an alternative approach to structuring RDMA applications
//! in Rust, offering insights into managing complex, interdependent RDMA resources.
//! It serves as a more advanced example for developers looking to implement sophisticated
//! RDMA programs while maintaining idiomatic Rust patterns.

#![allow(clippy::too_many_arguments)]

use std::io::{Error, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use sideway::ibverbs::address::{AddressHandleAttribute, Gid};
use sideway::ibverbs::completion::{
    CompletionChannel, CreateCompletionQueueWorkCompletionFlags, ExtendedCompletionQueue, ExtendedWorkCompletion,
    GenericCompletionQueue, PollCompletionQueueError, WorkCompletionStatus,
};
use sideway::ibverbs::device::{Device, DeviceInfo, DeviceList};
use sideway::ibverbs::device_context::{DeviceContext, Mtu};
use sideway::ibverbs::memory_region::MemoryRegion;
use sideway::ibverbs::protection_domain::ProtectionDomain;
use sideway::ibverbs::queue_pair::{
    ExtendedQueuePair, PostSendError, PostSendGuard, QueuePair, QueuePairAttribute, QueuePairState,
    SetScatterGatherEntry, WorkRequestFlags,
};
use sideway::ibverbs::AccessFlags;

use byte_unit::{Byte, UnitType};

const SEND_WR_ID: u64 = 0;
const RECV_WR_ID: u64 = 1;

#[derive(Debug, Parser)]
#[clap(name = "rc_pingpong", version = "0.1.0")]
pub struct Args {
    /// Listen on / connect to port
    #[clap(long, short = 'p', default_value_t = 18515)]
    port: u16,
    /// The IB device to use
    #[clap(long, short = 'd')]
    ib_dev: Option<String>,
    /// The port of IB device
    #[clap(long, short = 'i', default_value_t = 1)]
    ib_port: u8,
    /// The size of message to exchange
    #[clap(long, short = 's', default_value_t = 1024)]
    size: u32,
    /// Path MTU
    #[clap(long, short = 'm', value_enum, default_value_t = PathMtu(Mtu::Mtu1024))]
    mtu: PathMtu,
    /// Numbers of receives to post at a time
    #[clap(long, short = 'r', default_value_t = 500)]
    rx_depth: u32,
    /// Numbers of exchanges
    #[clap(long, short = 'n', default_value_t = 1000)]
    iter: u32,
    /// Service level value
    #[clap(long, short = 'l', default_value_t = 0)]
    sl: u8,
    /// Local port GID index
    #[clap(long, short = 'g', default_value_t = 0)]
    gid_idx: u8,
    /// Get CQE with timestamp
    #[arg(long, short = 't', default_value_t = false)]
    ts: bool,
    /// Use CQ events instead of busy polling
    #[arg(long, short = 'e', default_value_t = false)]
    use_events: bool,
    /// If no value provided, start a server and wait for connection, otherwise, connect to server at [host]
    #[arg(name = "host")]
    server_ip: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct PathMtu(Mtu);

impl ValueEnum for PathMtu {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self(Mtu::Mtu256),
            Self(Mtu::Mtu512),
            Self(Mtu::Mtu1024),
            Self(Mtu::Mtu2048),
            Self(Mtu::Mtu4096),
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self.0 {
            Mtu::Mtu256 => Some(clap::builder::PossibleValue::new("256")),
            Mtu::Mtu512 => Some(clap::builder::PossibleValue::new("512")),
            Mtu::Mtu1024 => Some(clap::builder::PossibleValue::new("1024")),
            Mtu::Mtu2048 => Some(clap::builder::PossibleValue::new("2048")),
            Mtu::Mtu4096 => Some(clap::builder::PossibleValue::new("4096")),
        }
    }
}

struct PingPongContext {
    ctx: Arc<DeviceContext>,
    _pd: Arc<ProtectionDomain>,
    _send_buf: Arc<Vec<u8>>,
    send_mr: Arc<MemoryRegion>,
    _recv_buf: Arc<Vec<u8>>,
    recv_mr: Arc<MemoryRegion>,
    cq: Arc<ExtendedCompletionQueue>,
    cq_handle: GenericCompletionQueue,
    comp_channel: Option<Arc<CompletionChannel>>,
    qp: ExtendedQueuePair,
    size: u32,
    completion_timestamp_mask: u64,
}

impl PingPongContext {
    fn build(
        device: &Device, size: u32, rx_depth: u32, ib_port: u8, use_ts: bool, use_events: bool,
    ) -> anyhow::Result<PingPongContext> {
        let context: Arc<DeviceContext> = device
            .open()
            .unwrap_or_else(|_| panic!("Couldn't get context for {}", device.name()));

        let attr = context.query_device().unwrap();

        let completion_timestamp_mask = if use_ts {
            match attr.completion_timestamp_mask() {
                0 => panic!("The device isn't completion timestamp capable"),
                mask => mask,
            }
        } else {
            0
        };

        // Create completion channel if using events
        let comp_channel = if use_events {
            Some(CompletionChannel::new(&context).expect("Couldn't create completion channel"))
        } else {
            None
        };

        let pd = context.alloc_pd().unwrap_or_else(|_| panic!("Couldn't allocate PD"));

        let send_buf = Arc::new(vec![0; size as usize]);
        let send_mr = unsafe {
            pd.reg_mr(
                send_buf.as_ptr() as usize,
                send_buf.len(),
                AccessFlags::LocalWrite | AccessFlags::RemoteWrite,
            )
            .unwrap_or_else(|_| panic!("Couldn't register send MR"))
        };

        let recv_buf = Arc::new(vec![0; size as usize]);
        let recv_mr = unsafe {
            pd.reg_mr(
                recv_buf.as_ptr() as usize,
                recv_buf.len(),
                AccessFlags::LocalWrite | AccessFlags::RemoteWrite,
            )
            .unwrap_or_else(|_| panic!("Couldn't register recv MR"))
        };

        let mut cq_builder = context.create_cq_builder();
        if use_ts {
            cq_builder.setup_wc_flags(
                CreateCompletionQueueWorkCompletionFlags::StandardFlags
                    | CreateCompletionQueueWorkCompletionFlags::CompletionTimestamp,
            );
        }
        // Associate completion channel with CQ if using events
        if let Some(ref channel) = comp_channel {
            cq_builder.setup_comp_channel(channel, 0);
        }
        let cq = cq_builder.setup_cqe(rx_depth + 1).build_ex().unwrap();

        let cq_handle = GenericCompletionQueue::from(Arc::clone(&cq));

        // Request initial notification if using events
        if use_events {
            cq_handle
                .req_notify_cq(false)
                .expect("Couldn't request CQ notification");
        }

        let mut builder = pd.create_qp_builder();

        let mut qp = builder
            .setup_max_inline_data(128)
            .setup_send_cq(cq_handle.clone())
            .setup_recv_cq(cq_handle.clone())
            .setup_max_send_wr(1)
            .setup_max_recv_wr(rx_depth)
            .build_ex()
            .unwrap_or_else(|_| panic!("Couldn't create QP"));

        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::Init)
            .setup_pkey_index(0)
            .setup_port(ib_port)
            .setup_access_flags(AccessFlags::LocalWrite | AccessFlags::RemoteWrite);
        qp.modify(&attr).expect("Failed to modify QP to INIT");

        Ok(PingPongContext {
            ctx: context,
            _pd: pd,
            _send_buf: send_buf,
            send_mr,
            _recv_buf: recv_buf,
            recv_mr,
            cq,
            cq_handle,
            comp_channel,
            qp,
            size,
            completion_timestamp_mask,
        })
    }

    fn post_recv(&mut self, num: u32) -> Result<(), String> {
        for _ in 0..num {
            let mut guard = self.qp.start_post_recv();
            let lkey = self.recv_mr.lkey();
            let ptr = self.recv_mr.get_ptr() as u64;
            let size = self.size;

            let recv_handle = guard.construct_wr(RECV_WR_ID);

            unsafe {
                recv_handle.setup_sge(lkey, ptr, size);
            };

            guard.post().map_err(|err| err.to_string())?;
        }

        Ok(())
    }

    fn post_send(&mut self) -> Result<(), PostSendError> {
        let mut guard = self.qp.start_post_send();
        let lkey = self.send_mr.lkey();
        let ptr = self.send_mr.get_ptr() as u64;
        let size = self.size;

        let send_handle = guard.construct_wr(SEND_WR_ID, WorkRequestFlags::Signaled).setup_send();

        unsafe {
            send_handle.setup_sge(lkey, ptr, size);
        };

        guard.post()
    }

    fn connect(
        &mut self, remote_context: &PingPongDestination, ib_port: u8, psn: u32, mtu: Mtu, sl: u8, gid_idx: u8,
    ) -> anyhow::Result<()> {
        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::ReadyToReceive)
            .setup_path_mtu(mtu)
            .setup_dest_qp_num(remote_context.qp_number)
            .setup_rq_psn(psn)
            .setup_max_dest_read_atomic(0)
            .setup_min_rnr_timer(0);

        // setup address vector
        let mut ah_attr = AddressHandleAttribute::new();

        ah_attr
            .setup_dest_lid(1)
            .setup_port(ib_port)
            .setup_service_level(sl)
            .setup_grh_src_gid_index(gid_idx)
            .setup_grh_dest_gid(&remote_context.gid)
            .setup_grh_hop_limit(1);
        attr.setup_address_vector(&ah_attr);
        self.qp.modify(&attr).expect("Failed to modify QP to RTR");

        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::ReadyToSend)
            .setup_sq_psn(remote_context.packet_seq_number)
            .setup_timeout(12)
            .setup_retry_cnt(7)
            .setup_rnr_retry(7)
            .setup_max_read_atomic(0);
        self.qp.modify(&attr).expect("Failed to modify QP to RTS");

        Ok(())
    }

    #[inline]
    fn parse_single_work_completion(
        &self, wc: &ExtendedWorkCompletion, ts_param: &mut TimeStamps, scnt: &mut u32, rcnt: &mut u32,
        outstanding_send: &mut bool, rout: &mut u32, rx_depth: u32, need_post_recv: &mut bool, to_post_recv: &mut u32,
        use_ts: bool,
    ) {
        if wc.status() != WorkCompletionStatus::Success as u32 {
            panic!(
                "Failed status {:#?} ({}) for wr_id {}",
                Into::<WorkCompletionStatus>::into(wc.status()),
                wc.status(),
                wc.wr_id()
            );
        }
        match wc.wr_id() {
            SEND_WR_ID => {
                *scnt += 1;
                *outstanding_send = false;
            },
            RECV_WR_ID => {
                *rcnt += 1;
                *rout -= 1;

                if *rout <= rx_depth / 2 {
                    *to_post_recv = rx_depth - *rout;
                    *need_post_recv = true;
                }

                if use_ts {
                    let timestamp = wc.completion_timestamp();
                    if ts_param.last_completion_with_timestamp != 0 {
                        let delta: u64 = if timestamp >= ts_param.completion_recv_prev_time {
                            timestamp - ts_param.completion_recv_prev_time
                        } else {
                            self.completion_timestamp_mask - ts_param.completion_recv_prev_time + timestamp + 1
                        };

                        ts_param.completion_recv_max_time_delta = ts_param.completion_recv_max_time_delta.max(delta);
                        ts_param.completion_recv_min_time_delta = ts_param.completion_recv_min_time_delta.min(delta);
                        ts_param.completion_recv_total_time_delta += delta;
                        ts_param.completion_with_time_iters += 1;
                    }

                    ts_param.completion_recv_prev_time = timestamp;
                    ts_param.last_completion_with_timestamp = 1;
                } else {
                    ts_param.last_completion_with_timestamp = 0;
                }
            },
            _ => {
                panic!("Unknown wr_id {}", wc.wr_id());
            },
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct PingPongDestination {
    lid: u32,
    qp_number: u32,
    packet_seq_number: u32,
    gid: Gid,
}

#[derive(Debug, Default)]
struct TimeStamps {
    completion_recv_max_time_delta: u64,
    completion_recv_min_time_delta: u64,
    completion_recv_total_time_delta: u64,
    completion_recv_prev_time: u64,
    last_completion_with_timestamp: u32,
    completion_with_time_iters: u32,
}

#[allow(clippy::while_let_on_iterator)]
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut scnt: u32 = 0;
    let mut rcnt: u32 = 0;
    let mut rout: u32 = 0;
    let rx_depth = if args.iter > args.rx_depth {
        args.rx_depth
    } else {
        args.iter
    };
    let mut ts_param = TimeStamps {
        completion_recv_min_time_delta: u64::MAX,
        ..Default::default()
    };

    let device_list = DeviceList::new().expect("Failed to get IB devices list");
    let device = match args.ib_dev {
        Some(ib_dev) => device_list
            .iter()
            .find(|dev| dev.name().eq(&ib_dev))
            .unwrap_or_else(|| panic!("IB device {ib_dev} not found")),
        None => device_list.iter().next().expect("No IB device found"),
    };

    let mut ctx = PingPongContext::build(&device, args.size, rx_depth, args.ib_port, args.ts, args.use_events)?;

    let gid = ctx.ctx.query_gid(args.ib_port, args.gid_idx.into()).unwrap();
    let psn = rand::random::<u32>() & 0xFFFFFF;

    ctx.post_recv(rx_depth).unwrap();
    rout += rx_depth;

    println!(
        " local address: QPN {:#06x}, PSN {psn:#08x}, GID {gid}",
        ctx.qp.qp_number()
    );

    let mut stream = match args.server_ip {
        Some(ref ip_str) => {
            let ip = IpAddr::from_str(ip_str).expect("Invalid IP address");
            let server_addr = SocketAddr::from((ip, args.port));
            TcpStream::connect(server_addr)?
        },
        None => {
            let server_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, args.port));
            let listener = TcpListener::bind(server_addr)?;
            let (stream, _peer_addr) = listener.accept()?;
            stream
        },
    };

    let send_context = |stream: &mut TcpStream, dest: &PingPongDestination| {
        let msg_buf = to_allocvec(dest).unwrap();
        let size = msg_buf.len().to_be_bytes();
        stream.write_all(&size)?;
        stream.write_all(&msg_buf)?;
        stream.flush()?;

        Ok::<(), Error>(())
    };

    let recv_context = |stream: &mut TcpStream, msg_buf: &mut Vec<u8>| {
        let mut size = usize::to_be_bytes(0);
        stream.read_exact(&mut size)?;
        msg_buf.clear();
        msg_buf.resize(usize::from_be_bytes(size), 0);
        stream.read_exact(&mut *msg_buf)?;
        let dest: PingPongDestination = from_bytes(msg_buf).unwrap();

        Ok::<PingPongDestination, Error>(dest)
    };

    let local_context = PingPongDestination {
        lid: 1,
        qp_number: ctx.qp.qp_number(),
        packet_seq_number: psn,
        gid,
    };
    let mut msg_buf = Vec::new();
    let _ = send_context(&mut stream, &local_context);
    let remote_context = recv_context(&mut stream, &mut msg_buf)?;
    println!(
        "remote address: QPN {:#06x}, PSN {:#08x}, GID {}",
        remote_context.qp_number, remote_context.packet_seq_number, remote_context.gid
    );

    ctx.connect(&remote_context, args.ib_port, psn, args.mtu.0, args.sl, args.gid_idx)?;

    let clock = quanta::Clock::new();
    let start_time = clock.now();
    let mut outstanding_send = false;

    if args.server_ip.is_some() {
        ctx.post_send()?;
        outstanding_send = true;
    }
    // poll for the completion
    let mut num_cq_events: u32 = 0;
    loop {
        let mut need_post_recv = false;
        let mut to_post_recv = 0;
        let mut need_post_send = false;

        // If using events, wait for CQ event before polling
        if args.use_events {
            if let Some(ref channel) = ctx.comp_channel {
                // Get the CQ event (this blocks until an event arrives)
                let _event_cq = channel.get_cq_event().expect("Failed to get CQ event");
                num_cq_events += 1;

                // Re-arm the notification BEFORE polling to avoid missing events
                ctx.cq_handle
                    .req_notify_cq(false)
                    .expect("Couldn't request CQ notification");
            }
        }

        // Poll for completions
        match ctx.cq.start_poll() {
            Ok(mut poller) => {
                while let Some(wc) = poller.next() {
                    ctx.parse_single_work_completion(
                        &wc,
                        &mut ts_param,
                        &mut scnt,
                        &mut rcnt,
                        &mut outstanding_send,
                        &mut rout,
                        rx_depth,
                        &mut need_post_recv,
                        &mut to_post_recv,
                        args.ts,
                    );

                    // Record that we need to post a send later
                    if scnt < args.iter && !outstanding_send {
                        need_post_send = true;
                        outstanding_send = true;
                    }
                }
            },
            Err(PollCompletionQueueError::CompletionQueueEmpty) => {
                // CQ is empty - if not using events, continue busy polling
                if !args.use_events {
                    continue;
                }
            },
            Err(e) => {
                panic!("Failed to poll CQ: {:?}", e);
            },
        }

        if need_post_recv {
            ctx.post_recv(to_post_recv).unwrap();
            rout += to_post_recv;
        }

        if need_post_send {
            ctx.post_send()?;
        }

        // Check if we're done
        if scnt >= args.iter && rcnt >= args.iter {
            break;
        }
    }

    // Acknowledge all CQ events before cleanup
    if num_cq_events > 0 {
        ctx.cq_handle.ack_events(num_cq_events);
    }

    let end_time = clock.now();
    let time = end_time.duration_since(start_time);
    let bytes = args.size as u64 * args.iter as u64 * 2;
    // bi-directional bandwidth
    let bytes_per_second = bytes as f64 / time.as_secs_f64();
    println!(
        "{} bytes in {:.2} seconds = {:.2}/s",
        bytes,
        time.as_secs_f64(),
        Byte::from_f64(bytes_per_second)
            .unwrap()
            .get_appropriate_unit(UnitType::Binary)
    );
    println!(
        "{} iters in {:.2} seconds = {:#.2?}/iter",
        args.iter,
        time.as_secs_f64(),
        time / args.iter
    );

    if args.ts && ts_param.completion_with_time_iters != 0 {
        println!(
            "Max receive completion clock cycles = {}",
            ts_param.completion_recv_max_time_delta
        );
        println!(
            "Min receive completion clock cycles = {}",
            ts_param.completion_recv_min_time_delta
        );
        println!(
            "Average receive completion clock cycles = {}",
            ts_param.completion_recv_total_time_delta as f64 / ts_param.completion_with_time_iters as f64
        );
    }

    Ok(())
}
