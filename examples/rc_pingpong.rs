//! InfiniBand Reliable Connection (RC) Ping-Pong Example
//!
//! This module implements a ping-pong test using InfiniBand's Reliable Connection (RC) transport.
//! It demonstrates basic RDMA operations, connection setup, and data exchange in a Rust environment.
//!
//! Key features:
//! - Utilizes InfiniBand verbs for RDMA operations
//! - Implements both client and server roles
//! - Measures bandwidth and latency of RDMA communications
//! - Supports various configuration options including MTU size, iteration count, and more
//!
//! This example is valuable for developers learning RDMA programming in Rust or
//! benchmarking InfiniBand network performance.

use std::io::{Error, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;

use clap::{Parser, ValueEnum};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use sideway::ibverbs::address::{AddressHandleAttribute, Gid};
use sideway::ibverbs::completion::{CreateCompletionQueueWorkCompletionFlags, WorkCompletionStatus};
use sideway::ibverbs::device::DeviceList;
use sideway::ibverbs::device_context::Mtu;
use sideway::ibverbs::queue_pair::{
    PostSendGuard, QueuePair, QueuePairAttribute, QueuePairState, SetScatterGatherEntry, WorkRequestFlags,
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
    let rx_depth = if args.iter > args.rx_depth {
        args.rx_depth
    } else {
        args.iter
    };
    let mut rout: u32 = 0;
    let mut ts_param = TimeStamps {
        completion_recv_min_time_delta: u64::MAX,
        ..Default::default()
    };
    let mut completion_timestamp_mask = 0;

    let device_list = DeviceList::new().expect("Failed to get IB devices list");
    let device = match args.ib_dev {
        Some(ib_dev) => device_list
            .iter()
            .find(|dev| dev.name().unwrap().eq(&ib_dev))
            .unwrap_or_else(|| panic!("IB device {ib_dev} not found")),
        None => device_list.iter().next().expect("No IB device found"),
    };

    let context = device
        .open()
        .unwrap_or_else(|_| panic!("Couldn't get context for {}", device.name().unwrap()));

    let attr = context.query_device().unwrap();

    if args.ts {
        completion_timestamp_mask = attr.completion_timestamp_mask();
        if completion_timestamp_mask == 0 {
            panic!("The device isn't completion timestamp capable");
        }
    }

    let pd = context.alloc_pd().unwrap_or_else(|_| panic!("Couldn't allocate PD"));
    let send_mr = pd
        .reg_managed_mr(args.size as _)
        .unwrap_or_else(|_| panic!("Couldn't register send MR"));

    let recv_mr = pd
        .reg_managed_mr(args.size as _)
        .unwrap_or_else(|_| panic!("Couldn't register recv MR"));

    let gid = context.query_gid(args.ib_port, args.gid_idx.into()).unwrap();
    let psn = rand::random::<u32>() & 0xFFFFFF;

    let mut cq_builder = context.create_cq_builder();

    if args.ts {
        cq_builder.setup_wc_flags(
            CreateCompletionQueueWorkCompletionFlags::StandardFlags
                | CreateCompletionQueueWorkCompletionFlags::CompletionTimestamp,
        );
    }

    let cq = cq_builder.setup_cqe(rx_depth + 1).build_ex().unwrap();

    let mut builder = pd.create_qp_builder();

    let mut qp = builder
        .setup_max_inline_data(128)
        .setup_send_cq(&cq)
        .setup_recv_cq(&cq)
        .setup_max_send_wr(1)
        .setup_max_recv_wr(rx_depth)
        .build_ex()
        .unwrap_or_else(|_| panic!("Couldn't create QP"));

    let mut attr = QueuePairAttribute::new();
    attr.setup_state(QueuePairState::Init)
        .setup_pkey_index(0)
        .setup_port(args.ib_port)
        .setup_access_flags(AccessFlags::LocalWrite | AccessFlags::RemoteWrite);
    qp.modify(&attr)?;

    for _i in 0..rx_depth {
        let mut guard = qp.start_post_recv();

        let recv_handle = guard.construct_wr(RECV_WR_ID);

        unsafe {
            recv_handle.setup_sge(recv_mr.lkey(), recv_mr.buf.data.as_ptr() as _, args.size);
        };

        guard.post().unwrap();
    }

    rout += rx_depth;

    println!(" local address: QPN {:#06x}, PSN {psn:#08x}, GID {gid}", qp.qp_number());

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
        qp_number: qp.qp_number(),
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

    let mut attr = QueuePairAttribute::new();
    attr.setup_state(QueuePairState::ReadyToReceive)
        .setup_path_mtu(args.mtu.0)
        .setup_dest_qp_num(remote_context.qp_number)
        .setup_rq_psn(psn)
        .setup_max_dest_read_atomic(0)
        .setup_min_rnr_timer(0);

    // setup address vector
    let mut ah_attr = AddressHandleAttribute::new();

    ah_attr
        .setup_dest_lid(1)
        .setup_port(args.ib_port)
        .setup_service_level(args.sl)
        .setup_grh_src_gid_index(args.gid_idx)
        .setup_grh_dest_gid(&remote_context.gid)
        .setup_grh_hop_limit(1);
    attr.setup_address_vector(&ah_attr);
    qp.modify(&attr)?;

    let mut attr = QueuePairAttribute::new();
    attr.setup_state(QueuePairState::ReadyToSend)
        .setup_sq_psn(remote_context.packet_seq_number)
        .setup_timeout(12)
        .setup_retry_cnt(7)
        .setup_rnr_retry(7)
        .setup_max_read_atomic(0);

    qp.modify(&attr)?;

    let clock = quanta::Clock::new();
    let start_time = clock.now();
    let mut outstanding_send = false;

    if args.server_ip.is_some() {
        let mut guard = qp.start_post_send();

        let send_handle = guard.construct_wr(SEND_WR_ID, WorkRequestFlags::Signaled).setup_send();

        unsafe {
            send_handle.setup_sge(send_mr.lkey(), send_mr.buf.data.as_ptr() as _, send_mr.buf.len as _);
        }

        guard.post()?;
        outstanding_send = true;
    }
    // poll for the completion
    {
        loop {
            match cq.start_poll() {
                Ok(mut poller) => {
                    while let Some(wc) = poller.next() {
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
                                scnt += 1;
                                outstanding_send = false;
                            },
                            RECV_WR_ID => {
                                rcnt += 1;
                                rout -= 1;

                                // Post more receives if the receive side credit is low
                                if rout <= rx_depth / 2 {
                                    let to_post = rx_depth - rout;
                                    for _ in 0..to_post {
                                        let mut guard = qp.start_post_recv();
                                        let recv_handle = guard.construct_wr(RECV_WR_ID);
                                        unsafe {
                                            recv_handle.setup_sge(
                                                recv_mr.lkey(),
                                                recv_mr.buf.data.as_ptr() as _,
                                                args.size,
                                            );
                                        };
                                        guard.post().unwrap();
                                    }
                                    rout += to_post;
                                }

                                if args.ts {
                                    let timestamp = wc.completion_timestamp();
                                    if ts_param.last_completion_with_timestamp != 0 {
                                        let delta: u64 = if timestamp >= ts_param.completion_recv_prev_time {
                                            timestamp - ts_param.completion_recv_prev_time
                                        } else {
                                            completion_timestamp_mask - ts_param.completion_recv_prev_time
                                                + timestamp
                                                + 1
                                        };

                                        ts_param.completion_recv_max_time_delta =
                                            ts_param.completion_recv_max_time_delta.max(delta);
                                        ts_param.completion_recv_min_time_delta =
                                            ts_param.completion_recv_min_time_delta.min(delta);
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
                                panic!("Unknown error!");
                            },
                        }

                        if scnt < args.iter && !outstanding_send {
                            // Post another send if we haven't reached the iteration limit
                            let mut guard = qp.start_post_send();
                            let send_handle = guard.construct_wr(SEND_WR_ID, WorkRequestFlags::Signaled).setup_send();
                            unsafe {
                                send_handle.setup_sge(
                                    send_mr.lkey(),
                                    send_mr.buf.data.as_ptr() as _,
                                    send_mr.buf.len as _,
                                );
                            }
                            guard.post()?;
                            outstanding_send = true;
                        }
                    }
                },
                Err(_) => {
                    continue;
                },
            }

            // Check if we're done
            if scnt >= args.iter && rcnt >= args.iter {
                break;
            }
        }
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
