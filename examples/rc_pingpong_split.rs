//! InfiniBand Reliable Connection (RC) Transport Test Program - Split Architecture Version
//!
//! This program is inspired by the `ibv_rc_pingpong` example from the rdma-core project:
//! https://github.com/linux-rdma/rdma-core/blob/master/libibverbs/examples/rc_pingpong.c
//!
//! Key Features and Differences from rc_pingpong.rs:
//! 1. Split Architecture: Implements a separation of functions and context, mirroring the
//!    original C implementation more closely.
//! 2. Self-Referential Structure: Utilizes a self-referential struct `PingPongContext`
//!    implemented using the `ouroboros` crate, which is not present in rc_pingpong.rs.
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

use clap::{Parser, ValueEnum};
use ouroboros::self_referencing;
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use sideway::verbs::address::{AddressHandleAttribute, Gid};
use sideway::verbs::completion::{
    CreateCompletionQueueWorkCompletionFlags, ExtendedCompletionQueue, ExtendedWorkCompletion, WorkCompletionStatus,
};
use sideway::verbs::device::{Device, DeviceList};
use sideway::verbs::device_context::{DeviceContext, Mtu};
use sideway::verbs::memory_region::MemoryRegion;
use sideway::verbs::protection_domain::ProtectionDomain;
use sideway::verbs::queue_pair::{
    ExtendedQueuePair, PostSendGuard, QueuePair, QueuePairAttribute, QueuePairState, SetScatterGatherEntry,
    WorkRequestFlags,
};
use sideway::verbs::AccessFlags;

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

#[self_referencing]
struct PingPongContext {
    ctx: DeviceContext,
    #[borrows(ctx)]
    #[covariant]
    pd: ProtectionDomain<'this>,
    #[borrows(ctx)]
    #[covariant]
    cq: ExtendedCompletionQueue<'this>,
    #[borrows(pd, cq)]
    #[covariant]
    qp: ExtendedQueuePair<'this>,
    #[borrows(pd)]
    #[covariant]
    send_mr: MemoryRegion<'this>,
    #[borrows(pd)]
    #[covariant]
    recv_mr: MemoryRegion<'this>,
    size: u32,
    rx_depth: u32,
    completion_timestamp_mask: u64,
    outstanding_send: bool,
    scnt: u32,
    rcnt: u32,
    rout: u32,
}

impl PingPongContext {
    fn build(device: &Device, size: u32, rx_depth: u32, ib_port: u8, use_ts: bool) -> Result<PingPongContext, String> {
        let context = device
            .open()
            .unwrap_or_else(|_| panic!("Couldn't get context for {}", device.name().unwrap()));

        let attr = context.query_device().unwrap();

        let completion_timestamp_mask = if use_ts {
            match attr.completion_timestamp_mask() {
                0 => panic!("The device isn't completion timestamp capable"),
                mask => mask,
            }
        } else {
            0
        };

        Ok(PingPongContext::new(
            context,
            |context| context.alloc_pd().unwrap_or_else(|_| panic!("Couldn't allocate PD")),
            |context| {
                let mut cq_builder = context.create_cq_builder();
                if use_ts {
                    cq_builder.setup_wc_flags(
                        CreateCompletionQueueWorkCompletionFlags::StandardFlags
                            | CreateCompletionQueueWorkCompletionFlags::CompletionTimestamp,
                    );
                }
                let cq = cq_builder.setup_cqe(rx_depth + 1).build_ex().unwrap();
                cq
            },
            |pd, cq| {
                let mut builder = pd.create_qp_builder();

                let mut qp = builder
                    .setup_max_inline_data(128)
                    .setup_send_cq(cq)
                    .setup_recv_cq(cq)
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

                qp
            },
            |pd| {
                pd.reg_managed_mr(size as _)
                    .unwrap_or_else(|_| panic!("Couldn't register recv MR"))
            },
            |pd| {
                pd.reg_managed_mr(size as _)
                    .unwrap_or_else(|_| panic!("Couldn't register recv MR"))
            },
            size,
            rx_depth,
            completion_timestamp_mask,
            false,
            0,
            0,
            0,
        ))
    }

    fn post_recv(&mut self, num: u32) -> Result<(), String> {
        for _i in 0..num {
            let (mut guard, lkey, ptr, size) = self.with_mut(|fields| {
                (
                    fields.qp.start_post_recv(),
                    fields.recv_mr.lkey(),
                    fields.recv_mr.buf.data.as_ptr() as u64,
                    *fields.size,
                )
            });

            let recv_handle = guard.construct_wr(RECV_WR_ID);

            unsafe {
                recv_handle.setup_sge(lkey, ptr, size);
            };

            guard.post().unwrap();
        }

        Ok(())
    }

    fn post_send(&mut self) -> Result<(), String> {
        let (mut guard, lkey, ptr, size) = self.with_mut(|fields| {
            (
                fields.qp.start_post_send(),
                fields.send_mr.lkey(),
                fields.send_mr.buf.data.as_ptr() as u64,
                *fields.size,
            )
        });

        let send_handle = guard.construct_wr(SEND_WR_ID, WorkRequestFlags::Signaled).setup_send();

        unsafe {
            send_handle.setup_sge(lkey, ptr, size);
        };

        guard.post()
    }

    fn connect(
        &mut self, remote_context: &PingPongDestination, ib_port: u8, psn: u32, mtu: Mtu, sl: u8, gid_idx: u8,
    ) -> Result<(), String> {
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
        self.with_qp_mut(|qp| qp.modify(&attr).expect("Failed to modify QP to RTR"));

        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::ReadyToSend)
            .setup_sq_psn(remote_context.packet_seq_number)
            .setup_timeout(12)
            .setup_retry_cnt(7)
            .setup_rnr_retry(7)
            .setup_max_read_atomic(0);
        self.with_qp_mut(|qp| qp.modify(&attr).expect("Failed to modify QP to RTS"));

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
                            self.borrow_completion_timestamp_mask() - ts_param.completion_recv_prev_time + timestamp + 1
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
fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            .find(|dev| dev.name().unwrap().eq(&ib_dev))
            .unwrap_or_else(|| panic!("IB device {ib_dev} not found")),
        None => device_list.iter().next().expect("No IB device found"),
    };

    let mut ctx = PingPongContext::build(&device, args.size, rx_depth, args.ib_port, args.ts).unwrap();

    let gid = ctx.borrow_ctx().query_gid(args.ib_port, args.gid_idx.into()).unwrap();
    let psn = rand::random::<u32>() & 0xFFFFFF;

    ctx.post_recv(rx_depth).unwrap();
    rout += rx_depth;

    println!(
        " local address: QPN {:#06x}, PSN {psn:#08x}, GID {gid}",
        ctx.borrow_qp().qp_number()
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
        qp_number: ctx.borrow_qp().qp_number(),
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

    ctx.connect(&remote_context, args.ib_port, psn, args.mtu.0, args.sl, args.gid_idx)
        .unwrap();

    let clock = quanta::Clock::new();
    let start_time = clock.now();
    let mut outstanding_send = false;

    if args.server_ip.is_some() {
        ctx.post_send().unwrap();
        outstanding_send = true;
    }
    // poll for the completion
    {
        loop {
            let mut need_post_recv = false;
            let mut to_post_recv = 0;
            let mut need_post_send = false;

            {
                match ctx.borrow_cq().start_poll() {
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
                    Err(_) => {
                        continue;
                    },
                }
            }

            if need_post_recv {
                ctx.post_recv(to_post_recv).unwrap();
                rout += to_post_recv;
            }

            if need_post_send {
                ctx.post_send().unwrap();
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
