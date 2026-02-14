#![allow(clippy::too_many_arguments)]

use std::io::{Error, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use byte_unit::{Byte, UnitType};
use clap::{Parser, ValueEnum};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use sideway::ibverbs::address::{AddressHandle, AddressHandleAttribute, Gid, GlobalRoutingHeader, GRH_HEADER_LEN};
use sideway::ibverbs::completion::{
    CreateCompletionQueueWorkCompletionFlags, ExtendedCompletionQueue, ExtendedWorkCompletion, GenericCompletionQueue,
    WorkCompletionStatus,
};
use sideway::ibverbs::device::{Device, DeviceInfo, DeviceList};
use sideway::ibverbs::device_context::{DeviceContext, Mtu};
use sideway::ibverbs::memory_region::MemoryRegion;
use sideway::ibverbs::protection_domain::ProtectionDomain;
use sideway::ibverbs::queue_pair::{
    ExtendedQueuePair, PostSendGuard, QueuePair, QueuePairAttribute, QueuePairState, QueuePairType, SendOperationFlags,
    SetScatterGatherEntry, WorkRequestFlags,
};
use sideway::ibverbs::AccessFlags;

const SEND_WR_ID: u64 = 0;
const RECV_WR_ID: u64 = 1;
const DEFAULT_QKEY: u32 = 0x1111_1111;

#[derive(Debug, Parser)]
#[clap(name = "ud_pingpong", version = "0.1.0")]
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
    /// Print GRH on each received packet
    #[arg(long, default_value_t = false)]
    debug_grh: bool,
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
    pd: Arc<ProtectionDomain>,
    _send_buf: Arc<Vec<u8>>,
    send_mr: Arc<MemoryRegion>,
    _recv_buf: Arc<Vec<u8>>,
    recv_mr: Arc<MemoryRegion>,
    cq: Arc<ExtendedCompletionQueue>,
    qp: ExtendedQueuePair,
    size: u32,
    completion_timestamp_mask: u64,
}

impl PingPongContext {
    fn build(device: &Device, size: u32, rx_depth: u32, ib_port: u8, use_ts: bool) -> Result<PingPongContext> {
        let context: Arc<DeviceContext> = device
            .open()
            .with_context(|| format!("Couldn't get context for {}", device.name()))?;

        let attr = context.query_device().with_context(|| "Failed to query device")?;

        let completion_timestamp_mask = if use_ts {
            match attr.completion_timestamp_mask() {
                0 => anyhow::bail!("The device isn't completion timestamp capable"),
                mask => mask,
            }
        } else {
            0
        };

        let pd = context.alloc_pd().context("Failed to allocate PD")?;

        let send_buf = Arc::new(vec![0; size as usize]);
        let send_mr = unsafe {
            pd.reg_mr(
                send_buf.as_ptr() as usize,
                send_buf.len(),
                AccessFlags::LocalWrite | AccessFlags::RemoteWrite,
            )
            .context("Failed to register send MR")?
        };

        let recv_buf = Arc::new(vec![0; size as usize + GRH_HEADER_LEN]);
        let recv_mr = unsafe {
            pd.reg_mr(
                recv_buf.as_ptr() as usize,
                recv_buf.len(),
                AccessFlags::LocalWrite | AccessFlags::RemoteWrite,
            )
            .context("Failed to register recv MR")?
        };

        let mut cq_builder = context.create_cq_builder();
        if use_ts {
            cq_builder.setup_wc_flags(
                CreateCompletionQueueWorkCompletionFlags::StandardFlags
                    | CreateCompletionQueueWorkCompletionFlags::CompletionTimestamp,
            );
        }
        let cq = cq_builder.setup_cqe(rx_depth + 1).build_ex()?;

        let cq_for_qp = GenericCompletionQueue::from(Arc::clone(&cq));

        let mut builder = pd.create_qp_builder();

        let mut qp = builder
            .setup_qp_type(QueuePairType::UnreliableDatagram)
            .setup_max_inline_data(0)
            .setup_send_cq(cq_for_qp.clone())
            .setup_recv_cq(cq_for_qp)
            .setup_max_send_wr(1)
            .setup_max_recv_wr(rx_depth)
            .setup_send_ops_flags(SendOperationFlags::Send | SendOperationFlags::SendWithImmediate)
            .build_ex()
            .context("Failed to create QP")?;

        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::Init)
            .setup_pkey_index(0)
            .setup_port(ib_port)
            .setup_qkey(DEFAULT_QKEY);
        qp.modify(&attr).context("Failed to modify QP to INIT")?;

        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::ReadyToReceive);
        qp.modify(&attr).context("Failed to modify QP to RTR")?;

        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::ReadyToSend).setup_sq_psn(1);
        qp.modify(&attr).context("Failed to modify QP to RTS")?;

        Ok(PingPongContext {
            ctx: context,
            pd,
            _send_buf: send_buf,
            send_mr,
            _recv_buf: recv_buf,
            recv_mr,
            cq,
            qp,
            size,
            completion_timestamp_mask,
        })
    }

    fn post_recv(&mut self, num: u32) -> Result<()> {
        for _ in 0..num {
            let mut guard = self.qp.start_post_recv();
            let lkey = self.recv_mr.lkey();
            let ptr = self.recv_mr.get_ptr() as u64;
            let size = self.size + GRH_HEADER_LEN as u32;

            let recv_handle = guard.construct_wr(RECV_WR_ID);

            unsafe {
                recv_handle.setup_sge(lkey, ptr, size);
            };

            guard.post()?;
        }

        Ok(())
    }

    fn create_address_handle(
        &self, remote_context: &PingPongDestination, ib_port: u8, sl: u8, gid_idx: u8,
    ) -> Result<AddressHandle> {
        let mut ah_attr = AddressHandleAttribute::new();
        ah_attr
            .setup_dest_lid(remote_context.lid)
            .setup_port(ib_port)
            .setup_service_level(sl)
            .setup_grh_src_gid_index(gid_idx)
            .setup_grh_dest_gid(&remote_context.gid)
            .setup_grh_hop_limit(1);

        self.pd
            .create_ah(&mut ah_attr)
            .context("Failed to create address handle")
    }

    fn post_send(&mut self, ah: &AddressHandle, remote_context: &PingPongDestination) -> Result<()> {
        let mut guard = self.qp.start_post_send();

        let send_handle = guard
            .construct_wr(SEND_WR_ID, WorkRequestFlags::Signaled)
            .setup_ud_addr(ah, remote_context.qp_number, remote_context.qkey)
            .setup_send();
        unsafe { send_handle.setup_sge(self.send_mr.lkey(), self.send_mr.get_ptr() as u64, self.size) };

        guard.post()?;

        Ok(())
    }

    #[inline]
    fn parse_single_work_completion(
        &self, wc: &ExtendedWorkCompletion, ts_param: &mut TimeStamps, scnt: &mut u32, rcnt: &mut u32,
        outstanding_send: &mut bool, rout: &mut u32, rx_depth: u32, need_post_recv: &mut bool, to_post_recv: &mut u32,
        use_ts: bool, debug_grh: bool,
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

                // Print GRH if debug mode is enabled
                if debug_grh {
                    let recv_buf = unsafe {
                        std::slice::from_raw_parts(
                            self.recv_mr.get_ptr() as *const u8,
                            self.size as usize + GRH_HEADER_LEN,
                        )
                    };
                    match GlobalRoutingHeader::new_checked(recv_buf) {
                        Ok(grh) => {
                            println!(
                                "[recv #{}] GRH: version={}, traffic_class={:#04x}, flow_label={:#07x}, \
                                 payload_len={}, next_hdr={:#04x}, hop_limit={}, src_gid={}, dst_gid={}",
                                *rcnt,
                                grh.version(),
                                grh.traffic_class(),
                                grh.flow_label(),
                                grh.payload_length(),
                                grh.next_header(),
                                grh.hop_limit(),
                                grh.source_gid(),
                                grh.destination_gid()
                            );
                        },
                        Err(e) => {
                            eprintln!("[recv #{}] Failed to parse GRH: {}", *rcnt, e);
                        },
                    }
                }

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
    lid: u16,
    qp_number: u32,
    qkey: u32,
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
fn main() -> Result<()> {
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

    let device_list = DeviceList::new().with_context(|| "Failed to get IB devices list")?;
    let device = match args.ib_dev {
        Some(ib_dev) => device_list
            .iter()
            .find(|dev| dev.name().eq(&ib_dev))
            .with_context(|| format!("IB device {ib_dev} not found"))?,
        None => device_list.iter().next().with_context(|| "No IB device found")?,
    };

    let mut ctx = PingPongContext::build(&device, args.size, rx_depth, args.ib_port, args.ts)?;

    let gid = ctx.ctx.query_gid(args.ib_port, args.gid_idx.into())?;
    let port_attr = ctx.ctx.query_port(args.ib_port)?;
    let lid = port_attr.lid();

    ctx.post_recv(rx_depth)?;
    rout += rx_depth;

    println!(
        " local address: QPN {:#06x}, QKey {DEFAULT_QKEY:#010x}, LID {lid:#06x}, GID {gid}",
        ctx.qp.qp_number()
    );

    let mut stream = match args.server_ip {
        Some(ref ip_str) => {
            let ip = IpAddr::from_str(ip_str).context("Invalid IP address")?;
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
        lid,
        qp_number: ctx.qp.qp_number(),
        qkey: DEFAULT_QKEY,
        gid,
    };
    let mut msg_buf = Vec::new();
    send_context(&mut stream, &local_context)?;
    let remote_context = recv_context(&mut stream, &mut msg_buf)?;
    println!(
        "remote address: QPN {:#06x}, QKey {:#010x}, LID {:#06x}, GID {}",
        remote_context.qp_number, remote_context.qkey, remote_context.lid, remote_context.gid
    );

    let remote_ah = ctx.create_address_handle(&remote_context, args.ib_port, args.sl, args.gid_idx)?;

    let clock = quanta::Clock::new();
    let start_time = clock.now();
    let mut outstanding_send = false;

    if args.server_ip.is_some() {
        ctx.post_send(&remote_ah, &remote_context)?;
        outstanding_send = true;
    }
    // poll for the completion
    loop {
        let mut need_post_recv = false;
        let mut to_post_recv = 0;
        let mut need_post_send = false;

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
                        args.debug_grh,
                    );

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

        if need_post_recv {
            ctx.post_recv(to_post_recv)?;
            rout += to_post_recv;
        }

        if need_post_send {
            ctx.post_send(&remote_ah, &remote_context)?;
        }

        if scnt >= args.iter && rcnt >= args.iter {
            break;
        }
    }

    let end_time = clock.now();
    let time = end_time.duration_since(start_time);
    let bytes = args.size as u64 * args.iter as u64 * 2;
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
