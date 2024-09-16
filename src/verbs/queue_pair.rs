use bitmask_enum::bitmask;
use lazy_static::lazy_static;
use rdma_mummy_sys::{
    ibv_create_qp, ibv_create_qp_ex, ibv_destroy_qp, ibv_modify_qp, ibv_qp, ibv_qp_attr, ibv_qp_attr_mask, ibv_qp_cap,
    ibv_qp_attr_mask, ibv_qp_cap, ibv_qp_ex, ibv_qp_init_attr, ibv_qp_init_attr_ex, ibv_qp_state, ibv_qp_type,
    ibv_rx_hash_conf,
};
use std::{
    io,
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{null_mut, NonNull},
};

use super::{
    address::AddressHandleAttribute, completion::CompletionQueue, device_context::Mtu,
    protection_domain::ProtectionDomain, AccessFlags,
};

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum QueuePairType {
    ReliableConnection = ibv_qp_type::IBV_QPT_RC,
    UnreliableConnection = ibv_qp_type::IBV_QPT_UC,
    UnreliableDatagram = ibv_qp_type::IBV_QPT_UD,
    RawPacket = ibv_qp_type::IBV_QPT_RAW_PACKET,
    ReliableConnectionExtendedSend = ibv_qp_type::IBV_QPT_XRC_SEND,
    ReliableConnectionExtendedRecv = ibv_qp_type::IBV_QPT_XRC_RECV,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueuePairState {
    Reset = ibv_qp_state::IBV_QPS_RESET,
    Init = ibv_qp_state::IBV_QPS_INIT,
    ReadyToReceive = ibv_qp_state::IBV_QPS_RTR,
    ReadyToSend = ibv_qp_state::IBV_QPS_RTS,
    SendQueueDrain = ibv_qp_state::IBV_QPS_SQD,
    SendQueueError = ibv_qp_state::IBV_QPS_SQE,
    Error = ibv_qp_state::IBV_QPS_ERR,
    Unknown = ibv_qp_state::IBV_QPS_UNKNOWN,
}

impl From<u32> for QueuePairState {
    fn from(state: u32) -> Self {
        match state {
            ibv_qp_state::IBV_QPS_RESET => QueuePairState::Reset,
            ibv_qp_state::IBV_QPS_INIT => QueuePairState::Init,
            ibv_qp_state::IBV_QPS_RTR => QueuePairState::ReadyToReceive,
            ibv_qp_state::IBV_QPS_RTS => QueuePairState::ReadyToSend,
            ibv_qp_state::IBV_QPS_SQD => QueuePairState::SendQueueDrain,
            ibv_qp_state::IBV_QPS_SQE => QueuePairState::SendQueueError,
            ibv_qp_state::IBV_QPS_ERR => QueuePairState::Error,
            ibv_qp_state::IBV_QPS_UNKNOWN => QueuePairState::Unknown,
            _ => panic!("Unknown qp state: {state}"),
        }
    }
}

pub trait QueuePair {
    //! return the basic handle of QP;
    //! we mark this method unsafe because the lifetime of ibv_qp is not
    //! associated with the return value.
    unsafe fn qp(&self) -> NonNull<ibv_qp>;

    fn modify(&mut self, attr: &QueuePairAttribute) -> Result<(), String> {
        // ibv_qp_attr does not impl Clone trait, so we use struct update syntax here
        let mut qp_attr = ibv_qp_attr { ..attr.attr };
        let ret = unsafe { ibv_modify_qp(self.qp().as_ptr(), &mut qp_attr as *mut _, attr.attr_mask.bits) };
        if ret == 0 {
            Ok(())
        } else {
            // User doesn't pass in a mask with IBV_QP_STATE, we just assume user doesn't
            // want to change the state, pass self.state() as next_state
            if attr.attr_mask.contains(QueuePairAttributeMask::State) {
                attr_mask_check(attr.attr_mask, self.state(), attr.attr.qp_state.into()).unwrap();
            } else {
                attr_mask_check(attr.attr_mask, self.state(), self.state()).unwrap();
            }

            Err(format!("ibv_modify_qp failed, err={ret}"))
        }
    }

    fn state(&self) -> QueuePairState {
        unsafe { self.qp().as_ref().state.into() }
    }
}

// According to C standard, enums should be int, but Rust just uses whatever
// type returned by Clang, which is uint on Linux platforms, so just cast it
// into int.
//
// https://github.com/rust-lang/rust-bindgen/issues/1966
//
#[bitmask(i32)]
#[bitmask_config(vec_debug)]
pub enum QueuePairAttributeMask {
    State = ibv_qp_attr_mask::IBV_QP_STATE.0 as _,
    CurrentState = ibv_qp_attr_mask::IBV_QP_CUR_STATE.0 as _,
    EnableSendQueueDrainedAsyncNotify = ibv_qp_attr_mask::IBV_QP_EN_SQD_ASYNC_NOTIFY.0 as _,
    AccessFlags = ibv_qp_attr_mask::IBV_QP_ACCESS_FLAGS.0 as _,
    PartitionKeyIndex = ibv_qp_attr_mask::IBV_QP_PKEY_INDEX.0 as _,
    Port = ibv_qp_attr_mask::IBV_QP_PORT.0 as _,
    QueueKey = ibv_qp_attr_mask::IBV_QP_QKEY.0 as _,
    AddressVector = ibv_qp_attr_mask::IBV_QP_AV.0 as _,
    PathMtu = ibv_qp_attr_mask::IBV_QP_PATH_MTU.0 as _,
    Timeout = ibv_qp_attr_mask::IBV_QP_TIMEOUT.0 as _,
    RetryCount = ibv_qp_attr_mask::IBV_QP_RETRY_CNT.0 as _,
    ResponderNotReadyRetryCount = ibv_qp_attr_mask::IBV_QP_RNR_RETRY.0 as _,
    ReceiveQueuePacketSequenceNumber = ibv_qp_attr_mask::IBV_QP_RQ_PSN.0 as _,
    MaxReadAtomic = ibv_qp_attr_mask::IBV_QP_MAX_QP_RD_ATOMIC.0 as _,
    AlternatePath = ibv_qp_attr_mask::IBV_QP_ALT_PATH.0 as _,
    MinResponderNotReadyTimer = ibv_qp_attr_mask::IBV_QP_MIN_RNR_TIMER.0 as _,
    SendQueuePacketSequenceNumber = ibv_qp_attr_mask::IBV_QP_SQ_PSN.0 as _,
    MaxDestinationReadAtomic = ibv_qp_attr_mask::IBV_QP_MAX_DEST_RD_ATOMIC.0 as _,
    PathMigrationState = ibv_qp_attr_mask::IBV_QP_PATH_MIG_STATE.0 as _,
    Capabilities = ibv_qp_attr_mask::IBV_QP_CAP.0 as _,
    DestinationQueuePairNumber = ibv_qp_attr_mask::IBV_QP_DEST_QPN.0 as _,
    RateLimit = ibv_qp_attr_mask::IBV_QP_RATE_LIMIT.0 as _,
}

// Define the required and optional mask according to the spec, so that we
// could provide attr check for users. Furthermore, provide more useful
// error messages.
//
// There is a corresponding table named qp_state_table in Linux kernel
//
// Ref: https://elixir.bootlin.com/linux/v6.10.9/source/drivers/infiniband/core/verbs.c#L1385
//
// We should consider using `std::mem::variant_count` here, after it stablized.
//
#[derive(Debug, Copy, Clone)]
struct QueuePairStateTableEntry {
    // whether this state transition is valid.
    valid: bool,
    required_mask: QueuePairAttributeMask,
    optional_mask: QueuePairAttributeMask,
}

lazy_static! {
    static ref RC_QP_STATE_TABLE: [[QueuePairStateTableEntry; QueuePairState::Error as usize + 1];
    QueuePairState::Error as usize + 1] = {
        use QueuePairState::*;

        let mut qp_state_table =
            [[QueuePairStateTableEntry { valid: false, required_mask: QueuePairAttributeMask { bits: 0 }, optional_mask: QueuePairAttributeMask { bits: 0 } }; Error as usize + 1]; Error as usize + 1];
        let mut state = Reset;

        // from any state to reset / error state only requires IBV_QP_STATE
        while state <= Error {
            qp_state_table[state as usize][Reset as usize] = QueuePairStateTableEntry {
                valid: true,
                required_mask: QueuePairAttributeMask::State,
                optional_mask: QueuePairAttributeMask { bits: 0 },
            };

            qp_state_table[state as usize][Error as usize] = QueuePairStateTableEntry {
                valid: true,
                required_mask: QueuePairAttributeMask::State,
                optional_mask: QueuePairAttributeMask { bits: 0 },
            };

            state = (state as u32 + 1).into()
        }

        qp_state_table[Reset as usize][Init as usize] = QueuePairStateTableEntry {
            valid: true,
            required_mask: QueuePairAttributeMask::State
            | QueuePairAttributeMask::PartitionKeyIndex
            | QueuePairAttributeMask::Port
            | QueuePairAttributeMask::AccessFlags,
            optional_mask: QueuePairAttributeMask { bits: 0 },
        };

        qp_state_table[Init as usize][Init as usize] = QueuePairStateTableEntry {
            valid: true,
            required_mask: QueuePairAttributeMask { bits: 0 },
            optional_mask: QueuePairAttributeMask::PartitionKeyIndex
            | QueuePairAttributeMask::Port
            | QueuePairAttributeMask::AccessFlags,
        };

        qp_state_table[Init as usize][ReadyToReceive as usize] = QueuePairStateTableEntry {
            valid: true,
            required_mask: QueuePairAttributeMask::State
            | QueuePairAttributeMask::AddressVector
            | QueuePairAttributeMask::PathMtu
            | QueuePairAttributeMask::DestinationQueuePairNumber
            | QueuePairAttributeMask::ReceiveQueuePacketSequenceNumber
            | QueuePairAttributeMask::MaxDestinationReadAtomic
            | QueuePairAttributeMask::MinResponderNotReadyTimer,
            optional_mask: QueuePairAttributeMask::PartitionKeyIndex
            | QueuePairAttributeMask::AccessFlags
            | QueuePairAttributeMask::AlternatePath,
        };

        qp_state_table[ReadyToReceive as usize][ReadyToSend as usize] = QueuePairStateTableEntry {
            valid: true,
            required_mask: QueuePairAttributeMask::State
            | QueuePairAttributeMask::SendQueuePacketSequenceNumber
            | QueuePairAttributeMask::Timeout
            | QueuePairAttributeMask::RetryCount
            | QueuePairAttributeMask::ResponderNotReadyRetryCount
            | QueuePairAttributeMask::MaxReadAtomic,
            optional_mask: QueuePairAttributeMask::CurrentState
            | QueuePairAttributeMask::AccessFlags
            | QueuePairAttributeMask::MinResponderNotReadyTimer
            | QueuePairAttributeMask::AlternatePath
            | QueuePairAttributeMask::PathMigrationState,
        };

        qp_state_table[ReadyToSend as usize][ReadyToSend as usize] = QueuePairStateTableEntry {
            valid: true,
            required_mask: QueuePairAttributeMask { bits: 0 },
            optional_mask: QueuePairAttributeMask::CurrentState
            | QueuePairAttributeMask::AccessFlags
            | QueuePairAttributeMask::MinResponderNotReadyTimer
            | QueuePairAttributeMask::AlternatePath
            | QueuePairAttributeMask::PathMigrationState,
        };

        qp_state_table[ReadyToSend as usize][SendQueueDrain as usize] = QueuePairStateTableEntry {
            valid: true,
            required_mask: QueuePairAttributeMask::State,
            optional_mask: QueuePairAttributeMask::EnableSendQueueDrainedAsyncNotify,
        };

        qp_state_table[SendQueueDrain as usize][ReadyToSend as usize] = QueuePairStateTableEntry {
            valid: true,
            required_mask: QueuePairAttributeMask::State,
            optional_mask: QueuePairAttributeMask::CurrentState
            | QueuePairAttributeMask::AccessFlags
            | QueuePairAttributeMask::MinResponderNotReadyTimer
            | QueuePairAttributeMask::AlternatePath
            | QueuePairAttributeMask::PathMigrationState,
        };

        qp_state_table[SendQueueDrain as usize][SendQueueDrain as usize] = QueuePairStateTableEntry {
            valid: true,
            required_mask: QueuePairAttributeMask { bits: 0 },
            optional_mask: QueuePairAttributeMask::PartitionKeyIndex
            | QueuePairAttributeMask::Port
            | QueuePairAttributeMask::AccessFlags
            | QueuePairAttributeMask::AddressVector
            | QueuePairAttributeMask::MaxReadAtomic
            | QueuePairAttributeMask::MinResponderNotReadyTimer
            | QueuePairAttributeMask::AlternatePath
            | QueuePairAttributeMask::Timeout
            | QueuePairAttributeMask::RetryCount
            | QueuePairAttributeMask::ResponderNotReadyRetryCount
            | QueuePairAttributeMask::MaxDestinationReadAtomic
            | QueuePairAttributeMask::PathMigrationState,
        };

        qp_state_table
    };
}

#[derive(Debug)]
pub struct BasicQueuePair<'res> {
    pub(crate) qp: NonNull<ibv_qp>,
    // phantom data for protection domain & completion queues
    _phantom: PhantomData<&'res ()>,
}

impl Drop for BasicQueuePair<'_> {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_qp(self.qp.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

impl QueuePair for BasicQueuePair<'_> {
    unsafe fn qp(&self) -> NonNull<ibv_qp> {
        self.qp
    }
}

#[derive(Debug)]
pub struct ExtendedQueuePair<'res> {
    // TODO: ibv_create_qp_ex returns ibv_qp instead of ibv_qp_ex, to be fixed
    pub(crate) qp_ex: NonNull<ibv_qp>,
    // phantom data for protection domain & completion queues
    _phantom: PhantomData<&'res ()>,
}

impl Drop for ExtendedQueuePair<'_> {
    fn drop(&mut self) {
        // TODO: convert qp_ex to qp (port ibv_qp_ex_to_qp in rdma-mummy-sys)
        let ret = unsafe { ibv_destroy_qp(self.qp_ex.as_ptr().cast()) };
        assert_eq!(ret, 0)
    }
}

impl QueuePair for ExtendedQueuePair<'_> {
    unsafe fn qp(&self) -> NonNull<ibv_qp> {
        // TODO: convert qp_ex to qp (port ibv_qp_ex_to_qp in rdma-mummy-sys)
        self.qp_ex.cast()
    }
}

pub struct QueuePairBuilder<'res> {
    init_attr: ibv_qp_init_attr_ex,
    // phantom data for protection domain & completion queues
    _phantom: PhantomData<&'res ()>,
}

impl<'res> QueuePairBuilder<'res> {
    pub fn new<'pd>(pd: &'pd ProtectionDomain) -> QueuePairBuilder<'res>
    where
        'pd: 'res,
    {
        QueuePairBuilder {
            init_attr: ibv_qp_init_attr_ex {
                qp_context: null_mut(),
                send_cq: null_mut(),
                recv_cq: null_mut(),
                srq: null_mut(),
                cap: ibv_qp_cap {
                    max_send_wr: 16,
                    max_recv_wr: 16,
                    max_send_sge: 1,
                    max_recv_sge: 1,
                    max_inline_data: 0,
                },
                qp_type: QueuePairType::ReliableConnection as _,
                sq_sig_all: 0,
                comp_mask: 0,
                pd: pd.pd.as_ptr(),
                xrcd: null_mut(),
                create_flags: 0,
                max_tso_header: 0,
                rwq_ind_tbl: null_mut(),
                rx_hash_conf: unsafe { MaybeUninit::<ibv_rx_hash_conf>::zeroed().assume_init() },
                source_qpn: 0,
                send_ops_flags: 0,
            },
            _phantom: PhantomData,
        }
    }

    pub fn setup_qp_type(&mut self, qp_type: QueuePairType) -> &mut Self {
        self.init_attr.qp_type = qp_type as u32;
        self
    }

    pub fn setup_max_send_wr(&mut self, max_send_wr: u32) -> &mut Self {
        self.init_attr.cap.max_send_wr = max_send_wr;
        self
    }

    pub fn setup_max_recv_wr(&mut self, max_recv_wr: u32) -> &mut Self {
        self.init_attr.cap.max_recv_wr = max_recv_wr;
        self
    }

    pub fn setup_max_send_sge(&mut self, max_send_sge: u32) -> &mut Self {
        self.init_attr.cap.max_send_sge = max_send_sge;
        self
    }

    pub fn setup_max_recv_sge(&mut self, max_recv_sge: u32) -> &mut Self {
        self.init_attr.cap.max_recv_sge = max_recv_sge;
        self
    }

    pub fn setup_max_inline_data(&mut self, max_inline_data: u32) -> &mut Self {
        self.init_attr.cap.max_inline_data = max_inline_data;
        self
    }

    pub fn setup_send_cq<'sq>(&mut self, send_cq: &'sq impl CompletionQueue) -> &mut Self
    where
        'sq: 'res,
    {
        self.init_attr.send_cq = unsafe { send_cq.cq().as_ptr() };
        self
    }

    pub fn setup_recv_cq<'rq>(&mut self, recv_cq: &'rq impl CompletionQueue) -> &mut Self
    where
        'rq: 'res,
    {
        self.init_attr.recv_cq = unsafe { recv_cq.cq().as_ptr() };
        self
    }

    // build basic qp
    pub fn build(&self) -> Result<BasicQueuePair<'res>, String> {
        let qp = unsafe {
            ibv_create_qp(
                self.init_attr.pd,
                &mut ibv_qp_init_attr {
                    qp_context: null_mut(),
                    send_cq: self.init_attr.send_cq,
                    recv_cq: self.init_attr.recv_cq,
                    srq: null_mut(),
                    cap: self.init_attr.cap,
                    qp_type: QueuePairType::ReliableConnection as _,
                    sq_sig_all: 0,
                },
            )
        };

        Ok(BasicQueuePair {
            qp: NonNull::new(qp).ok_or(format!("ibv_create_qp failed, {}", io::Error::last_os_error()))?,
            _phantom: PhantomData,
        })
    }

    // build extended qp
    pub fn build_ex(&mut self) -> Result<ExtendedQueuePair<'res>, String> {
        let qp = unsafe { ibv_create_qp_ex((*self.init_attr.pd).context, &mut self.init_attr).unwrap_or(null_mut()) };

        Ok(ExtendedQueuePair {
            qp_ex: NonNull::new(qp).ok_or(format!("ibv_create_qp failed, {}", io::Error::last_os_error()))?,
            _phantom: PhantomData,
        })
    }
}

pub struct QueuePairAttribute {
    attr: ibv_qp_attr,
    attr_mask: QueuePairAttributeMask,
}

impl QueuePairAttribute {
    pub fn new() -> Self {
        QueuePairAttribute {
            attr: unsafe { MaybeUninit::zeroed().assume_init() },
            attr_mask: QueuePairAttributeMask { bits: 0 },
        }
    }

    // initialize attr from an existing one (this is useful when we interact with rdmacm)
    pub fn from(attr: &ibv_qp_attr, attr_mask: i32) -> Self {
        QueuePairAttribute {
            attr: ibv_qp_attr { ..*attr },
            attr_mask: QueuePairAttributeMask { bits: attr_mask },
        }
    }

    // TODO what about the default value for qp_attr?

    pub fn setup_state(&mut self, state: QueuePairState) -> &mut Self {
        self.attr.qp_state = state as _;
        self.attr_mask |= QueuePairAttributeMask::State;
        self
    }

    pub fn setup_pkey_index(&mut self, pkey_index: u16) -> &mut Self {
        self.attr.pkey_index = pkey_index;
        self.attr_mask |= QueuePairAttributeMask::PartitionKeyIndex;
        self
    }

    pub fn setup_port(&mut self, port_num: u8) -> &mut Self {
        self.attr.port_num = port_num;
        self.attr_mask |= QueuePairAttributeMask::Port;
        self
    }

    pub fn setup_access_flags(&mut self, access_flags: AccessFlags) -> &mut Self {
        self.attr.qp_access_flags = access_flags.bits as _;
        self.attr_mask |= QueuePairAttributeMask::AccessFlags;
        self
    }

    pub fn setup_path_mtu(&mut self, path_mtu: Mtu) -> &mut Self {
        self.attr.path_mtu = path_mtu as _;
        self.attr_mask |= QueuePairAttributeMask::PathMtu;
        self
    }

    pub fn setup_dest_qp_num(&mut self, dest_qp_num: u32) -> &mut Self {
        self.attr.dest_qp_num = dest_qp_num;
        self.attr_mask |= QueuePairAttributeMask::DestinationQueuePairNumber;
        self
    }

    pub fn setup_rq_psn(&mut self, rq_psn: u32) -> &mut Self {
        self.attr.rq_psn = rq_psn;
        self.attr_mask |= QueuePairAttributeMask::ReceiveQueuePacketSequenceNumber;
        self
    }

    pub fn setup_sq_psn(&mut self, sq_psn: u32) -> &mut Self {
        self.attr.sq_psn = sq_psn;
        self.attr_mask |= QueuePairAttributeMask::SendQueuePacketSequenceNumber;
        self
    }

    pub fn setup_max_read_atomic(&mut self, max_read_atomic: u8) -> &mut Self {
        self.attr.max_rd_atomic = max_read_atomic;
        self.attr_mask |= QueuePairAttributeMask::MaxReadAtomic;
        self
    }

    pub fn setup_max_dest_read_atomic(&mut self, max_dest_read_atomic: u8) -> &mut Self {
        self.attr.max_dest_rd_atomic = max_dest_read_atomic;
        self.attr_mask |= QueuePairAttributeMask::MaxDestinationReadAtomic;
        self
    }

    pub fn setup_min_rnr_timer(&mut self, min_rnr_timer: u8) -> &mut Self {
        self.attr.min_rnr_timer = min_rnr_timer;
        self.attr_mask |= QueuePairAttributeMask::MinResponderNotReadyTimer;
        self
    }

    pub fn setup_timeout(&mut self, timeout: u8) -> &mut Self {
        self.attr.timeout = timeout;
        self.attr_mask |= QueuePairAttributeMask::Timeout;
        self
    }

    pub fn setup_retry_cnt(&mut self, retry_cnt: u8) -> &mut Self {
        self.attr.retry_cnt = retry_cnt;
        self.attr_mask |= QueuePairAttributeMask::RetryCount;
        self
    }

    pub fn setup_rnr_retry(&mut self, rnr_retry: u8) -> &mut Self {
        self.attr.rnr_retry = rnr_retry;
        self.attr_mask |= QueuePairAttributeMask::ResponderNotReadyRetryCount;
        self
    }

    pub fn setup_address_vector(&mut self, ah_attr: &AddressHandleAttribute) -> &mut Self {
        self.attr.ah_attr = ah_attr.attr.clone();
        self.attr_mask |= QueuePairAttributeMask::AddressVector;
        self
    }
}

// TODO(zhp): trait for QueuePair

#[inline]
fn get_needed_mask(cur_mask: QueuePairAttributeMask, required_mask: QueuePairAttributeMask) -> QueuePairAttributeMask {
    required_mask.and(required_mask.xor(cur_mask))
}

#[inline]
fn get_invalid_mask(
    cur_mask: QueuePairAttributeMask, required_mask: QueuePairAttributeMask, optional_mask: QueuePairAttributeMask,
) -> QueuePairAttributeMask {
    cur_mask.and(required_mask.or(optional_mask).not())
}

fn attr_mask_check(
    attr_mask: QueuePairAttributeMask, cur_state: QueuePairState, next_state: QueuePairState,
) -> Result<(), String> {
    if !RC_QP_STATE_TABLE[cur_state as usize][next_state as usize].valid {
        return Err(format!("Invalid transition from {cur_state:?} to {next_state:?}"));
    }

    let required = RC_QP_STATE_TABLE[cur_state as usize][next_state as usize].required_mask;
    let optional = RC_QP_STATE_TABLE[cur_state as usize][next_state as usize].optional_mask;
    let invalid = get_invalid_mask(attr_mask, required, optional);
    let needed = get_needed_mask(attr_mask, required);
    if invalid.bits == 0 && needed.bits == 0 {
        Ok(())
    } else {
        Err(format!("Invalid transition from {cur_state:?} to {next_state:?}, possible invalid masks {invalid:?}, possible needed masks {needed:?}"))
    }
}
