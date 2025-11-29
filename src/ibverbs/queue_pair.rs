//! A [`QueuePair`] is a pair of send queue and recv queue, considered as the basic transport
//! interface for RDMA communication.
use bitmask_enum::bitmask;
use rdma_mummy_sys::{
    ibv_create_qp, ibv_create_qp_ex, ibv_data_buf, ibv_destroy_qp, ibv_modify_qp, ibv_post_recv, ibv_post_send, ibv_qp,
    ibv_qp_attr, ibv_qp_attr_mask, ibv_qp_cap, ibv_qp_create_send_ops_flags, ibv_qp_ex, ibv_qp_init_attr,
    ibv_qp_init_attr_ex, ibv_qp_init_attr_mask, ibv_qp_state, ibv_qp_to_qp_ex, ibv_qp_type, ibv_query_qp, ibv_recv_wr,
    ibv_rx_hash_conf, ibv_send_flags, ibv_send_wr, ibv_sge, ibv_wr_abort, ibv_wr_complete, ibv_wr_opcode,
    ibv_wr_rdma_read, ibv_wr_rdma_write, ibv_wr_rdma_write_imm, ibv_wr_send, ibv_wr_send_imm, ibv_wr_set_inline_data,
    ibv_wr_set_inline_data_list, ibv_wr_set_sge, ibv_wr_set_sge_list, ibv_wr_set_ud_addr, ibv_wr_start,
};
use std::sync::{Arc, LazyLock};
use std::{
    fmt,
    io::{self, IoSlice},
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{null_mut, NonNull},
};

use super::{
    address::{AddressHandle, AddressHandleAttribute, Gid},
    completion::{CompletionQueue, GenericCompletionQueue},
    device_context::Mtu,
    protection_domain::ProtectionDomain,
    AccessFlags,
};

/// Error returned by [`QueuePairBuilder::build`] and [`QueuePairBuilder::build_ex`] for creating a
/// new RDMA QP.
#[derive(Debug, thiserror::Error)]
#[error("failed to create queue pair")]
#[non_exhaustive]
pub struct CreateQueuePairError(#[from] pub CreateQueuePairErrorKind);

/// The enum type for [`CreateQueuePairError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum CreateQueuePairErrorKind {
    Ibverbs(#[from] io::Error),
}

/// Error returned by [`QueuePair::query`] for querying a RDMA QP's attributes.
#[derive(Debug, thiserror::Error)]
#[error("failed to query queue pair")]
#[non_exhaustive]
pub struct QueryQueuePairError(#[from] pub QueryQueuePairErrorKind);

/// The enum type for [`QueryQueuePairError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum QueryQueuePairErrorKind {
    Ibverbs(#[from] io::Error),
}

/// Error returned by [`QueuePair::modify`] for modifying a RDMA QP's attributes.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub struct ModifyQueuePairError(#[from] pub ModifyQueuePairErrorKind);

/// The enum type for [`ModifyQueuePairError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModifyQueuePairErrorKind {
    #[error("modify queue pair failed")]
    Ibverbs(#[from] io::Error),
    #[error("invalid transition from {cur_state:?} to {next_state:?}")]
    InvalidTransition {
        cur_state: QueuePairState,
        next_state: QueuePairState,
        source: io::Error,
    },
    #[error("invalid transition from {cur_state:?} to {next_state:?}, possible invalid masks {invalid:?}, possible needed masks {needed:?}")]
    InvalidAttributeMask {
        cur_state: QueuePairState,
        next_state: QueuePairState,
        invalid: QueuePairAttributeMask,
        needed: QueuePairAttributeMask,
        source: io::Error,
    },
    #[error("resolve route timed out, source gid index: {sgid_index}, destination gid: {gid}")]
    ResolveRouteTimedout {
        sgid_index: u8,
        gid: Gid,
        source: io::Error,
    },
    #[error("network unreachable, source gid index: {sgid_index}, destination gid: {gid}")]
    NetworkUnreachable {
        sgid_index: u8,
        gid: Gid,
        source: io::Error,
    },
}

/// Error returned by [`PostSendGuard::post`] for posting Work Requests to QP's send queue.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PostSendError {
    #[error("post send failed")]
    Ibverbs(#[from] io::Error),
    #[error("invalid value provided in work request")]
    InvalidWorkRequest(#[source] io::Error),
    #[error("invalid value provided in queue pair")]
    InvalidQueuePair(#[source] io::Error),
    #[error("send queue is full or not enough resources to complete this operation")]
    NotEnoughResources(#[source] io::Error),
}

/// Error returned by [`PostRecvGuard::post`] for posting Work Requests to QP's recv queue.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PostRecvError {
    #[error("post receive failed")]
    Ibverbs(#[from] io::Error),
    #[error("invalid value provided in work request")]
    InvalidWorkRequest(#[source] io::Error),
    #[error("invalid value provided in queue pair")]
    InvalidQueuePair(#[source] io::Error),
    #[error("receive queue is full or not enough resources to complete this operation")]
    NotEnoughResources(#[source] io::Error),
}

/// The requested transport service type of a QP.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum QueuePairType {
    /// A reliable connection is a connection created between a single local QP and a single remote
    /// QP and that can guarantee that messages are delivered at most once, in order and without
    /// corruption between the local and remote QP's.
    ReliableConnection = ibv_qp_type::IBV_QPT_RC,
    /// An unreliable connection consists of a one-to-one correspondence between two QPs. Packets
    /// are sent from one QP to the other but no acknowledgments are generated by the desination QP.
    /// So there are no deliver guarantees made to the requester.
    UnreliableConnection = ibv_qp_type::IBV_QPT_UC,
    /// Unreliable datagrams are a form of communication that allows a source QP to send each
    /// message to one of many destination QPs.
    UnreliableDatagram = ibv_qp_type::IBV_QPT_UD,
    /// Raw packet QP allows an application build a complete packet including L2 headers. On the
    /// receiver side, the hardware would not strip any headers.
    RawPacket = ibv_qp_type::IBV_QPT_RAW_PACKET,
    /// Extended Reliable Connection QP, for detailed information, you could take this [commit] and
    /// this [PDF] as references.
    ///
    /// [commit]: https://github.com/linux-rdma/rdma-core/commit/c7e3e61052dd756c394d8fbccbc498aa4eebbd37
    /// [PDF]: https://downloads.openfabrics.org/Media/SC07/2007_SC_Nov_XRC.pdf
    ///
    ReliableConnectionExtendedSend = ibv_qp_type::IBV_QPT_XRC_SEND,
    ReliableConnectionExtendedRecv = ibv_qp_type::IBV_QPT_XRC_RECV,
}

/// QP's state, which controls the behavior of a QP. For detailed information, take
/// [qp state machine] for reference.
///
/// [qp state machine]: https://www.rdmamojo.com/2012/05/05/qp-state-machine/
///
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

/// Controls operations could be used of a [`ExtendedQueuePair`]. It's either 0 or
/// the bitwise `OR` of one or more of the following flags. Used in
/// [`QueuePairBuilder::setup_send_ops_flags`].
#[bitmask(u64)]
#[bitmask_config(vec_debug)]
pub enum SendOperationFlags {
    Write = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_RDMA_WRITE.0 as _,
    WriteWithImmediate = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM.0 as _,
    Send = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_SEND.0 as _,
    SendWithImmediate = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_SEND_WITH_IMM.0 as _,
    Read = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_RDMA_READ.0 as _,
    AtomicCompareAndSwap = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_ATOMIC_CMP_AND_SWP.0 as _,
    AtomicFetchAndAdd = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_ATOMIC_FETCH_AND_ADD.0 as _,
    LocalInvalidate = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_LOCAL_INV.0 as _,
    BindMemoryWindow = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_BIND_MW.0 as _,
    SendWithInvalidate = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_SEND_WITH_INV.0 as _,
    TcpSegmentationOffload = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_TSO.0 as _,
    Flush = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_FLUSH.0 as _,
    AtomicWrite = ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_ATOMIC_WRITE.0 as _,
}

/// Operation type of the Work Request.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkRequestOperationType {
    Send = ibv_wr_opcode::IBV_WR_SEND,
    SendWithImmediate = ibv_wr_opcode::IBV_WR_SEND_WITH_IMM,
    Write = ibv_wr_opcode::IBV_WR_RDMA_WRITE,
    WriteWithImmediate = ibv_wr_opcode::IBV_WR_RDMA_WRITE_WITH_IMM,
    Read = ibv_wr_opcode::IBV_WR_RDMA_READ,
    AtomicCompareAndSwap = ibv_wr_opcode::IBV_WR_ATOMIC_CMP_AND_SWP,
    AtomicFetchAndAdd = ibv_wr_opcode::IBV_WR_ATOMIC_FETCH_AND_ADD,
    LocalInvalidate = ibv_wr_opcode::IBV_WR_LOCAL_INV,
    BindMemoryWindow = ibv_wr_opcode::IBV_WR_BIND_MW,
    SendWithInvalidate = ibv_wr_opcode::IBV_WR_SEND_WITH_INV,
    TcpSegmentationOffload = ibv_wr_opcode::IBV_WR_TSO,
    Driver1 = ibv_wr_opcode::IBV_WR_DRIVER1,
    Flush = ibv_wr_opcode::IBV_WR_FLUSH,
    AtomicWrite = ibv_wr_opcode::IBV_WR_ATOMIC_WRITE,
}

impl From<u32> for WorkRequestOperationType {
    fn from(opcode: u32) -> Self {
        match opcode {
            ibv_wr_opcode::IBV_WR_SEND => WorkRequestOperationType::Send,
            ibv_wr_opcode::IBV_WR_SEND_WITH_IMM => WorkRequestOperationType::SendWithImmediate,
            ibv_wr_opcode::IBV_WR_RDMA_WRITE => WorkRequestOperationType::Write,
            ibv_wr_opcode::IBV_WR_RDMA_WRITE_WITH_IMM => WorkRequestOperationType::WriteWithImmediate,
            ibv_wr_opcode::IBV_WR_RDMA_READ => WorkRequestOperationType::Read,
            ibv_wr_opcode::IBV_WR_ATOMIC_CMP_AND_SWP => WorkRequestOperationType::AtomicCompareAndSwap,
            ibv_wr_opcode::IBV_WR_ATOMIC_FETCH_AND_ADD => WorkRequestOperationType::AtomicFetchAndAdd,
            ibv_wr_opcode::IBV_WR_LOCAL_INV => WorkRequestOperationType::LocalInvalidate,
            ibv_wr_opcode::IBV_WR_BIND_MW => WorkRequestOperationType::BindMemoryWindow,
            ibv_wr_opcode::IBV_WR_SEND_WITH_INV => WorkRequestOperationType::SendWithInvalidate,
            ibv_wr_opcode::IBV_WR_TSO => WorkRequestOperationType::TcpSegmentationOffload,
            ibv_wr_opcode::IBV_WR_DRIVER1 => WorkRequestOperationType::Driver1,
            ibv_wr_opcode::IBV_WR_FLUSH => WorkRequestOperationType::Flush,
            ibv_wr_opcode::IBV_WR_ATOMIC_WRITE => WorkRequestOperationType::AtomicWrite,
            _ => panic!("Unknown work request opcode: {opcode}"),
        }
    }
}

/// Flags of the Work Request properties.
#[bitmask(u32)]
#[bitmask_config(vec_debug)]
pub enum WorkRequestFlags {
    Fence = ibv_send_flags::IBV_SEND_FENCE.0,
    Signaled = ibv_send_flags::IBV_SEND_SIGNALED.0,
    Solicited = ibv_send_flags::IBV_SEND_SOLICITED.0,
    Inline = ibv_send_flags::IBV_SEND_INLINE.0,
    IpChecksum = ibv_send_flags::IBV_SEND_IP_CSUM.0,
}

/// Unified interface for operations over RDMA QPs.
#[allow(private_bounds)]
pub trait QueuePair {
    /// # Safety
    ///
    /// Return the basic handle of QP; we mark this method unsafe because the lifetime of `ibv_qp`
    /// is not associated with the return value.
    ///
    /// # Examples
    ///
    /// ```compile_fail
    /// unsafe {
    ///     let qp_ptr = generic_queue_pair.qp();
    ///     // Use qp_ptr carefully...
    /// }
    unsafe fn qp(&self) -> NonNull<ibv_qp>;

    /// Modify the [QueuePair]'s attributes.
    ///
    /// # Example
    ///
    /// ```compile_fail
    /// let mut attr = QueuePairAttribute::new();
    /// attr.setup_state(QueuePairState::ReadyToSend);
    /// generic_queue_pair.modify(&attr)?;
    /// ```
    fn modify(&mut self, attr: &QueuePairAttribute) -> Result<(), ModifyQueuePairError> {
        // ibv_qp_attr does not impl Clone trait, so we use struct update syntax here
        let mut qp_attr = ibv_qp_attr { ..attr.attr };
        let ret = unsafe { ibv_modify_qp(self.qp().as_ptr(), &mut qp_attr as *mut _, attr.attr_mask.bits) };
        if ret == 0 {
            Ok(())
        } else {
            match ret {
                libc::EINVAL => {
                    // User doesn't pass in a mask with IBV_QP_STATE, we just assume user doesn't
                    // want to change the state, pass self.state() as next_state
                    let err = if attr.attr_mask.contains(QueuePairAttributeMask::State) {
                        attr_mask_check(attr.attr_mask, self.state(), attr.attr.qp_state.into())
                    } else {
                        attr_mask_check(attr.attr_mask, self.state(), self.state())
                    };
                    match err {
                        Ok(()) => {
                            Err(ModifyQueuePairErrorKind::Ibverbs(io::Error::from_raw_os_error(libc::EINVAL)).into())
                        },
                        Err(err) => Err(err),
                    }
                },
                libc::ETIMEDOUT => Err(ModifyQueuePairErrorKind::ResolveRouteTimedout {
                    sgid_index: attr.attr.ah_attr.grh.sgid_index,
                    gid: attr.attr.ah_attr.grh.dgid.into(),
                    source: io::Error::from_raw_os_error(libc::ETIMEDOUT),
                }
                .into()),
                libc::ENETUNREACH => Err(ModifyQueuePairErrorKind::NetworkUnreachable {
                    sgid_index: attr.attr.ah_attr.grh.sgid_index,
                    gid: attr.attr.ah_attr.grh.dgid.into(),
                    source: io::Error::from_raw_os_error(libc::ENETUNREACH),
                }
                .into()),
                err => Err(ModifyQueuePairErrorKind::Ibverbs(io::Error::from_raw_os_error(err)).into()),
            }
        }
    }

    /// Query the [QueuePair]'s attributes. Specify the attributes to query by providing a mask.
    fn query(
        &self, mask: QueuePairAttributeMask,
    ) -> Result<(QueuePairAttribute, QueuePairInitAttribute), QueryQueuePairError> {
        let mut attr = QueuePairAttribute::default();
        let mut init_attr = QueuePairInitAttribute::default();

        attr.attr_mask = mask;

        let result = unsafe {
            ibv_query_qp(
                self.qp().as_ptr(),
                &mut attr.attr as *mut _,
                mask.bits(),
                &mut init_attr.init_attr as *mut _,
            )
        };

        match result {
            0 => Ok((attr, init_attr)),
            err => Err(QueryQueuePairErrorKind::Ibverbs(io::Error::from_raw_os_error(err)).into()),
        }
    }

    /// Get the [QueuePair]'s state.
    fn state(&self) -> QueuePairState {
        unsafe { self.qp().as_ref().state.into() }
    }

    /// Get the [QueuePair]'s number.
    fn qp_number(&self) -> u32 {
        unsafe { self.qp().as_ref().qp_num }
    }

    /// Could be [`ExtendedPostSendGuard`], [`BasicPostSendGuard`] or [`GenericPostSendGuard`].
    type Guard<'g>: PostSendGuard
    where
        Self: 'g;

    /// Starts a post send operation, every [`QueuePair`] should hold only one [`PostSendGuard`] at
    /// the same time.
    ///
    /// # Example
    ///
    /// ```compile_fail
    /// let mut guard = generic_queue_pair.start_post_send();
    /// let send_wr = guard.construct_wr(/* ... */);
    /// guard.post()?;
    /// ```
    //
    // RPITIT could be used here, but with lifetime bound, there could be problems.
    //
    // Ref: https://github.com/rust-lang/rust/issues/128752
    //      https://github.com/rust-lang/rust/issues/91611
    //      https://github.com/rust-lang/rfcs/pull/3425
    //      https://github.com/rust-lang/rust/issues/125836
    //
    fn start_post_send(&mut self) -> Self::Guard<'_>;

    /// Starts a post receive operation, every [`QueuePair`] should hold only one [`PostRecvGuard`]
    /// at the same time.
    ///
    /// # Example
    ///
    /// ```compile_fail
    /// let mut guard = generic_queue_pair.start_post_recv();
    /// let recv_wr = guard.construct_wr(/* ... */);
    /// guard.post()?;
    /// ```
    fn start_post_recv(&mut self) -> PostRecvGuard<'_> {
        PostRecvGuard {
            qp: unsafe { self.qp() },
            wrs: Vec::new(),
            sges: Vec::new(),
            _phantom: PhantomData,
        }
    }
}

mod private_traits {
    use std::io::IoSlice;

    use crate::ibverbs::address::AddressHandle;
    use rdma_mummy_sys::ibv_sge;

    // This is the private part of PostSendGuard, which is a workaround for pub trait
    // not being able to have private functions.
    //
    // Ref: https://stackoverflow.com/questions/53204327/how-to-have-a-private-part-of-a-trait
    //
    pub trait PostSendGuard {
        fn setup_send(&mut self);

        fn setup_send_imm(&mut self, imm_data: u32);

        fn setup_ud_addr(&mut self, ah: &AddressHandle, remote_qpn: u32, remote_qkey: u32);

        fn setup_write(&mut self, rkey: u32, remote_addr: u64);

        fn setup_write_imm(&mut self, rkey: u32, remote_addr: u64, imm_data: u32);

        fn setup_read(&mut self, rkey: u32, remote_addr: u64);

        fn setup_inline_data(&mut self, buf: &[u8]);

        fn setup_inline_data_list(&mut self, bufs: &[IoSlice<'_>]);

        unsafe fn setup_sge(&mut self, lkey: u32, addr: u64, length: u32);

        unsafe fn setup_sge_list(&mut self, sg_list: &[ibv_sge]);
    }
}

/// A [`PostSendGuard`] that can be used to construct and post send RDMA Work Requests.
pub trait PostSendGuard: private_traits::PostSendGuard {
    /// Construct a new [`WorkRequestHandle`] for setting up a new RDMA Work Request, every
    /// [`QueuePair`] should hold only one [`WorkRequestHandle`] at the same time.
    fn construct_wr(&mut self, wr_id: u64, wr_flags: WorkRequestFlags) -> WorkRequestHandle<'_, Self>;

    /// Post all previously setuped RDMA Work Requests into the [`QueuePair`]'s send queue.
    fn post(self) -> Result<(), PostSendError>;
}

// According to C standard, enums should be int, but Rust just uses whatever
// type returned by Clang, which is uint on Linux platforms, so just cast it
// into int.
//
// https://github.com/rust-lang/rust-bindgen/issues/1966
//
/// Mask of the [`QueuePairAttribute`], used for specifying the fields to be modified or queried in
/// attributes of the [`QueuePair`].
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

static RC_QP_STATE_TABLE: LazyLock<
    [[QueuePairStateTableEntry; QueuePairState::Error as usize + 1]; QueuePairState::Error as usize + 1],
> = LazyLock::new(|| {
    use QueuePairState::*;

    let mut qp_state_table = [[QueuePairStateTableEntry {
        valid: false,
        required_mask: QueuePairAttributeMask { bits: 0 },
        optional_mask: QueuePairAttributeMask { bits: 0 },
    }; Error as usize + 1]; Error as usize + 1];
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
});

/// The legacy [`QueuePair`] created with [`QueuePairBuilder::build`] ([`ibv_create_qp`]), which
/// doesn't support some advanced features (including [`ibv_wr_*`] APIs).
///
/// [`ibv_create_qp`]: https://man7.org/linux/man-pages/man3/ibv_create_qp.3.html
/// [`ibv_wr_*`]: https://manpages.debian.org/testing/libibverbs-dev/ibv_wr_post.3.en.html
///
pub struct BasicQueuePair {
    pub(crate) qp: NonNull<ibv_qp>,
    _pd: Arc<ProtectionDomain>,
    _send_cq: GenericCompletionQueue,
    _recv_cq: GenericCompletionQueue,
}

unsafe impl Send for BasicQueuePair {}
unsafe impl Sync for BasicQueuePair {}

impl Drop for BasicQueuePair {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_qp(self.qp.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

impl QueuePair for BasicQueuePair {
    unsafe fn qp(&self) -> NonNull<ibv_qp> {
        self.qp
    }

    type Guard<'g>
        = BasicPostSendGuard<'g>
    where
        Self: 'g;
    fn start_post_send(&mut self) -> Self::Guard<'_> {
        BasicPostSendGuard {
            qp: self.qp,
            wrs: Vec::with_capacity(0),
            sges: Vec::with_capacity(0),
            inline_buffers: Vec::with_capacity(0),
            _phantom: PhantomData,
        }
    }
}

impl fmt::Debug for BasicQueuePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicQueuePair").field("qp", &self.qp).finish()
    }
}

/// The extended [`QueuePair`] created with [`QueuePairBuilder::build_ex`] ([`ibv_create_qp_ex`]),
/// which support some advanced features (including [`ibv_wr_*`] APIs), should provide better
/// performance compared to [`BasicQueuePair`].
///
/// [`ibv_create_qp_ex`]: https://man7.org/linux/man-pages/man3/ibv_create_qp_ex.3.html
/// [`ibv_wr_*`]: https://manpages.debian.org/testing/libibverbs-dev/ibv_wr_post.3.en.html
///
pub struct ExtendedQueuePair {
    pub(crate) qp_ex: NonNull<ibv_qp_ex>,
    _pd: Arc<ProtectionDomain>,
    _send_cq: GenericCompletionQueue,
    _recv_cq: GenericCompletionQueue,
}

unsafe impl Send for ExtendedQueuePair {}
unsafe impl Sync for ExtendedQueuePair {}

impl Drop for ExtendedQueuePair {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_qp(self.qp().as_ptr()) };
        assert_eq!(ret, 0)
    }
}

impl QueuePair for ExtendedQueuePair {
    unsafe fn qp(&self) -> NonNull<ibv_qp> {
        NonNull::new_unchecked(&mut (*self.qp_ex.as_ptr()).qp_base as _)
    }

    type Guard<'g>
        = ExtendedPostSendGuard<'g>
    where
        Self: 'g;
    fn start_post_send(&mut self) -> Self::Guard<'_> {
        unsafe {
            ibv_wr_start(self.qp().as_ptr() as _);
        }

        ExtendedPostSendGuard {
            qp_ex: self.qp_ex,
            _phantom: PhantomData,
        }
    }
}

impl fmt::Debug for ExtendedQueuePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedQueuePair").field("qp_ex", &self.qp_ex).finish()
    }
}

/// A factory for creating [`BasicQueuePair`] and [`ExtendedQueuePair`] with the specified
/// parameters.
pub struct QueuePairBuilder {
    init_attr: ibv_qp_init_attr_ex,
    pd: Arc<ProtectionDomain>,
    send_cq: Option<GenericCompletionQueue>,
    recv_cq: Option<GenericCompletionQueue>,
}

impl QueuePairBuilder {
    pub fn new(pd: &Arc<ProtectionDomain>) -> QueuePairBuilder {
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
                // when building an extended qp instead of a basic qp, we need to pass in
                // these essential attributes.
                comp_mask: ibv_qp_init_attr_mask::IBV_QP_INIT_ATTR_PD.0
                    | ibv_qp_init_attr_mask::IBV_QP_INIT_ATTR_SEND_OPS_FLAGS.0,
                pd: pd.pd.as_ptr(),
                xrcd: null_mut(),
                create_flags: 0,
                max_tso_header: 0,
                rwq_ind_tbl: null_mut(),
                rx_hash_conf: unsafe { MaybeUninit::<ibv_rx_hash_conf>::zeroed().assume_init() },
                source_qpn: 0,
                // unless user specified, we assume every extended qp would support send,
                // write and read, just as what basic qp supports.
                send_ops_flags: (SendOperationFlags::Send
                    | SendOperationFlags::SendWithImmediate
                    | SendOperationFlags::Write
                    | SendOperationFlags::WriteWithImmediate
                    | SendOperationFlags::Read)
                    .into(),
            },
            pd: Arc::clone(pd),
            send_cq: None,
            recv_cq: None,
        }
    }

    /// Setup the requested QP type.
    pub fn setup_qp_type(&mut self, qp_type: QueuePairType) -> &mut Self {
        self.init_attr.qp_type = qp_type as u32;
        self
    }

    /// Setup the maximum number of outstanding RDMA Work Requests that can be posted to the
    /// **send queue** in the QP.
    pub fn setup_max_send_wr(&mut self, max_send_wr: u32) -> &mut Self {
        self.init_attr.cap.max_send_wr = max_send_wr;
        self
    }

    /// Setup the maximum number of outstanding RDMA Work Requests that can be posted to the
    /// **recv queue** in the QP.
    pub fn setup_max_recv_wr(&mut self, max_recv_wr: u32) -> &mut Self {
        self.init_attr.cap.max_recv_wr = max_recv_wr;
        self
    }

    /// Setup the maximum number of scatter / gather elements in any RDMA Work Request that can be
    /// posted to the **send queue** in the QP.
    pub fn setup_max_send_sge(&mut self, max_send_sge: u32) -> &mut Self {
        self.init_attr.cap.max_send_sge = max_send_sge;
        self
    }

    /// Setup the maximum number of scatter / gather elements in any RDMA Work Request that can be
    /// posted to the **recv queue** in the QP.
    pub fn setup_max_recv_sge(&mut self, max_recv_sge: u32) -> &mut Self {
        self.init_attr.cap.max_recv_sge = max_recv_sge;
        self
    }

    /// Setup the maximum message size that can be posted inline (in the RDMA Work Request) to the
    /// send queue.
    pub fn setup_max_inline_data(&mut self, max_inline_data: u32) -> &mut Self {
        self.init_attr.cap.max_inline_data = max_inline_data;
        self
    }

    /// Setup the [`CompletionQueue`] to be associated with the QP's send queue, could be the same
    /// one for [`setup_recv_cq`].
    ///
    /// [`setup_recv_cq`]: QueuePairBuilder::setup_recv_cq
    ///
    pub fn setup_send_cq<C>(&mut self, send_cq: C) -> &mut Self
    where
        C: Into<GenericCompletionQueue>,
    {
        let cq = send_cq.into();
        unsafe {
            self.init_attr.send_cq = cq.cq().as_ptr();
        }
        self.send_cq = Some(cq);
        self
    }

    /// Setup the [`CompletionQueue`] to be associated with the QP's recv queue, could be the same
    /// one for [`setup_send_cq`].
    ///
    /// [`setup_send_cq`]: QueuePairBuilder::setup_send_cq
    ///
    pub fn setup_recv_cq<C>(&mut self, recv_cq: C) -> &mut Self
    where
        C: Into<GenericCompletionQueue>,
    {
        let cq = recv_cq.into();
        unsafe {
            self.init_attr.recv_cq = cq.cq().as_ptr();
        }
        self.recv_cq = Some(cq);
        self
    }

    /// Setup the operations could be used of a [`ExtendedQueuePair`].
    pub fn setup_send_ops_flags(&mut self, send_ops_flags: SendOperationFlags) -> &mut Self {
        self.init_attr.send_ops_flags = send_ops_flags.bits;
        self
    }

    /// Create a [`BasicQueuePair`] with [`ibv_create_qp`].
    ///
    /// [`ibv_create_qp`]: https://man7.org/linux/man-pages/man3/ibv_create_qp.3.html
    ///
    pub fn build(&self) -> Result<BasicQueuePair, CreateQueuePairError> {
        let send_cq = self
            .send_cq
            .as_ref()
            .cloned()
            .expect("send completion queue must be configured before building a QueuePair");
        let recv_cq = self
            .recv_cq
            .as_ref()
            .cloned()
            .expect("receive completion queue must be configured before building a QueuePair");

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
            qp: NonNull::new(qp)
                .ok_or::<CreateQueuePairError>(CreateQueuePairErrorKind::Ibverbs(io::Error::last_os_error()).into())?,
            _pd: Arc::clone(&self.pd),
            _send_cq: send_cq,
            _recv_cq: recv_cq,
        })
    }

    /// Create a [`ExtendedQueuePair`] with [`ibv_create_qp_ex`].
    ///
    /// [`ibv_create_qp_ex`]: https://man7.org/linux/man-pages/man3/ibv_create_qp_ex.3.html
    ///
    pub fn build_ex(&self) -> Result<ExtendedQueuePair, CreateQueuePairError> {
        let send_cq = self
            .send_cq
            .as_ref()
            .cloned()
            .expect("send completion queue must be configured before building a QueuePair");
        let recv_cq = self
            .recv_cq
            .as_ref()
            .cloned()
            .expect("receive completion queue must be configured before building a QueuePair");

        let mut attr = self.init_attr;

        let qp = unsafe { ibv_create_qp_ex((*(attr.pd)).context, &mut attr) };

        if qp.is_null() {
            return Err(CreateQueuePairErrorKind::Ibverbs(io::Error::last_os_error()).into());
        }

        Ok(ExtendedQueuePair {
            qp_ex: NonNull::new(unsafe { ibv_qp_to_qp_ex(qp) })
                .ok_or::<CreateQueuePairError>(CreateQueuePairErrorKind::Ibverbs(io::Error::last_os_error()).into())?,
            _pd: Arc::clone(&self.pd),
            _send_cq: send_cq,
            _recv_cq: recv_cq,
        })
    }
}

/// Describe the attributes of a [`QueuePair`], could be used for getting current [`QueuePair`]
/// attributes with [`QueuePair::query`] or modifying current [`QueuePair`] attributes with
/// [`QueuePair::modify`].
pub struct QueuePairAttribute {
    attr: ibv_qp_attr,
    attr_mask: QueuePairAttributeMask,
}

impl Default for QueuePairAttribute {
    fn default() -> Self {
        Self::new()
    }
}

impl QueuePairAttribute {
    pub fn new() -> Self {
        QueuePairAttribute {
            attr: unsafe { MaybeUninit::zeroed().assume_init() },
            attr_mask: QueuePairAttributeMask { bits: 0 },
        }
    }

    /// Initialize attr from an existing one, this is useful when we interact with RDMA CM, or other
    /// existing libraries.
    pub fn from(attr: &ibv_qp_attr, attr_mask: i32) -> Self {
        QueuePairAttribute {
            attr: ibv_qp_attr { ..*attr },
            attr_mask: QueuePairAttributeMask { bits: attr_mask },
        }
    }

    /// Setup the next [`QueuePair`] state, note that not all state transitions
    /// are valid, you could take [qp state machine] as a reference.
    ///
    /// [qp state machine]: https://www.rdmamojo.com/2012/05/05/qp-state-machine/
    ///
    pub fn setup_state(&mut self, state: QueuePairState) -> &mut Self {
        self.attr.qp_state = state as _;
        self.attr_mask |= QueuePairAttributeMask::State;
        self
    }

    /// Get the [`QueuePair`] state you filled in or queried from [`QueuePair::query`].
    pub fn state(&self) -> QueuePairState {
        self.attr.qp_state.into()
    }

    /// Setup the primary `p_key` index.
    pub fn setup_pkey_index(&mut self, pkey_index: u16) -> &mut Self {
        self.attr.pkey_index = pkey_index;
        self.attr_mask |= QueuePairAttributeMask::PartitionKeyIndex;
        self
    }

    /// Get the primary `p_key` index you filled in or queried from [`QueuePair::query`].
    pub fn pkey_index(&self) -> u16 {
        self.attr.pkey_index
    }

    /// Setup the primary physical port number associated with this [`QueuePair`].
    ///
    /// # Notice
    ///
    /// RDMA port number starts with `1`.
    ///
    pub fn setup_port(&mut self, port_num: u8) -> &mut Self {
        self.attr.port_num = port_num;
        self.attr_mask |= QueuePairAttributeMask::Port;
        self
    }

    /// Setup the queue key (QKey) for this [`QueuePair`].
    pub fn setup_qkey(&mut self, qkey: u32) -> &mut Self {
        self.attr.qkey = qkey;
        self.attr_mask |= QueuePairAttributeMask::QueueKey;
        self
    }

    /// Get the primary physical port number you filled in or queried from [`QueuePair::query`].
    pub fn port(&self) -> u8 {
        self.attr.port_num
    }

    /// Get the queue key (QKey) you filled in or queried from [`QueuePair::query`].
    pub fn qkey(&self) -> u32 {
        self.attr.qkey
    }

    /// Setup allowed remote operations for incoming packets. It's either 0 or
    /// the bitwise `OR` of one or more of the following flags.
    ///
    /// - [`AccessFlags::RemoteWrite`]: Allowing incoming RDMA Writes on this [`QueuePair`]
    /// - [`AccessFlags::RemoteRead`]: Allowing incoming RDMA Reads on this [`QueuePair`]
    /// - [`AccessFlags::RemoteAtomic`]: Allowing incoming Atomic operations on this [`QueuePair`]
    ///
    /// # Notice
    ///
    /// Only valid for [`ReliableConnection`] and [`UnreliableConnection`] [`QueuePair`]s.
    ///
    /// [`ReliableConnection`]: QueuePairType::ReliableConnection
    /// [`UnreliableConnection`]: QueuePairType::UnreliableConnection
    ///
    pub fn setup_access_flags(&mut self, access_flags: AccessFlags) -> &mut Self {
        self.attr.qp_access_flags = access_flags.bits as _;
        self.attr_mask |= QueuePairAttributeMask::AccessFlags;
        self
    }

    /// Get the allowed remote operations for incoming packets you filled in or queried from
    /// [`QueuePair::query`].
    pub fn access_flags(&self) -> AccessFlags {
        AccessFlags::from(self.attr.qp_access_flags as i32)
    }

    /// Setup the path MTU, which is the maximum payload size of a packet that can be transferred in
    /// the path. Just like TCP's MTU.
    ///
    /// # Notice
    ///
    /// Only valid for [`ReliableConnection`] and [`UnreliableConnection`] [`QueuePair`]s.
    ///
    /// [`ReliableConnection`]: QueuePairType::ReliableConnection
    /// [`UnreliableConnection`]: QueuePairType::UnreliableConnection
    ///
    pub fn setup_path_mtu(&mut self, path_mtu: Mtu) -> &mut Self {
        self.attr.path_mtu = path_mtu as _;
        self.attr_mask |= QueuePairAttributeMask::PathMtu;
        self
    }

    /// Get the path MTU you filled in or queried from [`QueuePair::query`].
    pub fn path_mtu(&self) -> Mtu {
        self.attr.path_mtu.into()
    }

    /// Setup the destination [`QueuePair`] number for setting up a new connection, 24 bits only.
    /// After connection set up, you could only send data to / recv data from this [`QueuePair`]
    /// number.
    ///
    /// # Notice
    ///
    /// Only valid for [`ReliableConnection`] and [`UnreliableConnection`] [`QueuePair`]s.
    ///
    /// [`ReliableConnection`]: QueuePairType::ReliableConnection
    /// [`UnreliableConnection`]: QueuePairType::UnreliableConnection
    ///
    pub fn setup_dest_qp_num(&mut self, dest_qp_num: u32) -> &mut Self {
        self.attr.dest_qp_num = dest_qp_num;
        self.attr_mask |= QueuePairAttributeMask::DestinationQueuePairNumber;
        self
    }

    /// Get the destination [`QueuePair`] number you filled in or queried from [`QueuePair::query`].
    pub fn dest_qp_num(&self) -> u32 {
        self.attr.dest_qp_num
    }

    /// Setup the initial Packet Sequence Number (PSN) required for received packets for this
    /// [`QueuePair`], which means this should be exactly the same with remote side's sq psn.
    /// 24 bits only.
    ///
    /// # Notice
    ///
    /// Only valid for [`ReliableConnection`] and [`UnreliableConnection`] [`QueuePair`]s.
    ///
    /// [`ReliableConnection`]: QueuePairType::ReliableConnection
    /// [`UnreliableConnection`]: QueuePairType::UnreliableConnection
    ///
    pub fn setup_rq_psn(&mut self, rq_psn: u32) -> &mut Self {
        self.attr.rq_psn = rq_psn;
        self.attr_mask |= QueuePairAttributeMask::ReceiveQueuePacketSequenceNumber;
        self
    }

    /// Get the initial Packet Sequence Number (PSN) required for received packets you filled in or
    /// queried from [`QueuePair::query`].
    pub fn rq_psn(&self) -> u32 {
        self.attr.rq_psn
    }

    /// Setup the initial Packet Sequence Number (PSN) to be used in sent packets from this
    /// [`QueuePair`], 24 bits only.
    pub fn setup_sq_psn(&mut self, sq_psn: u32) -> &mut Self {
        self.attr.sq_psn = sq_psn;
        self.attr_mask |= QueuePairAttributeMask::SendQueuePacketSequenceNumber;
        self
    }

    /// Get the initial Packet Sequence Number (PSN) required for sent packets you filled in or
    /// queried from [`QueuePair::query`].
    pub fn sq_psn(&self) -> u32 {
        self.attr.sq_psn
    }

    /// Setup the number of RDMA Read & atomic operations outstanding at any time that can be
    /// handled by this [`QueuePair`] as an **initiator**.
    ///
    /// # Notice
    ///
    /// Only valid for [`ReliableConnection`] [`QueuePair`]s.
    ///
    /// [`ReliableConnection`]: QueuePairType::ReliableConnection
    ///
    pub fn setup_max_read_atomic(&mut self, max_read_atomic: u8) -> &mut Self {
        self.attr.max_rd_atomic = max_read_atomic;
        self.attr_mask |= QueuePairAttributeMask::MaxReadAtomic;
        self
    }

    /// Get the the number of RDMA Read & atomic operations outstanding at any time you filled in or
    /// queried from [`QueuePair::query`].
    pub fn max_read_atomic(&self) -> u8 {
        self.attr.max_rd_atomic
    }

    /// Setup the number of RDMA Read & atomic operations outstanding at any time that can be
    /// handled by this [`QueuePair`] as a **destination**.
    ///
    /// # Notice
    ///
    /// Only valid for [`ReliableConnection`] [`QueuePair`]s.
    ///
    /// [`ReliableConnection`]: QueuePairType::ReliableConnection
    ///
    pub fn setup_max_dest_read_atomic(&mut self, max_dest_read_atomic: u8) -> &mut Self {
        self.attr.max_dest_rd_atomic = max_dest_read_atomic;
        self.attr_mask |= QueuePairAttributeMask::MaxDestinationReadAtomic;
        self
    }

    /// Get the the destination number of RDMA Read & atomic operations outstanding at any time you
    /// filled in or queried from [`QueuePair::query`].
    pub fn max_dest_read_atomic(&self) -> u8 {
        self.attr.max_dest_rd_atomic
    }

    /// Setup the minimum Receiver Not Ready (RNR) NACK timeout. When an incoming message to this
    /// [`QueuePair`] should consume a Work Request from the Receive Queue, but not Work Request is
    /// outstanding on that Queue, the [`QueuePair`] will send an RNR NAK packet to the initiator.
    /// It does not affect RNR NAKs sent for other reasons.
    pub fn setup_min_rnr_timer(&mut self, min_rnr_timer: u8) -> &mut Self {
        self.attr.min_rnr_timer = min_rnr_timer;
        self.attr_mask |= QueuePairAttributeMask::MinResponderNotReadyTimer;
        self
    }

    /// Get the minimum Receiver Not Ready (RNR) NACK timeout you filled in or queried from
    /// [`QueuePair::query`].
    pub fn min_rnr_timer(&self) -> u8 {
        self.attr.min_rnr_timer
    }

    /// Setup the minimum timeout that a [`QueuePair`] waits for ACK / NACK from remote
    /// [`QueuePair`] before retransmitting the packet. The value `0` is special value which means
    /// wait an infinite time for the ACK / NACK. For any other value, the actual timeout time is
    /// 4.096 * 2 ^ timeout usec.
    ///
    /// # Notice
    ///
    /// By saying mininum, it means that the real retransmit time is hardware dependent, it could
    /// choose a longer retransmit time.
    ///
    pub fn setup_timeout(&mut self, timeout: u8) -> &mut Self {
        self.attr.timeout = timeout;
        self.attr_mask |= QueuePairAttributeMask::Timeout;
        self
    }

    /// Get the minimum timeout that a [`QueuePair`] waits for ACK / NACK from remote you filled in
    /// or queried from [`QueuePair::query`].
    pub fn timeout(&self) -> u8 {
        self.attr.timeout
    }

    /// Setup the total number of times that the [`QueuePair`] will try to resend the packets before
    /// reporting an error because the remote side doesn't answer in the primary path (send an ACK
    /// or NACK packet).
    ///
    /// # Notice
    ///
    /// While most of the documentations say that this is a 3 bits only value, it's actually varies
    /// between the underlying hardware driver implementation. You could provide a value more than 7,
    /// but it may be overrided.
    pub fn setup_retry_cnt(&mut self, retry_cnt: u8) -> &mut Self {
        self.attr.retry_cnt = retry_cnt;
        self.attr_mask |= QueuePairAttributeMask::RetryCount;
        self
    }

    /// Get the total number of times that the [`QueuePair`] will try to resend the packets before
    /// reporting an error, the value would be you filled in or queried from [`QueuePair::query`].
    pub fn retry_cnt(&self) -> u8 {
        self.attr.retry_cnt
    }

    /// Setup the total number of times that the [`QueuePair`] will try to resend the packets when
    /// an Receiver Not Ready (RNR) NACK was sent by the remote [`QueuePair`] before reporting an
    /// error.
    pub fn setup_rnr_retry(&mut self, rnr_retry: u8) -> &mut Self {
        self.attr.rnr_retry = rnr_retry;
        self.attr_mask |= QueuePairAttributeMask::ResponderNotReadyRetryCount;
        self
    }

    /// Get the total number of times that the [`QueuePair`] will try to resend the packets when
    /// an Receiver Not Ready (RNR) NACK was sent by the remote [`QueuePair`] before reporting an
    /// error, the value would be you filled in or queried from [`QueuePair::query`].
    pub fn rnr_retry(&self) -> u8 {
        self.attr.rnr_retry
    }

    /// Setup the address vector of the primary path which describes the path information of the
    /// remote [`QueuePair`], for detailed information, you could take [`AddressHandleAttribute`] as
    /// a reference.
    pub fn setup_address_vector(&mut self, ah_attr: &AddressHandleAttribute) -> &mut Self {
        self.attr.ah_attr = ah_attr.attr;
        self.attr_mask |= QueuePairAttributeMask::AddressVector;
        self
    }
}

/// Describes the requested attributes of a newly created [`QueuePair`].
pub struct QueuePairInitAttribute {
    init_attr: ibv_qp_init_attr,
}

impl Default for QueuePairInitAttribute {
    fn default() -> Self {
        Self::new()
    }
}

impl QueuePairInitAttribute {
    pub fn new() -> Self {
        QueuePairInitAttribute {
            init_attr: unsafe { MaybeUninit::zeroed().assume_init() },
        }
    }

    /// Get the maximum number of outstanding Work Requests that can be posted to the Send Queue in
    /// that QP.
    pub fn max_send_wr(&self) -> u32 {
        self.init_attr.cap.max_send_wr
    }

    /// Get the maximum number of outstanding Work Requests that can be posted to the Receive Queue
    /// in that QP.
    pub fn max_recv_wr(&self) -> u32 {
        self.init_attr.cap.max_recv_wr
    }

    /// The maximum number of scatter/gather elements in any Work Request that can be posted to the
    /// Send Queue in that QP.
    pub fn max_send_sge(&self) -> u32 {
        self.init_attr.cap.max_send_sge
    }

    /// The maximum number of scatter/gather elements in any Work Request that can be posted to the
    /// Receive Queue in that QP.
    pub fn max_recv_sge(&self) -> u32 {
        self.init_attr.cap.max_recv_sge
    }

    /// The maximum message size (in bytes) that can be posted inline to the Send Queue. 0, if no
    /// inline message is requested.
    pub fn max_inline_data(&self) -> u32 {
        self.init_attr.cap.max_inline_data
    }
}

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
) -> Result<(), ModifyQueuePairError> {
    if !RC_QP_STATE_TABLE[cur_state as usize][next_state as usize].valid {
        return Err(ModifyQueuePairErrorKind::InvalidTransition {
            cur_state,
            next_state,
            source: io::Error::from_raw_os_error(libc::EINVAL),
        }
        .into());
    }

    let required = RC_QP_STATE_TABLE[cur_state as usize][next_state as usize].required_mask;
    let optional = RC_QP_STATE_TABLE[cur_state as usize][next_state as usize].optional_mask;
    let invalid = get_invalid_mask(attr_mask, required, optional);
    let needed = get_needed_mask(attr_mask, required);
    if invalid.bits == 0 && needed.bits == 0 {
        Ok(())
    } else {
        Err(ModifyQueuePairErrorKind::InvalidAttributeMask {
            cur_state,
            next_state,
            invalid,
            needed,
            source: io::Error::from_raw_os_error(libc::EINVAL),
        }
        .into())
    }
}

/// A handle that user would use to fill the concrete information of the RDMA Work Request.
pub struct WorkRequestHandle<'g, G: PostSendGuard + ?Sized> {
    guard: &'g mut G,
}

/// Setup scatter gather entry (sge) for a Work Request.
pub trait SetScatterGatherEntry {
    /// # Safety
    ///
    /// Set a local buffer to the request; note that the lifetime of the buffer associated with the
    /// sge is managed by the caller.
    unsafe fn setup_sge(self, lkey: u32, addr: u64, length: u32);
    /// # Safety
    ///
    /// Set a list of local buffers to the request; note that the lifetime of the buffer associated
    /// with the sge is managed by the caller.
    unsafe fn setup_sge_list(self, sg_list: &[ibv_sge]);
}

/// Setup inline data for a Work Request.
pub trait SetInlineData {
    /// Attach data to current Work Request by `memcpy` the `buf` into it.
    fn setup_inline_data(self, buf: &[u8]);

    /// Attach data to current Work Request by `memcpy` the `bufs` into it continuously.
    fn setup_inline_data_list(self, bufs: &[IoSlice<'_>]);
}

/// A handle to set local buffer for RDMA Send & RDMA Write request, a [`QueuePair`] should hold
/// only one [`LocalBufferHandle`] at the same time.
pub struct LocalBufferHandle<'g, G: PostSendGuard> {
    guard: &'g mut G,
}

impl<G: PostSendGuard> SetInlineData for LocalBufferHandle<'_, G> {
    fn setup_inline_data(self, buf: &[u8]) {
        self.guard.setup_inline_data(buf);
    }

    fn setup_inline_data_list(self, bufs: &[IoSlice<'_>]) {
        self.guard.setup_inline_data_list(bufs);
    }
}

impl<G: PostSendGuard> SetScatterGatherEntry for LocalBufferHandle<'_, G> {
    unsafe fn setup_sge(self, lkey: u32, addr: u64, length: u32) {
        self.guard.setup_sge(lkey, addr, length);
    }

    unsafe fn setup_sge_list(self, sg_list: &[ibv_sge]) {
        self.guard.setup_sge_list(sg_list);
    }
}

impl<'g, G: PostSendGuard> WorkRequestHandle<'g, G> {
    pub fn setup_send(self) -> LocalBufferHandle<'g, G> {
        self.guard.setup_send();
        LocalBufferHandle { guard: self.guard }
    }

    pub fn setup_send_imm(self, imm_data: u32) -> LocalBufferHandle<'g, G> {
        self.guard.setup_send_imm(imm_data);
        LocalBufferHandle { guard: self.guard }
    }

    pub fn setup_ud_addr(self, ah: &AddressHandle, remote_qpn: u32, remote_qkey: u32) -> Self {
        let WorkRequestHandle { guard } = self;
        guard.setup_ud_addr(ah, remote_qpn, remote_qkey);
        WorkRequestHandle { guard }
    }

    pub fn setup_write(self, rkey: u32, remote_addr: u64) -> LocalBufferHandle<'g, G> {
        self.guard.setup_write(rkey, remote_addr);
        LocalBufferHandle { guard: self.guard }
    }

    pub fn setup_write_imm(self, rkey: u32, remote_addr: u64, imm_data: u32) -> LocalBufferHandle<'g, G> {
        self.guard.setup_write_imm(rkey, remote_addr, imm_data);
        LocalBufferHandle { guard: self.guard }
    }

    pub fn setup_read(self, rkey: u32, remote_addr: u64) -> LocalBufferHandle<'g, G> {
        self.guard.setup_read(rkey, remote_addr);
        LocalBufferHandle { guard: self.guard }
    }
}

/// The basic [`PostSendGuard`] that works for [`BasicQueuePair`] which doesn't support [`ibv_wr_*`]
/// APIs.
///
/// [`ibv_wr_*`]: https://manpages.debian.org/testing/libibverbs-dev/ibv_wr_post.3.en.html
///
pub struct BasicPostSendGuard<'g> {
    qp: NonNull<ibv_qp>,
    wrs: Vec<ibv_send_wr>,
    sges: Vec<ibv_sge>,
    inline_buffers: Vec<Vec<u8>>,
    _phantom: PhantomData<&'g ()>,
}

impl PostSendGuard for BasicPostSendGuard<'_> {
    fn construct_wr(&mut self, wr_id: u64, wr_flags: WorkRequestFlags) -> WorkRequestHandle<'_, Self> {
        self.wrs.push(ibv_send_wr {
            wr_id,
            next: null_mut(),
            sg_list: null_mut(),
            num_sge: 0,
            opcode: 0,
            send_flags: wr_flags.bits,
            ..unsafe { MaybeUninit::zeroed().assume_init() }
        });

        WorkRequestHandle { guard: self }
    }

    /// Post all previously setuped RDMA Work Requests into the [`BasicQueuePair`]'s send queue,
    /// using [`ibv_post_send`].
    ///
    /// [`ibv_post_send`]: https://man7.org/linux/man-pages/man3/ibv_post_send.3.html
    ///
    fn post(mut self) -> Result<(), PostSendError> {
        let mut sge_index = 0;

        for i in 0..self.wrs.len() {
            // Set up the linked list
            if i < self.wrs.len() - 1 {
                self.wrs[i].next = &mut self.wrs[i + 1] as *mut _;
            } else {
                self.wrs[i].next = null_mut();
            }

            // Set up the sg_list
            if self.wrs[i].num_sge > 0 {
                self.wrs[i].sg_list = &mut self.sges[sge_index] as *mut _;
                sge_index += self.wrs[i].num_sge as usize;
            }
        }

        let mut bad_wr: *mut ibv_send_wr = null_mut();
        let ret = unsafe { ibv_post_send(self.qp.as_ptr(), self.wrs.as_mut_ptr(), &mut bad_wr) };
        match ret {
            0 => Ok(()),
            libc::EINVAL => Err(PostSendError::InvalidWorkRequest(io::Error::from_raw_os_error(
                libc::EINVAL,
            ))),
            libc::ENOMEM => Err(PostSendError::NotEnoughResources(io::Error::from_raw_os_error(
                libc::ENOMEM,
            ))),
            libc::EFAULT => Err(PostSendError::InvalidQueuePair(io::Error::from_raw_os_error(
                libc::EFAULT,
            ))),
            err => Err(PostSendError::Ibverbs(io::Error::from_raw_os_error(err))),
        }
    }
}

impl private_traits::PostSendGuard for BasicPostSendGuard<'_> {
    fn setup_send(&mut self) {
        self.wrs.last_mut().unwrap().opcode = WorkRequestOperationType::Send as _;
    }

    fn setup_send_imm(&mut self, imm_data: u32) {
        self.wrs.last_mut().unwrap().opcode = WorkRequestOperationType::SendWithImmediate as _;
        self.wrs.last_mut().unwrap().imm_data_invalidated_rkey_union.imm_data = imm_data;
    }

    fn setup_ud_addr(&mut self, ah: &AddressHandle, remote_qpn: u32, remote_qkey: u32) {
        self.wrs.last_mut().unwrap().wr.ud.ah = unsafe { ah.ah().as_ptr() };
        self.wrs.last_mut().unwrap().wr.ud.remote_qpn = remote_qpn;
        self.wrs.last_mut().unwrap().wr.ud.remote_qkey = remote_qkey;
    }

    fn setup_write(&mut self, rkey: u32, remote_addr: u64) {
        self.wrs.last_mut().unwrap().opcode = WorkRequestOperationType::Write as _;
        self.wrs.last_mut().unwrap().wr.rdma.remote_addr = remote_addr;
        self.wrs.last_mut().unwrap().wr.rdma.rkey = rkey;
    }

    fn setup_write_imm(&mut self, rkey: u32, remote_addr: u64, imm_data: u32) {
        self.wrs.last_mut().unwrap().opcode = WorkRequestOperationType::WriteWithImmediate as _;
        self.wrs.last_mut().unwrap().wr.rdma.remote_addr = remote_addr;
        self.wrs.last_mut().unwrap().wr.rdma.rkey = rkey;
        self.wrs.last_mut().unwrap().imm_data_invalidated_rkey_union.imm_data = imm_data;
    }

    fn setup_read(&mut self, rkey: u32, remote_addr: u64) {
        self.wrs.last_mut().unwrap().opcode = WorkRequestOperationType::Read as _;
        self.wrs.last_mut().unwrap().wr.rdma.remote_addr = remote_addr;
        self.wrs.last_mut().unwrap().wr.rdma.rkey = rkey;
    }

    // Memcopy inline buffer manually to make it safe for user to modify / drop
    // the buffer before calling `ibv_post_send`.
    //
    // This should be slower than C implementation, compared to memcopy only once
    // in `ibv_post_send`, we would do twice. But this would keep our interface
    // consistent and safe.
    fn setup_inline_data(&mut self, buf: &[u8]) {
        self.inline_buffers.push(Vec::from(buf));

        unsafe {
            self.sges.push(ibv_sge {
                addr: self.inline_buffers.last().unwrap_unchecked().as_ptr() as u64,
                length: self.inline_buffers.last().unwrap_unchecked().len() as u32,
                lkey: 0,
            });
        }

        self.wrs.last_mut().unwrap().send_flags |= WorkRequestFlags::Inline.bits;
        self.wrs.last_mut().unwrap().num_sge += 1;
    }

    // According to the `ibv_wr_set_inline_data_list` implementation in rdma-core,
    // most providers are just memcopying the list into a continuous buffer and use
    // a single sge to send it. We just mimic the behavior here.
    fn setup_inline_data_list(&mut self, bufs: &[IoSlice<'_>]) {
        self.inline_buffers
            .push(bufs.iter().fold(Vec::<u8>::new(), |mut res, slice| {
                res.append(&mut slice.to_vec().clone());
                res
            }));

        unsafe {
            self.sges.push(ibv_sge {
                addr: self.inline_buffers.last().unwrap_unchecked().as_ptr() as u64,
                length: self.inline_buffers.last().unwrap_unchecked().len() as u32,
                lkey: 0,
            });
        }

        self.wrs.last_mut().unwrap().send_flags |= WorkRequestFlags::Inline.bits;
        self.wrs.last_mut().unwrap().num_sge += 1;
    }

    unsafe fn setup_sge(&mut self, lkey: u32, addr: u64, length: u32) {
        self.sges.push(ibv_sge { addr, length, lkey });
        self.wrs.last_mut().unwrap_unchecked().num_sge = 1;
    }

    unsafe fn setup_sge_list(&mut self, sg_list: &[ibv_sge]) {
        self.sges.extend_from_slice(sg_list);
        self.wrs.last_mut().unwrap_unchecked().num_sge = sg_list.len() as _;
    }
}

/// The extended [`PostSendGuard`] that works for [`ExtendedQueuePair`] which supports [`ibv_wr_*`]
/// APIs, should provide better performance.
///
/// [`ibv_wr_*`]: https://manpages.debian.org/testing/libibverbs-dev/ibv_wr_post.3.en.html
///
pub struct ExtendedPostSendGuard<'qp> {
    qp_ex: NonNull<ibv_qp_ex>,
    _phantom: PhantomData<&'qp ()>,
}

impl PostSendGuard for ExtendedPostSendGuard<'_> {
    fn construct_wr(&mut self, wr_id: u64, wr_flags: WorkRequestFlags) -> WorkRequestHandle<'_, Self> {
        unsafe {
            self.qp_ex.as_mut().wr_id = wr_id;
            self.qp_ex.as_mut().wr_flags = wr_flags.bits;
        }
        WorkRequestHandle { guard: self }
    }

    /// Post all previously setuped RDMA Work Requests into the [`ExtendedQueuePair`]'s send queue,
    /// using [`ibv_wr_complete`].
    ///
    /// [`ibv_wr_complete`]: https://manpages.debian.org/testing/libibverbs-dev/ibv_wr_post.3.en.html
    ///
    fn post(self) -> Result<(), PostSendError> {
        let ret: i32 = unsafe { ibv_wr_complete(self.qp_ex.as_ptr()) };

        // do not run the dtor
        std::mem::forget(self);

        match ret {
            0 => Ok(()),
            libc::EINVAL => Err(PostSendError::InvalidWorkRequest(io::Error::from_raw_os_error(
                libc::EINVAL,
            ))),
            libc::ENOMEM => Err(PostSendError::NotEnoughResources(io::Error::from_raw_os_error(
                libc::ENOMEM,
            ))),
            libc::EFAULT => Err(PostSendError::InvalidQueuePair(io::Error::from_raw_os_error(
                libc::EFAULT,
            ))),
            err => Err(PostSendError::Ibverbs(io::Error::from_raw_os_error(err))),
        }
    }
}

impl private_traits::PostSendGuard for ExtendedPostSendGuard<'_> {
    fn setup_send(&mut self) {
        unsafe { ibv_wr_send(self.qp_ex.as_ptr()) };
    }

    fn setup_send_imm(&mut self, imm_data: u32) {
        unsafe { ibv_wr_send_imm(self.qp_ex.as_ptr(), imm_data) };
    }

    fn setup_ud_addr(&mut self, ah: &AddressHandle, remote_qpn: u32, remote_qkey: u32) {
        unsafe {
            ibv_wr_set_ud_addr(self.qp_ex.as_ptr(), ah.ah().as_ptr(), remote_qpn, remote_qkey);
        }
    }

    fn setup_write(&mut self, rkey: u32, remote_addr: u64) {
        unsafe { ibv_wr_rdma_write(self.qp_ex.as_ptr(), rkey, remote_addr) };
    }

    fn setup_write_imm(&mut self, rkey: u32, remote_addr: u64, imm_data: u32) {
        unsafe { ibv_wr_rdma_write_imm(self.qp_ex.as_ptr(), rkey, remote_addr, imm_data) };
    }

    fn setup_read(&mut self, rkey: u32, remote_addr: u64) {
        unsafe { ibv_wr_rdma_read(self.qp_ex.as_ptr(), rkey, remote_addr) };
    }

    fn setup_inline_data(&mut self, buf: &[u8]) {
        unsafe { ibv_wr_set_inline_data(self.qp_ex.as_ptr(), buf.as_ptr() as _, buf.len()) }
    }

    fn setup_inline_data_list(&mut self, bufs: &[IoSlice<'_>]) {
        let mut buf_list = Vec::with_capacity(bufs.len());

        buf_list.extend(bufs.iter().map(|x| ibv_data_buf {
            addr: x.as_ptr() as _,
            length: x.len(),
        }));

        unsafe { ibv_wr_set_inline_data_list(self.qp_ex.as_ptr(), buf_list.len(), buf_list.as_ptr()) };
    }

    unsafe fn setup_sge(&mut self, lkey: u32, addr: u64, length: u32) {
        ibv_wr_set_sge(self.qp_ex.as_ptr(), lkey, addr, length);
    }

    unsafe fn setup_sge_list(&mut self, sg_list: &[ibv_sge]) {
        ibv_wr_set_sge_list(self.qp_ex.as_ptr(), sg_list.len(), sg_list.as_ptr());
    }
}

impl Drop for ExtendedPostSendGuard<'_> {
    fn drop(&mut self) {
        unsafe { ibv_wr_abort(self.qp_ex.as_ptr()) };
    }
}

/// A [`PostRecvGuard`] that can be used to construct and post recv RDMA Work Requests.
pub struct PostRecvGuard<'qp> {
    qp: NonNull<ibv_qp>,
    wrs: Vec<ibv_recv_wr>,
    sges: Vec<ibv_sge>,
    _phantom: PhantomData<&'qp ()>,
}

impl<'qp> PostRecvGuard<'qp> {
    /// Construct a new [`RecvWorkRequestHandle`] for setting up a new RDMA Work Request, every
    /// [`QueuePair`] should hold only one [`RecvWorkRequestHandle`] at the same time.
    pub fn construct_wr<'g>(&'g mut self, wr_id: u64) -> RecvWorkRequestHandle<'g, 'qp> {
        self.wrs.push(ibv_recv_wr {
            wr_id,
            next: null_mut(),
            sg_list: null_mut(),
            num_sge: 0,
        });

        RecvWorkRequestHandle { guard: self }
    }

    pub fn post(mut self) -> Result<(), PostRecvError> {
        let mut sge_index = 0;

        for i in 0..self.wrs.len() {
            // Set up the linked list
            if i < self.wrs.len() - 1 {
                self.wrs[i].next = &mut self.wrs[i + 1] as *mut _;
            } else {
                self.wrs[i].next = null_mut();
            }

            // Set up the sg_list
            if self.wrs[i].num_sge > 0 {
                self.wrs[i].sg_list = &mut self.sges[sge_index] as *mut _;
                sge_index += self.wrs[i].num_sge as usize;
            }
        }

        let mut bad_wr: *mut ibv_recv_wr = null_mut();
        let ret = unsafe { ibv_post_recv(self.qp.as_ptr(), self.wrs.as_mut_ptr(), &mut bad_wr) };
        match ret {
            0 => Ok(()),
            libc::EINVAL => Err(PostRecvError::InvalidWorkRequest(io::Error::from_raw_os_error(
                libc::EINVAL,
            ))),
            libc::ENOMEM => Err(PostRecvError::NotEnoughResources(io::Error::from_raw_os_error(
                libc::ENOMEM,
            ))),
            libc::EFAULT => Err(PostRecvError::InvalidQueuePair(io::Error::from_raw_os_error(
                libc::EFAULT,
            ))),
            err => Err(PostRecvError::Ibverbs(io::Error::from_raw_os_error(err))),
        }
    }
}

/// A handle that user would use to fill the concrete information of the **recv** RDMA Work Request.
pub struct RecvWorkRequestHandle<'g, 'qp> {
    guard: &'g mut PostRecvGuard<'qp>,
}

impl SetScatterGatherEntry for RecvWorkRequestHandle<'_, '_> {
    unsafe fn setup_sge(self, lkey: u32, addr: u64, length: u32) {
        assert!(!self.guard.wrs.is_empty());
        self.guard.wrs.last_mut().unwrap_unchecked().num_sge = 1;
        self.guard.sges.push(ibv_sge { addr, length, lkey });
    }

    unsafe fn setup_sge_list(self, sg_list: &[ibv_sge]) {
        assert!(!self.guard.wrs.is_empty());
        self.guard.wrs.last_mut().unwrap_unchecked().num_sge = sg_list.len() as _;
        self.guard.sges.extend_from_slice(sg_list);
    }
}

/// A unified interface for [`BasicQueuePair`] and [`ExtendedQueuePair`], implemented with enum
/// dispatching.
#[derive(Debug)]
pub enum GenericQueuePair {
    /// Variant for a Basic Queue Pair
    Basic(BasicQueuePair),
    /// Variant for an Extended Queue Pair
    Extended(ExtendedQueuePair),
}

impl QueuePair for GenericQueuePair {
    unsafe fn qp(&self) -> NonNull<ibv_qp> {
        match self {
            GenericQueuePair::Basic(qp) => qp.qp(),
            GenericQueuePair::Extended(qp) => qp.qp(),
        }
    }

    fn qp_number(&self) -> u32 {
        match self {
            GenericQueuePair::Basic(qp) => qp.qp_number(),
            GenericQueuePair::Extended(qp) => qp.qp_number(),
        }
    }

    fn modify(&mut self, attr: &QueuePairAttribute) -> Result<(), ModifyQueuePairError> {
        match self {
            GenericQueuePair::Basic(qp) => qp.modify(attr),
            GenericQueuePair::Extended(qp) => qp.modify(attr),
        }
    }

    fn start_post_recv(&mut self) -> PostRecvGuard<'_> {
        match self {
            GenericQueuePair::Basic(qp) => qp.start_post_recv(),
            GenericQueuePair::Extended(qp) => qp.start_post_recv(),
        }
    }

    type Guard<'g>
        = GenericPostSendGuard<'g>
    where
        Self: 'g;

    fn start_post_send(&mut self) -> Self::Guard<'_> {
        match self {
            GenericQueuePair::Basic(qp) => GenericPostSendGuard::Basic(qp.start_post_send()),
            GenericQueuePair::Extended(qp) => GenericPostSendGuard::Extended(qp.start_post_send()),
        }
    }
}

/// A unified interface for [`BasicPostSendGuard`] and [`ExtendedPostSendGuard`], implemented with
/// enum dispatching.
pub enum GenericPostSendGuard<'g> {
    Basic(BasicPostSendGuard<'g>),
    Extended(ExtendedPostSendGuard<'g>),
}

impl PostSendGuard for GenericPostSendGuard<'_> {
    fn construct_wr(&mut self, wr_id: u64, wr_flags: WorkRequestFlags) -> WorkRequestHandle<'_, Self> {
        match self {
            GenericPostSendGuard::Basic(guard) => {
                guard.construct_wr(wr_id, wr_flags);
                WorkRequestHandle { guard: self }
            },
            GenericPostSendGuard::Extended(guard) => {
                guard.construct_wr(wr_id, wr_flags);
                WorkRequestHandle { guard: self }
            },
        }
    }

    fn post(self) -> Result<(), PostSendError> {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.post(),
            GenericPostSendGuard::Extended(guard) => guard.post(),
        }
    }
}

impl private_traits::PostSendGuard for GenericPostSendGuard<'_> {
    fn setup_send(&mut self) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_send(),
            GenericPostSendGuard::Extended(guard) => guard.setup_send(),
        }
    }

    fn setup_send_imm(&mut self, imm_data: u32) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_send_imm(imm_data),
            GenericPostSendGuard::Extended(guard) => guard.setup_send_imm(imm_data),
        }
    }

    fn setup_ud_addr(&mut self, ah: &AddressHandle, remote_qpn: u32, remote_qkey: u32) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_ud_addr(ah, remote_qpn, remote_qkey),
            GenericPostSendGuard::Extended(guard) => guard.setup_ud_addr(ah, remote_qpn, remote_qkey),
        }
    }

    fn setup_write(&mut self, rkey: u32, remote_addr: u64) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_write(rkey, remote_addr),
            GenericPostSendGuard::Extended(guard) => guard.setup_write(rkey, remote_addr),
        }
    }

    fn setup_write_imm(&mut self, rkey: u32, remote_addr: u64, imm_data: u32) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_write_imm(rkey, remote_addr, imm_data),
            GenericPostSendGuard::Extended(guard) => guard.setup_write_imm(rkey, remote_addr, imm_data),
        }
    }

    fn setup_read(&mut self, rkey: u32, remote_addr: u64) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_read(rkey, remote_addr),
            GenericPostSendGuard::Extended(guard) => guard.setup_read(rkey, remote_addr),
        }
    }

    fn setup_inline_data(&mut self, buf: &[u8]) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_inline_data(buf),
            GenericPostSendGuard::Extended(guard) => guard.setup_inline_data(buf),
        }
    }

    fn setup_inline_data_list(&mut self, bufs: &[IoSlice<'_>]) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_inline_data_list(bufs),
            GenericPostSendGuard::Extended(guard) => guard.setup_inline_data_list(bufs),
        }
    }

    unsafe fn setup_sge(&mut self, lkey: u32, addr: u64, length: u32) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_sge(lkey, addr, length),
            GenericPostSendGuard::Extended(guard) => guard.setup_sge(lkey, addr, length),
        }
    }

    unsafe fn setup_sge_list(&mut self, sg_list: &[ibv_sge]) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_sge_list(sg_list),
            GenericPostSendGuard::Extended(guard) => guard.setup_sge_list(sg_list),
        }
    }
}

impl From<BasicQueuePair> for GenericQueuePair {
    /// Converts a BasicQueuePair into a GenericQueuePair.
    ///
    /// This allows for easy creation of a GenericQueuePair from a BasicQueuePair.
    ///
    /// # Examples
    ///
    /// ```compile_fail
    /// let basic_qp = builder.build().unwarp();
    /// let generic_qp: GenericQueuePair = basic_qp.into();
    /// ```
    fn from(qp: BasicQueuePair) -> Self {
        GenericQueuePair::Basic(qp)
    }
}

impl From<ExtendedQueuePair> for GenericQueuePair {
    /// Converts an ExtendedQueuePair into a GenericQueuePair.
    ///
    /// This allows for easy creation of a GenericQueuePair from an ExtendedQueuePair.
    ///
    /// # Examples
    ///
    /// ```compile_fail
    /// let extended_qp = builder.build_ex().unwarp();
    /// let generic_qp: GenericQueuePair = extended_qp.into();
    /// ```
    fn from(qp: ExtendedQueuePair) -> Self {
        GenericQueuePair::Extended(qp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ibverbs::address::GidType;
    use crate::ibverbs::completion::GenericCompletionQueue;
    use crate::ibverbs::device;

    #[test]
    fn test_query_qp() -> Result<(), Box<dyn std::error::Error>> {
        let device_list = device::DeviceList::new()?;
        match device_list.get(0) {
            Some(device) => {
                let ctx = device.open()?;

                let pd = ctx.alloc_pd()?;
                let memory = [1, 2, 3, 4];
                let mr_handle = memory.as_ptr() as usize;
                let mr = unsafe {
                    pd.reg_mr(mr_handle, 16, AccessFlags::LocalWrite | AccessFlags::RemoteWrite)
                        .unwrap()
                };

                let cq = GenericCompletionQueue::from(ctx.create_cq_builder().setup_cqe(2).build_ex()?);

                let mut qp = pd
                    .create_qp_builder()
                    .setup_send_cq(cq.clone())
                    .setup_recv_cq(cq.clone())
                    .build()?;

                let mut guard = qp.start_post_recv();
                unsafe {
                    let handle = guard.construct_wr(1);
                    handle.setup_sge(mr.lkey(), mr.get_ptr() as u64, 1);
                    match guard.post() {
                        Err(PostRecvError::InvalidWorkRequest(_)) => {},
                        other => panic!("Expected InvalidWorkRequest error, got: {other:?}"),
                    }
                }

                let mut attr = QueuePairAttribute::new();
                attr.setup_state(QueuePairState::Init)
                    .setup_pkey_index(0)
                    .setup_port(1)
                    .setup_access_flags(AccessFlags::RemoteWrite);
                qp.modify(&attr)?;

                let mut attr = QueuePairAttribute::new();
                attr.setup_state(QueuePairState::ReadyToReceive)
                    .setup_path_mtu(Mtu::Mtu1024)
                    .setup_dest_qp_num(1024)
                    .setup_rq_psn(1024)
                    .setup_max_dest_read_atomic(0)
                    .setup_min_rnr_timer(0);

                // setup address vector
                let mut ah_attr = AddressHandleAttribute::new();
                let gid_entries = ctx.query_gid_table().unwrap();
                let gid = gid_entries
                    .iter()
                    .find(|&&gid| !gid.gid().is_unicast_link_local() || gid.gid_type() == GidType::RoceV1)
                    .unwrap();

                ah_attr
                    .setup_dest_lid(1)
                    .setup_port(1)
                    .setup_service_level(1)
                    .setup_grh_src_gid_index(gid.gid_index().try_into().unwrap())
                    .setup_grh_dest_gid(&gid.gid())
                    .setup_grh_hop_limit(64);
                attr.setup_address_vector(&ah_attr);
                qp.modify(&attr)?;

                let mask = QueuePairAttributeMask::AccessFlags
                    | QueuePairAttributeMask::PathMtu
                    | QueuePairAttributeMask::DestinationQueuePairNumber
                    | QueuePairAttributeMask::Port;
                let (attr, init_attr) = qp.query(mask)?;

                assert_eq!(attr.access_flags(), AccessFlags::RemoteWrite);
                assert_eq!(attr.dest_qp_num(), 1024);
                assert_eq!(attr.path_mtu(), Mtu::Mtu1024);
                assert_eq!(attr.port(), 1);

                assert!(init_attr.max_send_wr() >= 16);
                assert!(init_attr.max_recv_wr() >= 16);
                assert!(init_attr.max_send_sge() >= 1);
                assert!(init_attr.max_recv_sge() >= 1);

                Ok(())
            },
            None => Ok(()),
        }
    }

    #[test]
    fn test_post_recv_errors() -> Result<(), Box<dyn std::error::Error>> {
        let device_list = device::DeviceList::new()?;
        match device_list.get(0) {
            Some(device) => {
                let ctx = device.open()?;

                let pd = ctx.alloc_pd()?;
                let memory = [1, 2, 3, 4];
                let mr_handle = memory.as_ptr() as usize;
                let mr = unsafe {
                    pd.reg_mr(mr_handle, 16, AccessFlags::LocalWrite | AccessFlags::RemoteWrite)
                        .unwrap()
                };

                let cq = GenericCompletionQueue::from(ctx.create_cq_builder().setup_cqe(2).build_ex()?);

                let mut qp = pd
                    .create_qp_builder()
                    .setup_send_cq(cq.clone())
                    .setup_recv_cq(cq.clone())
                    .setup_max_recv_wr(1)
                    .build()?;

                let mut guard = qp.start_post_recv();
                unsafe {
                    let handle = guard.construct_wr(1);
                    handle.setup_sge(mr.lkey(), mr.get_ptr() as u64, 1);
                    match guard.post() {
                        Err(PostRecvError::InvalidWorkRequest(_)) => {},
                        other => panic!("Expected InvalidWorkRequest error, got: {other:?}"),
                    }
                }

                let mut attr = QueuePairAttribute::new();
                attr.setup_state(QueuePairState::Init)
                    .setup_pkey_index(0)
                    .setup_port(1)
                    .setup_access_flags(AccessFlags::RemoteWrite);
                qp.modify(&attr)?;

                let mut attr = QueuePairAttribute::new();
                attr.setup_state(QueuePairState::ReadyToReceive)
                    .setup_path_mtu(Mtu::Mtu1024)
                    .setup_dest_qp_num(1024)
                    .setup_rq_psn(1024)
                    .setup_max_dest_read_atomic(0)
                    .setup_min_rnr_timer(0);

                // setup address vector
                let mut ah_attr = AddressHandleAttribute::new();
                let gid_entries = ctx.query_gid_table().unwrap();
                let gid = gid_entries
                    .iter()
                    .find(|&&gid| !gid.gid().is_unicast_link_local() || gid.gid_type() == GidType::RoceV1)
                    .unwrap();

                ah_attr
                    .setup_dest_lid(1)
                    .setup_port(1)
                    .setup_service_level(1)
                    .setup_grh_src_gid_index(gid.gid_index().try_into().unwrap())
                    .setup_grh_dest_gid(&gid.gid())
                    .setup_grh_hop_limit(64);
                attr.setup_address_vector(&ah_attr);
                qp.modify(&attr)?;

                let mut guard = qp.start_post_recv();
                for i in 0..128 {
                    unsafe {
                        let handle = guard.construct_wr(i);
                        handle.setup_sge(mr.lkey(), mr.get_ptr() as u64, 1);
                    }
                }
                match guard.post() {
                    Err(PostRecvError::NotEnoughResources(_)) => {},
                    other => panic!("Expected NotEnoughResources error, got: {other:?}"),
                }

                Ok(())
            },
            None => Ok(()),
        }
    }
}
