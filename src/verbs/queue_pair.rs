use bitmask_enum::bitmask;
use rdma_mummy_sys::{
    ibv_create_qp, ibv_create_qp_ex, ibv_data_buf, ibv_destroy_qp, ibv_modify_qp, ibv_post_recv, ibv_post_send, ibv_qp,
    ibv_qp_attr, ibv_qp_attr_mask, ibv_qp_cap, ibv_qp_create_send_ops_flags, ibv_qp_ex, ibv_qp_init_attr,
    ibv_qp_init_attr_ex, ibv_qp_init_attr_mask, ibv_qp_state, ibv_qp_to_qp_ex, ibv_qp_type, ibv_recv_wr,
    ibv_rx_hash_conf, ibv_send_flags, ibv_send_wr, ibv_sge, ibv_wr_abort, ibv_wr_complete, ibv_wr_opcode,
    ibv_wr_rdma_write, ibv_wr_send, ibv_wr_set_inline_data, ibv_wr_set_inline_data_list, ibv_wr_set_sge,
    ibv_wr_set_sge_list, ibv_wr_start,
};
use std::{
    io::{self, IoSlice},
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{null_mut, NonNull},
};

use super::{
    address::AddressHandleAttribute, completion::CompletionQueue, device_context::Mtu,
    protection_domain::ProtectionDomain, AccessFlags,
};

#[cfg(feature = "debug")]
use crate::verbs::address::Gid;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModifyQueuePairError {
    #[error("modify queue pair failed")]
    GenericError(#[from] io::Error),
    #[cfg(feature = "debug")]
    #[error("invalid transition from {cur_state:?} to {next_state:?}")]
    InvalidTransition {
        cur_state: QueuePairState,
        next_state: QueuePairState,
        source: io::Error,
    },
    #[cfg(feature = "debug")]
    #[error("invalid transition from {cur_state:?} to {next_state:?}, possible invalid masks {invalid:?}, possible needed masks {needed:?}")]
    InvalidAttributeMask {
        cur_state: QueuePairState,
        next_state: QueuePairState,
        invalid: QueuePairAttributeMask,
        needed: QueuePairAttributeMask,
        source: io::Error,
    },
    #[cfg(feature = "debug")]
    #[error("resolve route timed out, source gid index: {sgid_index}, destination gid: {gid}")]
    ResolveRouteTimedout {
        sgid_index: u8,
        gid: Gid,
        source: io::Error,
    },
    #[cfg(feature = "debug")]
    #[error("network unreachable, source gid index: {sgid_index}, destination gid: {gid}")]
    NetworkUnreachable {
        sgid_index: u8,
        gid: Gid,
        source: io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PostSendError {
    #[error("post send failed")]
    GenericError(#[from] io::Error),
    #[cfg(feature = "debug")]
    #[error("invalid value provided in work request")]
    InvalidWorkRequest(#[source] io::Error),
    #[cfg(feature = "debug")]
    #[error("invalid value provided in queue pair")]
    InvalidQueuePair(#[source] io::Error),
    #[cfg(feature = "debug")]
    #[error("send queue is full or not enough resources to complete this operation")]
    NotEnoughResources(#[source] io::Error),
}

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

#[bitmask(u32)]
#[bitmask_config(vec_debug)]
pub enum WorkRequestFlags {
    Fence = ibv_send_flags::IBV_SEND_FENCE.0,
    Signaled = ibv_send_flags::IBV_SEND_SIGNALED.0,
    Solicited = ibv_send_flags::IBV_SEND_SOLICITED.0,
    Inline = ibv_send_flags::IBV_SEND_INLINE.0,
    IpChecksum = ibv_send_flags::IBV_SEND_IP_CSUM.0,
}

#[allow(private_bounds)]
pub trait QueuePair {
    /// # Safety
    ///
    /// return the basic handle of QP;
    /// we mark this method unsafe because the lifetime of ibv_qp is not
    /// associated with the return value.
    ///
    /// # Examples
    ///
    /// ```compile_fail
    /// unsafe {
    ///     let qp_ptr = generic_queue_pair.qp();
    ///     // Use qp_ptr carefully...
    /// }
    unsafe fn qp(&self) -> NonNull<ibv_qp>;

    /// Modifies the queue pair attributes.
    ///
    /// # Arguments
    ///
    /// * `attr` - A reference to the QueuePairAttribute to be applied.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the modification was successful.
    /// * `Err(ModifyQueuePairError)` if the modification failed, containing an error message.
    ///
    /// # Examples
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
                #[cfg(feature = "debug")]
                libc::EINVAL => {
                    // User doesn't pass in a mask with IBV_QP_STATE, we just assume user doesn't
                    // want to change the state, pass self.state() as next_state
                    let err = if attr.attr_mask.contains(QueuePairAttributeMask::State) {
                        attr_mask_check(attr.attr_mask, self.state(), attr.attr.qp_state.into())
                    } else {
                        attr_mask_check(attr.attr_mask, self.state(), self.state())
                    };
                    match err {
                        Ok(()) => Err(ModifyQueuePairError::GenericError(io::Error::from_raw_os_error(
                            libc::EINVAL,
                        ))),
                        Err(err) => Err(err),
                    }
                },
                #[cfg(feature = "debug")]
                libc::ETIMEDOUT => Err(ModifyQueuePairError::ResolveRouteTimedout {
                    sgid_index: attr.attr.ah_attr.grh.sgid_index,
                    gid: attr.attr.ah_attr.grh.dgid.into(),
                    source: io::Error::from_raw_os_error(libc::ETIMEDOUT),
                }),
                #[cfg(feature = "debug")]
                libc::ENETUNREACH => Err(ModifyQueuePairError::NetworkUnreachable {
                    sgid_index: attr.attr.ah_attr.grh.sgid_index,
                    gid: attr.attr.ah_attr.grh.dgid.into(),
                    source: io::Error::from_raw_os_error(libc::ENETUNREACH),
                }),
                err => Err(ModifyQueuePairError::GenericError(io::Error::from_raw_os_error(err))),
            }
        }
    }

    /// Get the queue pair state.
    fn state(&self) -> QueuePairState {
        unsafe { self.qp().as_ref().state.into() }
    }

    /// Get the queue pair number.
    fn qp_number(&self) -> u32 {
        unsafe { self.qp().as_ref().qp_num }
    }

    /// Could be [`ExtendedPostSendGuard`], [`BasicPostSendGuard`] or [`GenericPostSendGuard`]
    type Guard<'g>: PostSendGuard
    where
        Self: 'g;

    /// Starts a post send operation, every qp should hold only one PostSendGuard at the same time.
    ///
    /// # Returns
    ///
    /// A `PostSendGuard` that can be used to construct and post send work requests.
    ///
    /// # Examples
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

    /// Starts a post receive operation.
    ///
    /// # Returns
    ///
    /// A `PostRecvGuard` that can be used to construct and post receive work requests.
    ///
    /// # Examples
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

    use rdma_mummy_sys::ibv_sge;
    // This is the private part of PostSendGuard, which is a workaround for pub trait
    // not being able to have private functions.
    //
    // Ref: https://stackoverflow.com/questions/53204327/how-to-have-a-private-part-of-a-trait
    //
    pub trait PostSendGuard {
        fn setup_send(&mut self);

        fn setup_write(&mut self, rkey: u32, remote_addr: u64);

        fn setup_inline_data(&mut self, buf: &[u8]);

        fn setup_inline_data_list(&mut self, bufs: &[IoSlice<'_>]);

        unsafe fn setup_sge(&mut self, lkey: u32, addr: u64, length: u32);

        unsafe fn setup_sge_list(&mut self, sg_list: &[ibv_sge]);
    }
}

pub trait PostSendGuard: private_traits::PostSendGuard {
    // every qp should hold only one WorkRequestHandle at the same time
    fn construct_wr(&mut self, wr_id: u64, wr_flags: WorkRequestFlags) -> WorkRequestHandle<'_, Self>;

    fn post(self) -> Result<(), PostSendError>;
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
#[cfg(feature = "debug")]
#[derive(Debug, Copy, Clone)]
struct QueuePairStateTableEntry {
    // whether this state transition is valid.
    valid: bool,
    required_mask: QueuePairAttributeMask,
    optional_mask: QueuePairAttributeMask,
}

#[cfg(feature = "debug")]
use lazy_static::lazy_static;

#[cfg(feature = "debug")]
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

unsafe impl Send for BasicQueuePair<'_> {}
unsafe impl Sync for BasicQueuePair<'_> {}

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

#[derive(Debug)]
pub struct ExtendedQueuePair<'res> {
    pub(crate) qp_ex: NonNull<ibv_qp_ex>,
    // phantom data for protection domain & completion queues
    _phantom: PhantomData<&'res ()>,
}

unsafe impl Send for ExtendedQueuePair<'_> {}
unsafe impl Sync for ExtendedQueuePair<'_> {}

impl Drop for ExtendedQueuePair<'_> {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_qp(self.qp().as_ptr()) };
        assert_eq!(ret, 0)
    }
}

impl QueuePair for ExtendedQueuePair<'_> {
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

    pub fn setup_send_ops_flags(&mut self, send_ops_flags: SendOperationFlags) -> &mut Self {
        self.init_attr.send_ops_flags = send_ops_flags.bits;
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
    pub fn build_ex(&self) -> Result<ExtendedQueuePair<'res>, String> {
        let mut attr = self.init_attr;

        let qp = unsafe { ibv_create_qp_ex((*(attr.pd)).context, &mut attr) };

        Ok(ExtendedQueuePair {
            qp_ex: NonNull::new(unsafe { ibv_qp_to_qp_ex(qp) })
                .ok_or(format!("ibv_create_qp_ex failed, {}", io::Error::last_os_error()))?,
            _phantom: PhantomData,
        })
    }
}

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
        self.attr.ah_attr = ah_attr.attr;
        self.attr_mask |= QueuePairAttributeMask::AddressVector;
        self
    }
}

// TODO(zhp): trait for QueuePair

#[cfg(feature = "debug")]
#[inline]
fn get_needed_mask(cur_mask: QueuePairAttributeMask, required_mask: QueuePairAttributeMask) -> QueuePairAttributeMask {
    required_mask.and(required_mask.xor(cur_mask))
}

#[cfg(feature = "debug")]
#[inline]
fn get_invalid_mask(
    cur_mask: QueuePairAttributeMask, required_mask: QueuePairAttributeMask, optional_mask: QueuePairAttributeMask,
) -> QueuePairAttributeMask {
    cur_mask.and(required_mask.or(optional_mask).not())
}

#[cfg(feature = "debug")]
fn attr_mask_check(
    attr_mask: QueuePairAttributeMask, cur_state: QueuePairState, next_state: QueuePairState,
) -> Result<(), ModifyQueuePairError> {
    if !RC_QP_STATE_TABLE[cur_state as usize][next_state as usize].valid {
        return Err(ModifyQueuePairError::InvalidTransition {
            cur_state,
            next_state,
            source: io::Error::from_raw_os_error(libc::EINVAL),
        });
    }

    let required = RC_QP_STATE_TABLE[cur_state as usize][next_state as usize].required_mask;
    let optional = RC_QP_STATE_TABLE[cur_state as usize][next_state as usize].optional_mask;
    let invalid = get_invalid_mask(attr_mask, required, optional);
    let needed = get_needed_mask(attr_mask, required);
    if invalid.bits == 0 && needed.bits == 0 {
        Ok(())
    } else {
        Err(ModifyQueuePairError::InvalidAttributeMask {
            cur_state,
            next_state,
            invalid,
            needed,
            source: io::Error::from_raw_os_error(libc::EINVAL),
        })
    }
}

pub struct WorkRequestHandle<'g, G: PostSendGuard + ?Sized> {
    guard: &'g mut G,
}

pub trait SetScatterGatherEntry {
    /// # Safety
    ///
    /// set a local buffer to the request; note that the lifetime of the buffer
    /// associated with the sge is managed by the caller.
    unsafe fn setup_sge(self, lkey: u32, addr: u64, length: u32);
    /// # Safety
    ///
    /// set a list of local buffers to the request; note that the lifetime of
    /// the buffer associated with the sge is managed by the caller.
    unsafe fn setup_sge_list(self, sg_list: &[ibv_sge]);
}

pub trait SetInlineData {
    fn setup_inline_data(self, buf: &[u8]);

    fn setup_inline_data_list(self, bufs: &[IoSlice<'_>]);
}

// handle to set local buffer for SEND & WRITE request
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

    pub fn setup_write(self, rkey: u32, remote_addr: u64) -> LocalBufferHandle<'g, G> {
        self.guard.setup_write(rkey, remote_addr);
        LocalBufferHandle { guard: self.guard }
    }
}

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
            #[cfg(feature = "debug")]
            libc::EINVAL => Err(PostSendError::InvalidWorkRequest(io::Error::from_raw_os_error(
                libc::EINVAL,
            ))),
            #[cfg(feature = "debug")]
            libc::ENOMEM => Err(PostSendError::NotEnoughResources(io::Error::from_raw_os_error(
                libc::ENOMEM,
            ))),
            #[cfg(feature = "debug")]
            libc::EFAULT => Err(PostSendError::InvalidQueuePair(io::Error::from_raw_os_error(
                libc::EFAULT,
            ))),
            err => Err(PostSendError::GenericError(io::Error::from_raw_os_error(err))),
        }
    }
}

impl private_traits::PostSendGuard for BasicPostSendGuard<'_> {
    fn setup_send(&mut self) {
        self.wrs.last_mut().unwrap().opcode = WorkRequestOperationType::Send as _;
    }

    fn setup_write(&mut self, rkey: u32, remote_addr: u64) {
        self.wrs.last_mut().unwrap().opcode = WorkRequestOperationType::Write as _;
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

    fn post(self) -> Result<(), PostSendError> {
        let ret: i32 = unsafe { ibv_wr_complete(self.qp_ex.as_ptr()) };

        // do not run the dtor
        std::mem::forget(self);

        match ret {
            0 => Ok(()),
            #[cfg(feature = "debug")]
            libc::EINVAL => Err(PostSendError::InvalidWorkRequest(io::Error::from_raw_os_error(
                libc::EINVAL,
            ))),
            #[cfg(feature = "debug")]
            libc::ENOMEM => Err(PostSendError::NotEnoughResources(io::Error::from_raw_os_error(
                libc::ENOMEM,
            ))),
            #[cfg(feature = "debug")]
            libc::EFAULT => Err(PostSendError::InvalidQueuePair(io::Error::from_raw_os_error(
                libc::EFAULT,
            ))),
            err => Err(PostSendError::GenericError(io::Error::from_raw_os_error(err))),
        }
    }
}

impl private_traits::PostSendGuard for ExtendedPostSendGuard<'_> {
    fn setup_send(&mut self) {
        unsafe { ibv_wr_send(self.qp_ex.as_ptr()) };
    }

    fn setup_write(&mut self, rkey: u32, remote_addr: u64) {
        unsafe { ibv_wr_rdma_write(self.qp_ex.as_ptr(), rkey, remote_addr) };
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

pub struct PostRecvGuard<'qp> {
    qp: NonNull<ibv_qp>,
    wrs: Vec<ibv_recv_wr>,
    sges: Vec<ibv_sge>,
    _phantom: PhantomData<&'qp ()>,
}

impl<'qp> PostRecvGuard<'qp> {
    pub fn construct_wr<'g>(&'g mut self, wr_id: u64) -> RecvWorkRequestHandle<'g, 'qp> {
        self.wrs.push(ibv_recv_wr {
            wr_id,
            next: null_mut(),
            sg_list: null_mut(),
            num_sge: 0,
        });

        RecvWorkRequestHandle { guard: self }
    }

    pub fn post(mut self) -> Result<(), String> {
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
            err => Err(format!("ibv_post_recv failed, ret={err}")),
        }
    }
}

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

#[derive(Debug)]
pub enum GenericQueuePair<'qp> {
    /// Variant for a Basic Queue Pair
    Basic(BasicQueuePair<'qp>),
    /// Variant for an Extended Queue Pair
    Extended(ExtendedQueuePair<'qp>),
}

impl QueuePair for GenericQueuePair<'_> {
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

    fn setup_write(&mut self, rkey: u32, remote_addr: u64) {
        match self {
            GenericPostSendGuard::Basic(guard) => guard.setup_write(rkey, remote_addr),
            GenericPostSendGuard::Extended(guard) => guard.setup_write(rkey, remote_addr),
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

impl<'qp> From<BasicQueuePair<'qp>> for GenericQueuePair<'qp> {
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
    fn from(qp: BasicQueuePair<'qp>) -> Self {
        GenericQueuePair::Basic(qp)
    }
}

impl<'qp> From<ExtendedQueuePair<'qp>> for GenericQueuePair<'qp> {
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
    fn from(qp: ExtendedQueuePair<'qp>) -> Self {
        GenericQueuePair::Extended(qp)
    }
}
