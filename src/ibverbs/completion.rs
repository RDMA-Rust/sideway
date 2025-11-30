//! Contains all you need for handling Work Completions.
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, RawFd};
use std::os::raw::c_void;
use std::ptr::NonNull;
use std::sync::{Arc, Weak};
use std::{io, ptr};
use std::{marker::PhantomData, mem::MaybeUninit};

use bitmask_enum::bitmask;

use super::device_context::DeviceContext;
use rdma_mummy_sys::{
    ibv_ack_cq_events, ibv_comp_channel, ibv_cq, ibv_cq_ex, ibv_cq_init_attr_ex, ibv_create_comp_channel,
    ibv_create_cq, ibv_create_cq_ex, ibv_create_cq_wc_flags, ibv_destroy_comp_channel, ibv_destroy_cq, ibv_end_poll,
    ibv_get_cq_event, ibv_next_poll, ibv_pd, ibv_poll_cq, ibv_poll_cq_attr, ibv_req_notify_cq, ibv_start_poll, ibv_wc,
    ibv_wc_opcode, ibv_wc_read_byte_len, ibv_wc_read_completion_ts, ibv_wc_read_imm_data, ibv_wc_read_opcode,
    ibv_wc_read_vendor_err, ibv_wc_status,
};

/// Error returned by [`DeviceContext::create_comp_channel`] for creating a new completion channel.
#[derive(Debug, thiserror::Error)]
#[error("failed to create completion channel")]
#[non_exhaustive]
pub struct CreateCompletionChannelError(#[from] pub CreateCompletionChannelErrorKind);

/// The enum type for [`CreateCompletionChannelError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum CreateCompletionChannelErrorKind {
    Ibverbs(#[from] io::Error),
}

/// Error returned by [`CompletionQueueBuilder::build`] and [`CompletionQueueBuilder::build_ex`] for
/// creating a new RDMA CQ.
#[derive(Debug, thiserror::Error)]
#[error("failed to create completion queue")]
#[non_exhaustive]
pub struct CreateCompletionQueueError(#[from] pub CreateCompletionQueueErrorKind);

/// The enum type for [`CreateCompletionQueueError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum CreateCompletionQueueErrorKind {
    Ibverbs(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("failed to get completion event")]
#[non_exhaustive]
pub struct GetCompletionEventError(#[from] pub GetCompletionEventErrorKind);

/// The enum type for [`GetCompletionEventError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum GetCompletionEventErrorKind {
    Ibverbs(#[from] io::Error),
}

/// Error returned by [`CompletionChannel::req_notify_cq`] for requesting notification of completion queue.
#[derive(Debug, thiserror::Error)]
#[error("failed to request notification of completion queue")]
#[non_exhaustive]
pub struct RequestNotifyCompletionQueueError(#[from] pub RequestNotifyCompletionQueueErrorKind);

/// The enum type for [`RequestNotifyCompletionQueueError`].

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum RequestNotifyCompletionQueueErrorKind {
    Ibverbs(#[from] io::Error),
}

/// Error returned by [`BasicCompletionQueue::start_poll`] and
/// [`ExtendedCompletionQueue::start_poll`] for polling Work Completions from RDMA CQ.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PollCompletionQueueError {
    #[error("poll completion queue failed")]
    Ibverbs(#[from] io::Error),
    #[error("completion queue is empty")]
    CompletionQueueEmpty,
}

/// Possible statuses of a Work Completion's corresponding operation.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkCompletionStatus {
    Success = ibv_wc_status::IBV_WC_SUCCESS,
    LocalLengthError = ibv_wc_status::IBV_WC_LOC_LEN_ERR,
    LocalQueuePairOperationError = ibv_wc_status::IBV_WC_LOC_QP_OP_ERR,
    LocalEndToEndContextOperationError = ibv_wc_status::IBV_WC_LOC_EEC_OP_ERR,
    LocalProtectionError = ibv_wc_status::IBV_WC_LOC_PROT_ERR,
    WorkRequestFlushedError = ibv_wc_status::IBV_WC_WR_FLUSH_ERR,
    MemoryWindowBindError = ibv_wc_status::IBV_WC_MW_BIND_ERR,
    BadResponseError = ibv_wc_status::IBV_WC_BAD_RESP_ERR,
    LocalAccessError = ibv_wc_status::IBV_WC_LOC_ACCESS_ERR,
    RemoteInvalidRequestError = ibv_wc_status::IBV_WC_REM_INV_REQ_ERR,
    RemoteAccessError = ibv_wc_status::IBV_WC_REM_ACCESS_ERR,
    RemoteOperationError = ibv_wc_status::IBV_WC_REM_OP_ERR,
    RetryCounterExceededError = ibv_wc_status::IBV_WC_RETRY_EXC_ERR,
    ResponderNotReadyRetryCounterExceededError = ibv_wc_status::IBV_WC_RNR_RETRY_EXC_ERR,
    LocalReliableDatagramDomainViolationError = ibv_wc_status::IBV_WC_LOC_RDD_VIOL_ERR,
    RemoteInvalidReliableDatagramRequest = ibv_wc_status::IBV_WC_REM_INV_RD_REQ_ERR,
    RemoteAbortedError = ibv_wc_status::IBV_WC_REM_ABORT_ERR,
    InvalidEndToEndContextNumberError = ibv_wc_status::IBV_WC_INV_EECN_ERR,
    InvalidEndToEndContextStateError = ibv_wc_status::IBV_WC_INV_EEC_STATE_ERR,
    FatalError = ibv_wc_status::IBV_WC_FATAL_ERR,
    ResponseTimeoutError = ibv_wc_status::IBV_WC_RESP_TIMEOUT_ERR,
    GeneralError = ibv_wc_status::IBV_WC_GENERAL_ERR,
    TagMatchingError = ibv_wc_status::IBV_WC_TM_ERR,
    TagMatchingRendezvousIncomplete = ibv_wc_status::IBV_WC_TM_RNDV_INCOMPLETE,
}

impl From<u32> for WorkCompletionStatus {
    fn from(status: u32) -> Self {
        match status {
            ibv_wc_status::IBV_WC_SUCCESS => WorkCompletionStatus::Success,
            ibv_wc_status::IBV_WC_LOC_LEN_ERR => WorkCompletionStatus::LocalLengthError,
            ibv_wc_status::IBV_WC_LOC_QP_OP_ERR => WorkCompletionStatus::LocalQueuePairOperationError,
            ibv_wc_status::IBV_WC_LOC_EEC_OP_ERR => WorkCompletionStatus::LocalEndToEndContextOperationError,
            ibv_wc_status::IBV_WC_LOC_PROT_ERR => WorkCompletionStatus::LocalProtectionError,
            ibv_wc_status::IBV_WC_WR_FLUSH_ERR => WorkCompletionStatus::WorkRequestFlushedError,
            ibv_wc_status::IBV_WC_MW_BIND_ERR => WorkCompletionStatus::MemoryWindowBindError,
            ibv_wc_status::IBV_WC_BAD_RESP_ERR => WorkCompletionStatus::BadResponseError,
            ibv_wc_status::IBV_WC_LOC_ACCESS_ERR => WorkCompletionStatus::LocalAccessError,
            ibv_wc_status::IBV_WC_REM_INV_REQ_ERR => WorkCompletionStatus::RemoteInvalidRequestError,
            ibv_wc_status::IBV_WC_REM_ACCESS_ERR => WorkCompletionStatus::RemoteAccessError,
            ibv_wc_status::IBV_WC_REM_OP_ERR => WorkCompletionStatus::RemoteOperationError,
            ibv_wc_status::IBV_WC_RETRY_EXC_ERR => WorkCompletionStatus::RetryCounterExceededError,
            ibv_wc_status::IBV_WC_RNR_RETRY_EXC_ERR => WorkCompletionStatus::ResponderNotReadyRetryCounterExceededError,
            ibv_wc_status::IBV_WC_LOC_RDD_VIOL_ERR => WorkCompletionStatus::LocalReliableDatagramDomainViolationError,
            ibv_wc_status::IBV_WC_REM_INV_RD_REQ_ERR => WorkCompletionStatus::RemoteInvalidReliableDatagramRequest,
            ibv_wc_status::IBV_WC_REM_ABORT_ERR => WorkCompletionStatus::RemoteAbortedError,
            ibv_wc_status::IBV_WC_INV_EECN_ERR => WorkCompletionStatus::InvalidEndToEndContextNumberError,
            ibv_wc_status::IBV_WC_INV_EEC_STATE_ERR => WorkCompletionStatus::InvalidEndToEndContextStateError,
            ibv_wc_status::IBV_WC_FATAL_ERR => WorkCompletionStatus::FatalError,
            ibv_wc_status::IBV_WC_RESP_TIMEOUT_ERR => WorkCompletionStatus::ResponseTimeoutError,
            ibv_wc_status::IBV_WC_GENERAL_ERR => WorkCompletionStatus::GeneralError,
            ibv_wc_status::IBV_WC_TM_ERR => WorkCompletionStatus::TagMatchingError,
            ibv_wc_status::IBV_WC_TM_RNDV_INCOMPLETE => WorkCompletionStatus::TagMatchingRendezvousIncomplete,
            _ => panic!("Unknown work completion status: {status}"),
        }
    }
}

/// Operation that a Work Completion's corresponding Work Request performed.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkCompletionOperationType {
    Send = ibv_wc_opcode::IBV_WC_SEND,
    Write = ibv_wc_opcode::IBV_WC_RDMA_WRITE,
    Read = ibv_wc_opcode::IBV_WC_RDMA_READ,
    CompareAndSwap = ibv_wc_opcode::IBV_WC_COMP_SWAP,
    FetchAndAdd = ibv_wc_opcode::IBV_WC_FETCH_ADD,
    BindMemoryWindow = ibv_wc_opcode::IBV_WC_BIND_MW,
    LocalInvalidate = ibv_wc_opcode::IBV_WC_LOCAL_INV,
    TcpSegmentationOffload = ibv_wc_opcode::IBV_WC_TSO,
    Flush = ibv_wc_opcode::IBV_WC_FLUSH,
    AtomicWrite = ibv_wc_opcode::IBV_WC_ATOMIC_WRITE,
    Receive = ibv_wc_opcode::IBV_WC_RECV,
    ReceiveWithImmediate = ibv_wc_opcode::IBV_WC_RECV_RDMA_WITH_IMM,
    TagMatchingAdd = ibv_wc_opcode::IBV_WC_TM_ADD,
    TagMatchingDelete = ibv_wc_opcode::IBV_WC_TM_DEL,
    TagMatchingSync = ibv_wc_opcode::IBV_WC_TM_SYNC,
    TagMatchingReceive = ibv_wc_opcode::IBV_WC_TM_RECV,
    TagMatchingNoTag = ibv_wc_opcode::IBV_WC_TM_NO_TAG,
    Driver1 = ibv_wc_opcode::IBV_WC_DRIVER1,
    Driver2 = ibv_wc_opcode::IBV_WC_DRIVER2,
    Driver3 = ibv_wc_opcode::IBV_WC_DRIVER3,
}

impl From<u32> for WorkCompletionOperationType {
    fn from(opcode: u32) -> Self {
        match opcode {
            ibv_wc_opcode::IBV_WC_SEND => WorkCompletionOperationType::Send,
            ibv_wc_opcode::IBV_WC_RDMA_WRITE => WorkCompletionOperationType::Write,
            ibv_wc_opcode::IBV_WC_RDMA_READ => WorkCompletionOperationType::Read,
            ibv_wc_opcode::IBV_WC_COMP_SWAP => WorkCompletionOperationType::CompareAndSwap,
            ibv_wc_opcode::IBV_WC_FETCH_ADD => WorkCompletionOperationType::FetchAndAdd,
            ibv_wc_opcode::IBV_WC_BIND_MW => WorkCompletionOperationType::BindMemoryWindow,
            ibv_wc_opcode::IBV_WC_LOCAL_INV => WorkCompletionOperationType::LocalInvalidate,
            ibv_wc_opcode::IBV_WC_TSO => WorkCompletionOperationType::TcpSegmentationOffload,
            ibv_wc_opcode::IBV_WC_FLUSH => WorkCompletionOperationType::Flush,
            ibv_wc_opcode::IBV_WC_ATOMIC_WRITE => WorkCompletionOperationType::AtomicWrite,
            ibv_wc_opcode::IBV_WC_RECV => WorkCompletionOperationType::Receive,
            ibv_wc_opcode::IBV_WC_RECV_RDMA_WITH_IMM => WorkCompletionOperationType::ReceiveWithImmediate,
            ibv_wc_opcode::IBV_WC_TM_ADD => WorkCompletionOperationType::TagMatchingAdd,
            ibv_wc_opcode::IBV_WC_TM_DEL => WorkCompletionOperationType::TagMatchingDelete,
            ibv_wc_opcode::IBV_WC_TM_SYNC => WorkCompletionOperationType::TagMatchingSync,
            ibv_wc_opcode::IBV_WC_TM_RECV => WorkCompletionOperationType::TagMatchingReceive,
            ibv_wc_opcode::IBV_WC_TM_NO_TAG => WorkCompletionOperationType::TagMatchingNoTag,
            ibv_wc_opcode::IBV_WC_DRIVER1 => WorkCompletionOperationType::Driver1,
            ibv_wc_opcode::IBV_WC_DRIVER2 => WorkCompletionOperationType::Driver2,
            ibv_wc_opcode::IBV_WC_DRIVER3 => WorkCompletionOperationType::Driver3,
            _ => panic!("Unknown work completion opcode: {opcode}"),
        }
    }
}

/// Controls fields to be filled for Work Completions of a [`ExtendedCompletionQueue`]. It's either
/// 0 or the bitwise `OR` of one or more of the following flags. Used in
/// [`CompletionQueueBuilder::setup_wc_flags`].
#[bitmask(u64)]
#[bitmask_config(vec_debug)]
pub enum CreateCompletionQueueWorkCompletionFlags {
    ByteLength = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_BYTE_LEN.0 as _,
    ImmediateData = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_IMM.0 as _,
    QueuePairNumber = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_QP_NUM.0 as _,
    SourceQueuePair = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_SRC_QP.0 as _,
    SourceLocalIdentifier = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_SLID.0 as _,
    ServiceLevel = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_SL.0 as _,
    DestinationLocalIdentifierPathBits = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_DLID_PATH_BITS.0 as _,
    CompletionTimestamp = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_COMPLETION_TIMESTAMP.0 as _,
    CustomerVlan = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_CVLAN.0 as _,
    FlowTag = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_FLOW_TAG.0 as _,
    TagMatchingInformation = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_TM_INFO.0 as _,
    CompletionTimestampWallclock = ibv_create_cq_wc_flags::IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK.0 as _,

    StandardFlags = CreateCompletionQueueWorkCompletionFlags::ByteLength.bits
        | CreateCompletionQueueWorkCompletionFlags::ImmediateData.bits
        | CreateCompletionQueueWorkCompletionFlags::QueuePairNumber.bits
        | CreateCompletionQueueWorkCompletionFlags::SourceQueuePair.bits
        | CreateCompletionQueueWorkCompletionFlags::SourceLocalIdentifier.bits
        | CreateCompletionQueueWorkCompletionFlags::ServiceLevel.bits
        | CreateCompletionQueueWorkCompletionFlags::DestinationLocalIdentifierPathBits.bits,
}

/// A completion channel is a file descriptor that is used to deliver Work Completion notifications
/// to userspace process. When a Work Completion event is generated for a [`CompletionQueue`], the
/// event is delivered via the completion channel attached to that CQ. This could be used for event
/// notification based poll instead of busy polling (of course, the latency would be higher).
#[derive(Debug, Clone)]
pub struct CompletionChannel {
    pub(crate) channel: NonNull<ibv_comp_channel>,
    _dev_ctx: Arc<DeviceContext>,
}

impl Drop for CompletionChannel {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_comp_channel(self.channel.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

impl CompletionChannel {
    pub fn new(dev_ctx: &Arc<DeviceContext>) -> Result<Arc<CompletionChannel>, CreateCompletionChannelError> {
        let comp_channel = unsafe { ibv_create_comp_channel(dev_ctx.context.as_ptr()) };
        if comp_channel.is_null() {
            Err(CreateCompletionChannelErrorKind::Ibverbs(io::Error::last_os_error()).into())
        } else {
            Ok(Arc::new(CompletionChannel {
                channel: unsafe { NonNull::new_unchecked(comp_channel) },
                _dev_ctx: Arc::clone(dev_ctx),
            }))
        }
    }

    /// Set the nonblocking mode of completion channel's underlying file descriptor to on (true) or
    /// off (false).
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        // from libstd/sys/unix/fd.rs
        let fd = self.as_raw_fd();

        unsafe {
            let previous = libc::fcntl(fd, libc::F_GETFL);
            if previous < 0 {
                return Err(io::Error::last_os_error());
            }
            let new = if nonblocking {
                previous | libc::O_NONBLOCK
            } else {
                previous & !libc::O_NONBLOCK
            };
            if libc::fcntl(fd, libc::F_SETFL, new) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    pub fn get_cq_event(&self) -> Result<GenericCompletionQueue, GetCompletionEventError> {
        let mut cq_ptr = MaybeUninit::<*mut ibv_cq>::uninit();
        let mut cq_wrapper = MaybeUninit::<*mut WeakGenericCompletionQueue>::uninit();

        let ret = unsafe { ibv_get_cq_event(self.channel.as_ptr(), cq_ptr.as_mut_ptr(), cq_wrapper.as_mut_ptr() as _) };
        if ret < 0 {
            return Err(GetCompletionEventErrorKind::Ibverbs(io::Error::last_os_error()).into());
        }
        let _cq = unsafe { NonNull::new(cq_ptr.assume_init()).unwrap() };
        let cq_wrapper = unsafe { NonNull::new(cq_wrapper.assume_init()).unwrap() };

        let weak_cq = unsafe { (*cq_wrapper.as_ptr()).upgrade() };

        Ok(weak_cq.unwrap())
    }

    /// # Safety
    ///
    /// Return the handle of completion channel.
    /// We mark this method unsafe because the lifetime of `ibv_comp_channel` is not associated
    /// with the return value.
    pub unsafe fn comp_channel(&self) -> NonNull<ibv_comp_channel> {
        self.channel
    }
}

impl AsRawFd for CompletionChannel {
    fn as_raw_fd(&self) -> RawFd {
        unsafe { self.channel.as_ref().fd }
    }
}

unsafe impl Send for CompletionChannel {}
unsafe impl Sync for CompletionChannel {}

/// Unified interface for operations over RDMA CQs.
pub trait CompletionQueue {
    /// # Safety
    ///
    /// Return the basic handle of CQ.
    /// We mark this method unsafe because the lifetime of `ibv_cq` is not
    /// associated with the return value.
    unsafe fn cq(&self) -> NonNull<ibv_cq>;

    fn ack_events(&self, num_events: u32) {
        unsafe { ibv_ack_cq_events(self.cq().as_ptr(), num_events) };
    }

    fn req_notify_cq(&self, solicited_only: bool) -> Result<(), RequestNotifyCompletionQueueError> {
        let ret = unsafe { ibv_req_notify_cq(self.cq().as_ptr(), if solicited_only { 1 } else { 0 }) };

        if ret != 0 {
            return Err(RequestNotifyCompletionQueueErrorKind::Ibverbs(io::Error::from_raw_os_error(ret)).into());
        }

        Ok(())
    }
}

/// The legacy [`CompletionQueue`] created with [`CompletionQueueBuilder::build`]
/// ([`ibv_create_cq`]), which doesn't support some advanced features (including
/// [`ibv_start_poll`] APIs and hardware timestamp).
///
/// [`ibv_create_cq`]: https://man7.org/linux/man-pages/man3/ibv_create_cq.3.html
/// [`ibv_start_poll`]: https://man7.org/linux/man-pages/man3/ibv_create_cq_ex.3.html
///
#[derive(Debug)]
pub struct BasicCompletionQueue {
    pub(crate) cq: NonNull<ibv_cq>,
    poll_batch: NonZeroU32,
    _dev_ctx: Arc<DeviceContext>,
    _comp_channel: Option<Arc<CompletionChannel>>,
}

unsafe impl Send for BasicCompletionQueue {}
unsafe impl Sync for BasicCompletionQueue {}

impl Drop for BasicCompletionQueue {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_cq(self.cq.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

impl CompletionQueue for BasicCompletionQueue {
    unsafe fn cq(&self) -> NonNull<ibv_cq> {
        self.cq
    }
}

impl BasicCompletionQueue {
    /// Starts to poll Work Completions over this CQ, every [`BasicCompletionQueue`] should hold only
    /// one [`BasicPoller`] at the same time.
    ///
    /// Note that this would call [`ibv_poll_cq`] for underlying polling, which requires users pass
    /// in a Work Completion array for filling informations. In C, users would create the array
    /// themselves, but for here, we would create it for you. To specify the array size
    /// (how many Work Completions you want to poll at a time), you should call
    /// [`BasicCompletionQueue::setup_poll_batch`].
    ///
    /// [`ibv_poll_cq`]: https://www.rdmamojo.com/2013/02/15/ibv_poll_cq/
    ///
    pub fn start_poll(&self) -> Result<BasicPoller<'_>, PollCompletionQueueError> {
        let mut cqes = Vec::<ibv_wc>::with_capacity(self.poll_batch.get() as _);

        let ret = unsafe {
            ibv_poll_cq(
                self.cq.as_ptr(),
                self.poll_batch.get().try_into().unwrap(),
                cqes.as_mut_ptr(),
            )
        };

        unsafe {
            match ret {
                0 => Err(PollCompletionQueueError::CompletionQueueEmpty),
                err if err < 0 => Err(PollCompletionQueueError::Ibverbs(io::Error::from_raw_os_error(-err))),
                res => Ok(BasicPoller {
                    cq: self.cq(),
                    wcs: {
                        cqes.set_len(res as _);
                        cqes
                    },
                    status: if res < self.poll_batch.get().try_into().unwrap_unchecked() {
                        BasicCompletionQueueState::Drained
                    } else {
                        BasicCompletionQueueState::Ready
                    },
                    current: 0,
                    _phantom: PhantomData,
                }),
            }
        }
    }

    /// Change the polling batch size, note that this won't take effect until your next call to
    /// [`BasicCompletionQueue::start_poll`].
    pub fn setup_poll_batch(&mut self, size: NonZeroU32) {
        self.poll_batch = size;
    }
}

/// The extended [`CompletionQueue`] created with [`CompletionQueueBuilder::build_ex`]
/// ([`ibv_create_cq_ex`]), which support some advanced features (including [`ibv_start_poll`] APIs
/// and hardware timestamp), should provide better performance compared to [`BasicCompletionQueue`].
///
/// [`ibv_create_cq_ex`]: https://man7.org/linux/man-pages/man3/ibv_create_cq_ex.3.html
/// [`ibv_start_poll`]: https://man7.org/linux/man-pages/man3/ibv_create_cq_ex.3.html
///
#[derive(Debug)]
pub struct ExtendedCompletionQueue {
    pub(crate) cq_ex: NonNull<ibv_cq_ex>,
    _dev_ctx: Arc<DeviceContext>,
    _comp_channel: Option<Arc<CompletionChannel>>,
}

unsafe impl Send for ExtendedCompletionQueue {}
unsafe impl Sync for ExtendedCompletionQueue {}

impl Drop for ExtendedCompletionQueue {
    fn drop(&mut self) {
        // TODO convert cq_ex to cq (port ibv_cq_ex_to_cq in rdma-mummy-sys)
        let ret = unsafe { ibv_destroy_cq(self.cq_ex.as_ptr().cast()) };
        assert_eq!(ret, 0);
    }
}

impl CompletionQueue for ExtendedCompletionQueue {
    unsafe fn cq(&self) -> NonNull<ibv_cq> {
        // TODO convert cq_ex to cq (port ibv_cq_ex_to_cq in rdma-mummy-sys)
        self.cq_ex.cast()
    }
}

impl ExtendedCompletionQueue {
    /// Starts to poll Work Completions over this CQ, every [`ExtendedCompletionQueue`] should hold
    /// only one [`ExtendedPoller`] at the same time.
    pub fn start_poll(&self) -> Result<ExtendedPoller<'_>, PollCompletionQueueError> {
        let ret = unsafe {
            ibv_start_poll(
                self.cq_ex.as_ptr(),
                MaybeUninit::<ibv_poll_cq_attr>::zeroed().as_mut_ptr(),
            )
        };

        match ret {
            0 => Ok(ExtendedPoller {
                cq: self.cq_ex,
                is_first: true,
                _phantom: PhantomData,
            }),
            libc::ENOENT => Err(PollCompletionQueueError::CompletionQueueEmpty),
            err => Err(PollCompletionQueueError::Ibverbs(io::Error::from_raw_os_error(err))),
        }
    }
}

/// A factory for creating [`BasicCompletionQueue`] and [`ExtendedCompletionQueue`] with specified
/// parameters.
pub struct CompletionQueueBuilder {
    dev_ctx: Arc<DeviceContext>,
    init_attr: ibv_cq_init_attr_ex,
    comp_channel: Option<Arc<CompletionChannel>>,
}

impl CompletionQueueBuilder {
    pub fn new(dev_ctx: &Arc<DeviceContext>) -> Self {
        // set default params for init_attr
        CompletionQueueBuilder {
            dev_ctx: Arc::clone(dev_ctx),
            init_attr: ibv_cq_init_attr_ex {
                cqe: 1024,
                cq_context: ptr::null_mut::<c_void>(),
                channel: ptr::null_mut::<ibv_comp_channel>(),
                comp_vector: 0,
                wc_flags: CreateCompletionQueueWorkCompletionFlags::StandardFlags.bits,
                comp_mask: 0,
                flags: 0,
                parent_domain: ptr::null_mut::<ibv_pd>(),
            },
            comp_channel: None,
        }
    }

    /// Setup the [`CompletionQueue`] depth, which controls how many Work Completions could be
    /// stored in this RDMA CQ. If it's too small, CQ may overrun.
    pub fn setup_cqe(&mut self, cqe: u32) -> &mut Self {
        self.init_attr.cqe = cqe;
        self
    }

    /// Setup a opaque context for the CQ, so user could use it later.
    pub fn setup_cq_context(&mut self, cq_context: *mut c_void) -> &mut Self {
        self.init_attr.cq_context = cq_context;
        self
    }

    /// Setup the completion channel to be associated with the CQ, such that when there is new
    /// Work Completions come in, the completion channel would notify user.
    pub fn setup_comp_channel(&mut self, channel: &Arc<CompletionChannel>, comp_vector: u32) -> &mut Self {
        self.init_attr.channel = channel.channel.as_ptr();
        self.init_attr.comp_vector = comp_vector;
        self.comp_channel = Some(Arc::clone(channel));
        self
    }

    /// Setup what fields should be filled in for Work Completions in this CQ. Only valid for
    /// [`CompletionQueueBuilder::build_ex`].
    pub fn setup_wc_flags(&mut self, wc_flags: CreateCompletionQueueWorkCompletionFlags) -> &mut Self {
        self.init_attr.wc_flags = wc_flags.bits();
        self
    }

    // TODO(fuji): set various attributes
    /// Create a [`ExtendedCompletionQueue`] with [`ibv_create_cq_ex`].
    ///
    /// [`ibv_create_cq_ex`]: https://man7.org/linux/man-pages/man3/ibv_create_cq_ex.3.html
    ///
    pub fn build_ex(&self) -> Result<Arc<ExtendedCompletionQueue>, CreateCompletionQueueError> {
        // create a copy of init_attr since ibv_create_cq_ex requires a mutable pointer to it
        let mut init_attr = self.init_attr;

        let cq_ex = unsafe { ibv_create_cq_ex(self.dev_ctx.context.as_ptr(), &mut init_attr as *mut _) };
        if cq_ex.is_null() {
            Err(CreateCompletionQueueErrorKind::Ibverbs(io::Error::last_os_error()).into())
        } else {
            let cq_wrapper = Arc::new(ExtendedCompletionQueue {
                cq_ex: unsafe { NonNull::new_unchecked(cq_ex) },
                _dev_ctx: Arc::clone(&self.dev_ctx),
                _comp_channel: self.comp_channel.clone(),
            });

            let weak_cq = Arc::downgrade(&cq_wrapper.clone());
            let boxed = Box::new(WeakGenericCompletionQueue::Extended(weak_cq));
            let raw_box = Box::into_raw(boxed);

            unsafe {
                (*cq_ex).cq_context = raw_box as *mut std::ffi::c_void;
            }

            Ok(cq_wrapper)
        }
    }

    /// Create a [`BasicCompletionQueue`] with [`ibv_create_cq`].
    ///
    /// [`ibv_create_cq`]: https://man7.org/linux/man-pages/man3/ibv_create_cq.3.html
    ///
    pub fn build(&self) -> Result<Arc<BasicCompletionQueue>, CreateCompletionQueueError> {
        let cq = unsafe {
            ibv_create_cq(
                self.dev_ctx.context.as_ptr(),
                self.init_attr.cqe as _,
                self.init_attr.cq_context,
                self.init_attr.channel,
                self.init_attr.comp_vector as _,
            )
        };

        if cq.is_null() {
            Err(CreateCompletionQueueErrorKind::Ibverbs(io::Error::last_os_error()).into())
        } else {
            let cq_wrapper = Arc::new(BasicCompletionQueue {
                cq: unsafe { NonNull::new_unchecked(cq) },
                poll_batch: unsafe { NonZeroU32::new(32).unwrap_unchecked() },
                _dev_ctx: Arc::clone(&self.dev_ctx),
                _comp_channel: self.comp_channel.clone(),
            });

            let weak_cq = Arc::downgrade(&cq_wrapper.clone());
            let boxed = Box::new(WeakGenericCompletionQueue::Basic(weak_cq));
            let raw_box = Box::into_raw(boxed);

            unsafe {
                (*cq).cq_context = raw_box as *mut std::ffi::c_void;
            }

            Ok(cq_wrapper)
        }
    }
}

// TODO trait for both cq and cq_ex?
/// The basic Work Completion indicates some Work Requests have completed.
pub struct BasicWorkCompletion<'iter> {
    wc: ibv_wc,
    _phantom: PhantomData<&'iter ()>,
}

impl BasicWorkCompletion<'_> {
    /// Get the 64 bits value that was associated with the corresponding Work Request.
    pub fn wr_id(&self) -> u64 {
        self.wc.wr_id
    }

    /// Get the status of the operation, could be cast into [`WorkCompletionStatus`].
    pub fn status(&self) -> u32 {
        self.wc.status
    }

    /// Get the operation that the corresponding Work Request performed, could be cast into
    /// [`WorkCompletionOperationType`].
    pub fn opcode(&self) -> u32 {
        self.wc.opcode
    }

    /// Get the vendor specific error which provides more information if the completion ended with
    /// error.
    pub fn vendor_err(&self) -> u32 {
        self.wc.vendor_err
    }

    /// Get the number of bytes transferred, relevant if the receive queue for incoming Send or RDMA
    /// Write with immediate operations. This value doesn't include the length of the immediate
    /// data.
    pub fn byte_len(&self) -> u32 {
        self.wc.byte_len
    }

    /// Get the immediate data associated with the corresponding Work Request.
    pub fn imm_data(&self) -> u32 {
        unsafe { self.wc.imm_data_invalidated_rkey_union.imm_data }
    }
}

/// The extended Work Completion indicates some Work Requests have completed, with support for more
/// fields filled in, including hardware timestamp.
pub struct ExtendedWorkCompletion<'iter> {
    cq: NonNull<ibv_cq_ex>,
    _phantom: PhantomData<&'iter ()>,
}

impl ExtendedWorkCompletion<'_> {
    /// Get the 64 bits value that was associated with the corresponding Work Request.
    pub fn wr_id(&self) -> u64 {
        unsafe { self.cq.as_ref().wr_id }
    }

    /// Get the status of the operation, could be cast into [`WorkCompletionStatus`].
    pub fn status(&self) -> u32 {
        unsafe { self.cq.as_ref().status }
    }

    /// Get the operation that the corresponding Work Request performed, could be cast into
    /// [`WorkCompletionOperationType`].
    pub fn opcode(&self) -> u32 {
        unsafe { ibv_wc_read_opcode(self.cq.as_ptr()) }
    }

    /// Get the vendor specific error which provides more information if the completion ended with
    /// error.
    pub fn vendor_err(&self) -> u32 {
        unsafe { ibv_wc_read_vendor_err(self.cq.as_ptr()) }
    }

    /// Get the number of bytes transferred, relevant if the receive queue for incoming Send or RDMA
    /// Write with immediate operations. This value doesn't include the length of the immediate
    /// data.
    pub fn byte_len(&self) -> u32 {
        unsafe { ibv_wc_read_byte_len(self.cq.as_ptr()) }
    }

    /// Get the completion timestamp in HCA clock units.
    pub fn completion_timestamp(&self) -> u64 {
        unsafe { ibv_wc_read_completion_ts(self.cq.as_ptr()) }
    }

    /// Get the immediate data associated with the corresponding Work Request.
    pub fn imm_data(&self) -> u32 {
        unsafe { ibv_wc_read_imm_data(self.cq.as_ptr()) }
    }
}

#[derive(PartialEq, Eq)]
enum BasicCompletionQueueState {
    // Ready means Completion Queue still has elements waiting to be polled.
    // For Basic CQ, it means we are ready to return a work completion, if no more
    // completions are there, we would call `ibv_poll_cq` immediately to get more.
    Ready,
    // Drained means the CQ is drained in this round of polling, we would return
    // None after user consuming the last work completion, if user want to use
    // `next()` to get more work completions, it would trigger `ibv_poll_cq` calls.
    Drained,
    // Empty means CQ is *likely* to be empty, if user want to get next work
    // completion, we would call `ibv_poll_cq` to check if there is a new one.
    Empty,
}

// TODO: provide a trait for poller?
/// The basic `Poller` that works for [`BasicCompletionQueue`] for getting Work Completions in an
/// iterator style.
pub struct BasicPoller<'cq> {
    cq: NonNull<ibv_cq>,
    wcs: Vec<ibv_wc>,
    status: BasicCompletionQueueState,
    current: usize,
    _phantom: PhantomData<&'cq ()>,
}

// TODO: implement BasicPoller with lending iterator for better performance.
impl<'cq> Iterator for BasicPoller<'cq> {
    type Item = BasicWorkCompletion<'cq>;

    fn next(&mut self) -> Option<Self::Item> {
        use BasicCompletionQueueState::*;

        let current = self.current;
        let len = self.wcs.len();

        if (self.status == Ready || self.status == Drained) && current < len {
            let wc = unsafe {
                BasicWorkCompletion {
                    wc: *self.wcs.get_unchecked(current),
                    _phantom: PhantomData,
                }
            };
            self.current += 1;
            return Some(wc);
        }

        if self.status == Drained && current >= len {
            // Completion Queue has been drained once, return None to let user
            // get sense of it.
            self.status = Empty;
            return None;
        }

        // Status is Ready, but all work completions have been consumed, poll
        // one more time to get more work completions.
        // Or status is Empty, try if we could get new work completions.
        let ret = unsafe {
            ibv_poll_cq(
                self.cq.as_ptr(),
                self.wcs.capacity().try_into().unwrap_unchecked(),
                self.wcs.as_mut_ptr(),
            )
        };

        if ret > 0 {
            unsafe {
                if ret < self.wcs.capacity().try_into().unwrap_unchecked() {
                    self.status = Drained;
                } else {
                    self.status = Ready;
                }

                self.wcs.set_len(ret as usize);
            }
            let wc = unsafe {
                BasicWorkCompletion {
                    wc: *self.wcs.get_unchecked(0),
                    _phantom: PhantomData,
                }
            };
            self.current = 1;
            Some(wc)
        } else {
            self.status = Empty;
            None
        }
    }
}

/// The extended `Poller` that works for [`ExtendedCompletionQueue`] for getting Work Completions in
/// an iterator style.
pub struct ExtendedPoller<'cq> {
    cq: NonNull<ibv_cq_ex>,
    is_first: bool,
    _phantom: PhantomData<&'cq ()>,
}

impl Drop for ExtendedPoller<'_> {
    fn drop(&mut self) {
        unsafe { ibv_end_poll(self.cq.as_ptr()) }
    }
}

impl<'cq> Iterator for ExtendedPoller<'cq> {
    type Item = ExtendedWorkCompletion<'cq>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_first {
            self.is_first = false;
            Some(ExtendedWorkCompletion {
                cq: self.cq,
                _phantom: PhantomData,
            })
        } else {
            let ret = unsafe { ibv_next_poll(self.cq.as_ptr()) };

            if ret != 0 {
                None
            } else {
                Some(ExtendedWorkCompletion {
                    cq: self.cq,
                    _phantom: PhantomData,
                })
            }
        }
    }
}

enum WeakGenericCompletionQueue {
    Basic(Weak<BasicCompletionQueue>),
    Extended(Weak<ExtendedCompletionQueue>),
}

impl WeakGenericCompletionQueue {
    pub fn upgrade(&self) -> Option<GenericCompletionQueue> {
        match self {
            WeakGenericCompletionQueue::Basic(cq) => cq.upgrade().map(GenericCompletionQueue::Basic),
            WeakGenericCompletionQueue::Extended(cq) => cq.upgrade().map(GenericCompletionQueue::Extended),
        }
    }
}

/// A unified interface for [`BasicCompletionQueue`] and [`ExtendedCompletionQueue`], implemented
/// with enum dispatching.
#[derive(Debug)]
pub enum GenericCompletionQueue {
    /// Variant for a Basic CQ
    Basic(Arc<BasicCompletionQueue>),
    /// Variant for an Extended CQ
    Extended(Arc<ExtendedCompletionQueue>),
}

impl Clone for GenericCompletionQueue {
    fn clone(&self) -> Self {
        match self {
            GenericCompletionQueue::Basic(cq) => GenericCompletionQueue::Basic(Arc::clone(cq)),
            GenericCompletionQueue::Extended(cq) => GenericCompletionQueue::Extended(Arc::clone(cq)),
        }
    }
}

impl CompletionQueue for GenericCompletionQueue {
    unsafe fn cq(&self) -> NonNull<ibv_cq> {
        match self {
            GenericCompletionQueue::Basic(cq) => cq.cq(),
            GenericCompletionQueue::Extended(cq) => cq.cq(),
        }
    }
}

/// A unified interface for [`BasicPoller`] and [`ExtendedPoller`], implemented with enum
/// dispatching.
pub enum GenericPoller<'cq> {
    Basic(BasicPoller<'cq>),
    Extended(ExtendedPoller<'cq>),
}

impl GenericCompletionQueue {
    pub fn start_poll(&self) -> Result<GenericPoller<'_>, PollCompletionQueueError> {
        match self {
            GenericCompletionQueue::Basic(cq) => cq.start_poll().map(GenericPoller::Basic),
            GenericCompletionQueue::Extended(cq) => cq.start_poll().map(GenericPoller::Extended),
        }
    }

    pub fn ack_events(&self, num_events: u32) {
        match self {
            GenericCompletionQueue::Basic(cq) => cq.ack_events(num_events),
            GenericCompletionQueue::Extended(cq) => cq.ack_events(num_events),
        }
    }

    pub fn req_notify_cq(&self, solicited_only: bool) -> Result<(), RequestNotifyCompletionQueueError> {
        match self {
            GenericCompletionQueue::Basic(cq) => cq.req_notify_cq(solicited_only),
            GenericCompletionQueue::Extended(cq) => cq.req_notify_cq(solicited_only),
        }
    }
}

impl<'cq> Iterator for GenericPoller<'cq> {
    type Item = GenericWorkCompletion<'cq>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            GenericPoller::Basic(poller) => poller.next().map(GenericWorkCompletion::Basic),
            GenericPoller::Extended(poller) => poller.next().map(GenericWorkCompletion::Extended),
        }
    }
}

/// A unified interface for [`BasicWorkCompletion`] and [`ExtendedWorkCompletion`], implemented with
/// enum dispatching.
pub enum GenericWorkCompletion<'iter> {
    Basic(BasicWorkCompletion<'iter>),
    Extended(ExtendedWorkCompletion<'iter>),
}

impl GenericWorkCompletion<'_> {
    /// Get the 64 bits value that was associated with the corresponding Work Request.
    pub fn wr_id(&self) -> u64 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.wr_id(),
            GenericWorkCompletion::Extended(wc) => wc.wr_id(),
        }
    }

    /// Get the status of the operation, could be cast into [`WorkCompletionStatus`].
    pub fn status(&self) -> u32 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.status(),
            GenericWorkCompletion::Extended(wc) => wc.status(),
        }
    }

    /// Get the operation that the corresponding Work Request performed, could be cast into
    /// [`WorkCompletionOperationType`].
    pub fn opcode(&self) -> u32 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.opcode(),
            GenericWorkCompletion::Extended(wc) => wc.opcode(),
        }
    }

    /// Get the vendor specific error which provides more information if the completion ended with
    /// error.
    pub fn vendor_err(&self) -> u32 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.vendor_err(),
            GenericWorkCompletion::Extended(wc) => wc.vendor_err(),
        }
    }

    /// Get the number of bytes transferred, relevant if the receive queue for incoming Send or RDMA
    /// Write with immediate operations. This value doesn't include the length of the immediate
    /// data.
    pub fn byte_len(&self) -> u32 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.byte_len(),
            GenericWorkCompletion::Extended(wc) => wc.byte_len(),
        }
    }

    /// Get the immediate data associated with the corresponding Work Request.
    pub fn imm_data(&self) -> u32 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.imm_data(),
            GenericWorkCompletion::Extended(wc) => wc.imm_data(),
        }
    }
}

impl From<Arc<BasicCompletionQueue>> for GenericCompletionQueue {
    fn from(cq: Arc<BasicCompletionQueue>) -> Self {
        GenericCompletionQueue::Basic(cq)
    }
}

impl From<Arc<ExtendedCompletionQueue>> for GenericCompletionQueue {
    fn from(cq: Arc<ExtendedCompletionQueue>) -> Self {
        GenericCompletionQueue::Extended(cq)
    }
}

impl From<Arc<GenericCompletionQueue>> for GenericCompletionQueue {
    fn from(cq: Arc<GenericCompletionQueue>) -> Self {
        cq.as_ref().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_work_completion_operation_type_conversion(opcode in 0u32..=256u32) {
            if let Ok(wc_op_type) = std::panic::catch_unwind(|| WorkCompletionOperationType::from(opcode)) {
                prop_assert_eq!(opcode, wc_op_type as u32);
            } else {
                // If it panics, it should be for an unknown opcode
                prop_assert!((opcode < ibv_wc_opcode::IBV_WC_RECV && opcode > ibv_wc_opcode::IBV_WC_ATOMIC_WRITE) || (opcode > ibv_wc_opcode::IBV_WC_DRIVER3));
            }
        }

        #[test]
        fn test_work_completion_status_conversion(status in 0u32..=32u32) {
            if let Ok(wc_status) = std::panic::catch_unwind(|| WorkCompletionStatus::from(status)) {
                prop_assert_eq!(status, wc_status as u32);
            } else {
                // If it panics, it should be for an unknown status
                prop_assert!(status > ibv_wc_status::IBV_WC_TM_RNDV_INCOMPLETE);
            }
        }
    }

    #[test]
    fn test_all_enum_variants() {
        let completion_status_variants = [
            WorkCompletionStatus::Success,
            WorkCompletionStatus::LocalLengthError,
            WorkCompletionStatus::LocalQueuePairOperationError,
            WorkCompletionStatus::LocalEndToEndContextOperationError,
            WorkCompletionStatus::LocalProtectionError,
            WorkCompletionStatus::WorkRequestFlushedError,
            WorkCompletionStatus::MemoryWindowBindError,
            WorkCompletionStatus::BadResponseError,
            WorkCompletionStatus::LocalAccessError,
            WorkCompletionStatus::RemoteInvalidRequestError,
            WorkCompletionStatus::RemoteAccessError,
            WorkCompletionStatus::RemoteOperationError,
            WorkCompletionStatus::RetryCounterExceededError,
            WorkCompletionStatus::ResponderNotReadyRetryCounterExceededError,
            WorkCompletionStatus::LocalReliableDatagramDomainViolationError,
            WorkCompletionStatus::RemoteInvalidReliableDatagramRequest,
            WorkCompletionStatus::RemoteAbortedError,
            WorkCompletionStatus::InvalidEndToEndContextNumberError,
            WorkCompletionStatus::InvalidEndToEndContextStateError,
            WorkCompletionStatus::FatalError,
            WorkCompletionStatus::ResponseTimeoutError,
            WorkCompletionStatus::GeneralError,
            WorkCompletionStatus::TagMatchingError,
            WorkCompletionStatus::TagMatchingRendezvousIncomplete,
        ];

        for &variant in &completion_status_variants {
            let status = variant as u32;
            assert_eq!(WorkCompletionStatus::from(status), variant);
        }

        let operation_type_variants = [
            WorkCompletionOperationType::Send,
            WorkCompletionOperationType::Write,
            WorkCompletionOperationType::Read,
            WorkCompletionOperationType::CompareAndSwap,
            WorkCompletionOperationType::FetchAndAdd,
            WorkCompletionOperationType::BindMemoryWindow,
            WorkCompletionOperationType::LocalInvalidate,
            WorkCompletionOperationType::TcpSegmentationOffload,
            WorkCompletionOperationType::Flush,
            WorkCompletionOperationType::AtomicWrite,
            WorkCompletionOperationType::Receive,
            WorkCompletionOperationType::ReceiveWithImmediate,
            WorkCompletionOperationType::TagMatchingAdd,
            WorkCompletionOperationType::TagMatchingDelete,
            WorkCompletionOperationType::TagMatchingSync,
            WorkCompletionOperationType::TagMatchingReceive,
            WorkCompletionOperationType::TagMatchingNoTag,
            WorkCompletionOperationType::Driver1,
            WorkCompletionOperationType::Driver2,
            WorkCompletionOperationType::Driver3,
        ];

        for &variant in &operation_type_variants {
            let opcode = variant as u32;
            assert_eq!(WorkCompletionOperationType::from(opcode), variant);
        }
    }
}
