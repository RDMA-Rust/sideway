use std::num::NonZeroU32;
use std::os::raw::c_void;
use std::ptr::NonNull;
use std::{io, ptr};
use std::{marker::PhantomData, mem::MaybeUninit};

use bitmask_enum::bitmask;

use super::device_context::DeviceContext;
use rdma_mummy_sys::{
    ibv_comp_channel, ibv_cq, ibv_cq_ex, ibv_cq_init_attr_ex, ibv_create_comp_channel, ibv_create_cq, ibv_create_cq_ex,
    ibv_create_cq_wc_flags, ibv_destroy_comp_channel, ibv_destroy_cq, ibv_end_poll, ibv_next_poll, ibv_pd, ibv_poll_cq,
    ibv_poll_cq_attr, ibv_start_poll, ibv_wc, ibv_wc_opcode, ibv_wc_read_byte_len, ibv_wc_read_completion_ts,
    ibv_wc_read_opcode, ibv_wc_read_vendor_err, ibv_wc_status,
};

#[derive(Debug, thiserror::Error)]
#[error("failed to create completion channel")]
#[non_exhaustive]
pub struct CreateCompletionChannelError(#[from] pub CreateCompletionChannelErrorKind);

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum CreateCompletionChannelErrorKind {
    Ibverbs(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("failed to create completion queue")]
#[non_exhaustive]
pub struct CreateCompletionQueueError(#[from] pub CreateCompletionQueueErrorKind);

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum CreateCompletionQueueErrorKind {
    Ibverbs(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PollCompletionQueueError {
    #[error("poll completion queue failed")]
    Ibverbs(#[from] io::Error),
    #[error("completion queue is empty")]
    CompletionQueueEmpty,
}

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

#[derive(Debug)]
pub struct CompletionChannel<'res> {
    pub(crate) channel: NonNull<ibv_comp_channel>,
    // phantom data for device context
    _phantom: PhantomData<&'res ()>,
}

impl Drop for CompletionChannel<'_> {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_comp_channel(self.channel.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

impl<'res> CompletionChannel<'res> {
    pub fn new<'ctx>(dev_ctx: &'ctx DeviceContext) -> Result<CompletionChannel<'res>, CreateCompletionChannelError>
    where
        'ctx: 'res,
    {
        let comp_channel = unsafe { ibv_create_comp_channel(dev_ctx.context) };
        if comp_channel.is_null() {
            Err(CreateCompletionChannelErrorKind::Ibverbs(io::Error::last_os_error()).into())
        } else {
            Ok(CompletionChannel {
                channel: unsafe { NonNull::new_unchecked(comp_channel) },
                _phantom: PhantomData,
            })
        }
    }
}

pub trait CompletionQueue {
    /// # Safety
    ///
    /// return the basic handle of CQ;
    /// we mark this method unsafe because the lifetime of ibv_cq is not
    /// associated with the return value.
    unsafe fn cq(&self) -> NonNull<ibv_cq>;
}

#[derive(Debug)]
pub struct BasicCompletionQueue<'res> {
    pub(crate) cq: NonNull<ibv_cq>,
    poll_batch: NonZeroU32,
    // phantom data for dev_ctx & comp_channel
    _phantom: PhantomData<&'res ()>,
}

unsafe impl Send for BasicCompletionQueue<'_> {}
unsafe impl Sync for BasicCompletionQueue<'_> {}

impl Drop for BasicCompletionQueue<'_> {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_cq(self.cq.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

impl CompletionQueue for BasicCompletionQueue<'_> {
    unsafe fn cq(&self) -> NonNull<ibv_cq> {
        self.cq
    }
}

impl BasicCompletionQueue<'_> {
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

    pub fn setup_poll_batch(&mut self, size: NonZeroU32) {
        self.poll_batch = size;
    }
}

#[derive(Debug)]
pub struct ExtendedCompletionQueue<'res> {
    pub(crate) cq_ex: NonNull<ibv_cq_ex>,
    // phantom data for dev_ctx & comp_channel
    _phantom: PhantomData<&'res ()>,
}

unsafe impl Send for ExtendedCompletionQueue<'_> {}
unsafe impl Sync for ExtendedCompletionQueue<'_> {}

impl Drop for ExtendedCompletionQueue<'_> {
    fn drop(&mut self) {
        // TODO convert cq_ex to cq (port ibv_cq_ex_to_cq in rdma-mummy-sys)
        let ret = unsafe { ibv_destroy_cq(self.cq_ex.as_ptr().cast()) };
        assert_eq!(ret, 0);
    }
}

impl CompletionQueue for ExtendedCompletionQueue<'_> {
    unsafe fn cq(&self) -> NonNull<ibv_cq> {
        // TODO convert cq_ex to cq (port ibv_cq_ex_to_cq in rdma-mummy-sys)
        self.cq_ex.cast()
    }
}

impl ExtendedCompletionQueue<'_> {
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

// generic builder for both cq and cq_ex
pub struct CompletionQueueBuilder<'res> {
    dev_ctx: &'res DeviceContext,
    init_attr: ibv_cq_init_attr_ex,
}

impl<'res> CompletionQueueBuilder<'res> {
    pub fn new<'ctx>(dev_ctx: &'ctx DeviceContext) -> Self
    where
        'ctx: 'res,
    {
        // set default params for init_attr
        CompletionQueueBuilder {
            dev_ctx,
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
        }
    }

    pub fn setup_cqe(&mut self, cqe: u32) -> &mut Self {
        self.init_attr.cqe = cqe;
        self
    }

    pub fn setup_cq_context(&mut self, cq_context: *mut c_void) -> &mut Self {
        self.init_attr.cq_context = cq_context;
        self
    }

    pub fn setup_comp_channel<'channel>(&mut self, channel: &'channel CompletionChannel, comp_vector: u32) -> &mut Self
    where
        'channel: 'res,
    {
        self.init_attr.channel = channel.channel.as_ptr();
        self.init_attr.comp_vector = comp_vector;
        self
    }

    pub fn setup_wc_flags(&mut self, wc_flags: CreateCompletionQueueWorkCompletionFlags) -> &mut Self {
        self.init_attr.wc_flags = wc_flags.bits();
        self
    }

    // TODO(fuji): set various attributes

    // build extended cq
    pub fn build_ex(&self) -> Result<ExtendedCompletionQueue<'res>, CreateCompletionQueueError> {
        // create a copy of init_attr since ibv_create_cq_ex requires a mutable pointer to it
        let mut init_attr = self.init_attr;

        let cq_ex = unsafe { ibv_create_cq_ex(self.dev_ctx.context, &mut init_attr as *mut _) };
        if cq_ex.is_null() {
            Err(CreateCompletionQueueErrorKind::Ibverbs(io::Error::last_os_error()).into())
        } else {
            Ok(ExtendedCompletionQueue {
                cq_ex: unsafe { NonNull::new_unchecked(cq_ex) },
                // associate the lifetime of dev_ctx & comp_channel with CQ
                _phantom: PhantomData,
            })
        }
    }

    // build basic cq
    pub fn build(&self) -> Result<BasicCompletionQueue<'res>, CreateCompletionQueueError> {
        let cq = unsafe {
            ibv_create_cq(
                self.dev_ctx.context,
                self.init_attr.cqe as _,
                self.init_attr.cq_context,
                self.init_attr.channel,
                self.init_attr.comp_vector as _,
            )
        };

        if cq.is_null() {
            Err(CreateCompletionQueueErrorKind::Ibverbs(io::Error::last_os_error()).into())
        } else {
            Ok(BasicCompletionQueue {
                cq: unsafe { NonNull::new_unchecked(cq) },
                poll_batch: unsafe { NonZeroU32::new(32).unwrap_unchecked() },
                // associate the lifetime of dev_ctx & comp_channel with CQ
                _phantom: PhantomData,
            })
        }
    }
}

// TODO trait for both cq and cq_ex?

pub struct BasicWorkCompletion<'iter> {
    wc: ibv_wc,
    _phantom: PhantomData<&'iter ()>,
}

impl BasicWorkCompletion<'_> {
    pub fn wr_id(&self) -> u64 {
        self.wc.wr_id
    }

    pub fn status(&self) -> u32 {
        self.wc.status
    }

    pub fn opcode(&self) -> u32 {
        self.wc.opcode
    }

    pub fn vendor_err(&self) -> u32 {
        self.wc.vendor_err
    }

    pub fn byte_len(&self) -> u32 {
        self.wc.byte_len
    }
}

pub struct ExtendedWorkCompletion<'iter> {
    cq: NonNull<ibv_cq_ex>,
    _phantom: PhantomData<&'iter ()>,
}

impl ExtendedWorkCompletion<'_> {
    pub fn wr_id(&self) -> u64 {
        unsafe { self.cq.as_ref().wr_id }
    }

    pub fn status(&self) -> u32 {
        unsafe { self.cq.as_ref().status }
    }

    pub fn opcode(&self) -> u32 {
        unsafe { ibv_wc_read_opcode(self.cq.as_ptr()) }
    }

    pub fn vendor_err(&self) -> u32 {
        unsafe { ibv_wc_read_vendor_err(self.cq.as_ptr()) }
    }

    pub fn byte_len(&self) -> u32 {
        unsafe { ibv_wc_read_byte_len(self.cq.as_ptr()) }
    }

    pub fn completion_timestamp(&self) -> u64 {
        unsafe { ibv_wc_read_completion_ts(self.cq.as_ptr()) }
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

pub struct BasicPoller<'cq> {
    cq: NonNull<ibv_cq>,
    wcs: Vec<ibv_wc>,
    status: BasicCompletionQueueState,
    current: usize,
    _phantom: PhantomData<&'cq ()>,
}

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

#[derive(Debug)]
pub enum GenericCompletionQueue<'cq> {
    /// Variant for a Basic CQ
    Basic(BasicCompletionQueue<'cq>),
    /// Variant for an Extended CQ
    Extended(ExtendedCompletionQueue<'cq>),
}

impl CompletionQueue for GenericCompletionQueue<'_> {
    unsafe fn cq(&self) -> NonNull<ibv_cq> {
        match self {
            GenericCompletionQueue::Basic(cq) => cq.cq(),
            GenericCompletionQueue::Extended(cq) => cq.cq(),
        }
    }
}

pub enum GenericPoller<'cq> {
    Basic(BasicPoller<'cq>),
    Extended(ExtendedPoller<'cq>),
}

impl GenericCompletionQueue<'_> {
    pub fn start_poll(&self) -> Result<GenericPoller<'_>, PollCompletionQueueError> {
        match self {
            GenericCompletionQueue::Basic(cq) => cq.start_poll().map(GenericPoller::Basic),
            GenericCompletionQueue::Extended(cq) => cq.start_poll().map(GenericPoller::Extended),
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

pub enum GenericWorkCompletion<'iter> {
    Basic(BasicWorkCompletion<'iter>),
    Extended(ExtendedWorkCompletion<'iter>),
}

impl GenericWorkCompletion<'_> {
    pub fn wr_id(&self) -> u64 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.wr_id(),
            GenericWorkCompletion::Extended(wc) => wc.wr_id(),
        }
    }

    pub fn status(&self) -> u32 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.status(),
            GenericWorkCompletion::Extended(wc) => wc.status(),
        }
    }

    pub fn opcode(&self) -> u32 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.opcode(),
            GenericWorkCompletion::Extended(wc) => wc.opcode(),
        }
    }

    pub fn vendor_err(&self) -> u32 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.vendor_err(),
            GenericWorkCompletion::Extended(wc) => wc.vendor_err(),
        }
    }

    pub fn byte_len(&self) -> u32 {
        match self {
            GenericWorkCompletion::Basic(wc) => wc.byte_len(),
            GenericWorkCompletion::Extended(wc) => wc.byte_len(),
        }
    }
}

impl<'cq> From<BasicCompletionQueue<'cq>> for GenericCompletionQueue<'cq> {
    fn from(cq: BasicCompletionQueue<'cq>) -> Self {
        GenericCompletionQueue::Basic(cq)
    }
}

impl<'cq> From<ExtendedCompletionQueue<'cq>> for GenericCompletionQueue<'cq> {
    fn from(cq: ExtendedCompletionQueue<'cq>) -> Self {
        GenericCompletionQueue::Extended(cq)
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
