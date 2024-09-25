use std::num::NonZeroU32;
use std::os::raw::c_void;
use std::ptr;
use std::ptr::NonNull;
use std::{marker::PhantomData, mem::MaybeUninit};

use super::device_context::DeviceContext;
use rdma_mummy_sys::{
    ibv_comp_channel, ibv_cq, ibv_cq_ex, ibv_cq_init_attr_ex, ibv_create_comp_channel, ibv_create_cq, ibv_create_cq_ex,
    ibv_destroy_comp_channel, ibv_destroy_cq, ibv_end_poll, ibv_next_poll, ibv_pd, ibv_poll_cq, ibv_poll_cq_attr,
    ibv_start_poll, ibv_wc, ibv_wc_read_byte_len, ibv_wc_read_completion_ts, ibv_wc_read_opcode,
    ibv_wc_read_vendor_err,
};

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
    pub fn new<'ctx>(dev_ctx: &'ctx DeviceContext) -> Result<CompletionChannel<'res>, String>
    where
        'ctx: 'res,
    {
        let comp_channel = unsafe { ibv_create_comp_channel(dev_ctx.context) };
        Ok(CompletionChannel {
            channel: NonNull::new(comp_channel).ok_or(String::from("ibv_create_comp_channel failed"))?,
            _phantom: PhantomData,
        })
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
    pub fn start_poll(&self) -> Result<BasicPoller<'_>, String> {
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
                0 => Err("no valid cqes".to_string()),
                err if err < 0 => Err(format!("ibv_poll_cq failed, ret={err}")),
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
    pub fn start_poll(&self) -> Result<ExtendedPoller<'_>, String> {
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
            err => Err(format!("ibv_start_poll failed, ret={err}")),
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
                // TODO(zhp): setup default flags for CQ
                wc_flags: 0,
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

    // TODO(fuji): set various attributes

    // build extended cq
    pub fn build_ex(&self) -> Result<ExtendedCompletionQueue<'res>, String> {
        // create a copy of init_attr since ibv_create_cq_ex requires a mutable pointer to it
        let mut init_attr = self.init_attr;

        let cq_ex = unsafe { ibv_create_cq_ex(self.dev_ctx.context, &mut init_attr as *mut _) };

        Ok(ExtendedCompletionQueue {
            cq_ex: NonNull::new(cq_ex).ok_or(String::from("ibv_create_cq_ex failed"))?,
            // associate the lifetime of dev_ctx & comp_channel with CQ
            _phantom: PhantomData,
        })
    }

    // build basic cq
    pub fn build(&self) -> Result<BasicCompletionQueue<'res>, String> {
        let cq = unsafe {
            ibv_create_cq(
                self.dev_ctx.context,
                self.init_attr.cqe as _,
                self.init_attr.cq_context,
                self.init_attr.channel,
                self.init_attr.comp_vector as _,
            )
        };
        Ok(BasicCompletionQueue {
            cq: NonNull::new(cq).ok_or(String::from("ibv_create_cq failed"))?,
            poll_batch: unsafe { NonZeroU32::new(32).unwrap_unchecked() },
            // associate the lifetime of dev_ctx & comp_channel with CQ
            _phantom: PhantomData,
        })
    }
}

// TODO trait for both cq and cq_ex?

pub struct BasicWorkCompletion<'iter> {
    wc: ibv_wc,
    _phantom: PhantomData<&'iter ()>,
}

impl<'iter> BasicWorkCompletion<'iter> {
    pub fn wr_id(&self) -> u64 {
        self.wc.wr_id
    }

    pub fn status(&self) -> u32 {
        self.wc.status
    }

    pub fn opcode(&self) -> u32 {
        self.wc.opcode
    }
}

pub struct ExtendedWorkCompletion<'iter> {
    cq: NonNull<ibv_cq_ex>,
    _phantom: PhantomData<&'iter ()>,
}

impl<'iter> ExtendedWorkCompletion<'iter> {
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
