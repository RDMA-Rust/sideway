use std::os::raw::c_void;
use std::ptr;
use std::ptr::NonNull;
use std::{marker::PhantomData, mem::MaybeUninit};

use super::device_context::DeviceContext;
use rdma_mummy_sys::{
    ibv_comp_channel, ibv_cq, ibv_cq_ex, ibv_cq_init_attr_ex, ibv_create_comp_channel, ibv_create_cq, ibv_create_cq_ex,
    ibv_destroy_comp_channel, ibv_destroy_cq, ibv_end_poll, ibv_next_poll, ibv_pd, ibv_poll_cq_attr, ibv_start_poll,
    ibv_wc_read_byte_len, ibv_wc_read_completion_ts, ibv_wc_read_opcode, ibv_wc_read_vendor_err,
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
    //! return the basic handle of CQ;
    //! we mark this method unsafe because the lifetime of ibv_cq is not
    //! associated with the return value.
    unsafe fn cq(&self) -> NonNull<ibv_cq>;
}

#[derive(Debug)]
pub struct BasicCompletionQueue<'res> {
    pub(crate) cq: NonNull<ibv_cq>,
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
    pub fn start_poll<'cq>(&'cq self) -> Result<ExtendedPoller<'cq>, String> {
        let ret = unsafe {
            ibv_start_poll(
                self.cq_ex.as_ptr(),
                MaybeUninit::<ibv_poll_cq_attr>::zeroed().as_mut_ptr(),
            )
        };

        match ret {
            0 => Ok(ExtendedPoller {
                cq: self.cq_ex,
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
        let mut init_attr = self.init_attr.clone();
        match unsafe { ibv_create_cq_ex(self.dev_ctx.context, &mut init_attr as *mut _) } {
            Some(cq_ex) => Ok(ExtendedCompletionQueue {
                cq_ex: NonNull::new(cq_ex).ok_or(String::from("ibv_create_cq_ex failed"))?,
                // associate the lifetime of dev_ctx & comp_channel with CQ
                _phantom: PhantomData,
            }),
            None => Err(String::from("ibv_create_cq_ex failed")),
        }
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
            // associate the lifetime of dev_ctx & comp_channel with CQ
            _phantom: PhantomData,
        })
    }
}

// TODO trait for both cq and cq_ex?

pub struct ExtendedWorkCompletion<'cq> {
    cq: NonNull<ibv_cq_ex>,
    _phantom: PhantomData<&'cq ()>,
}

impl<'cq> ExtendedWorkCompletion<'cq> {
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

pub struct ExtendedPoller<'cq> {
    cq: NonNull<ibv_cq_ex>,
    _phantom: PhantomData<&'cq ()>,
}

impl ExtendedPoller<'_> {
    pub fn iter_mut(&mut self) -> ExtendedWorkCompletion {
        ExtendedWorkCompletion {
            cq: self.cq,
            _phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for ExtendedWorkCompletion<'a> {
    type Item = ExtendedWorkCompletion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
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

impl Drop for ExtendedPoller<'_> {
    fn drop(&mut self) {
        unsafe { ibv_end_poll(self.cq.as_ptr()) }
    }
}
