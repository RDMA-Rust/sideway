use std::marker::PhantomData;
use std::os::raw::c_void;
use std::ptr;
use std::ptr::NonNull;

use super::device_context::DeviceContext;
use rdma_mummy_sys::{
    ibv_comp_channel, ibv_cq, ibv_cq_ex, ibv_cq_init_attr_ex, ibv_create_comp_channel, ibv_create_cq, ibv_create_cq_ex,
    ibv_destroy_comp_channel, ibv_destroy_cq, ibv_pd,
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
