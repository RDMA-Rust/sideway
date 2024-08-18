use std::os::raw::c_void;
use std::ptr;
use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    marker::PhantomData,
};

use super::comp_channel::CompletionChannel;
use super::{protection_domain::ProtectionDomain, rdma_context::RdmaContext};
use rdma_mummy_sys::{
    ibv_comp_channel, ibv_cq, ibv_cq_ex, ibv_cq_init_attr_ex, ibv_create_cq, ibv_create_cq_ex, ibv_destroy_cq, ibv_pd,
};

#[derive(Debug)]
pub struct CqInitAttr {
    pub(crate) attr_ptr: *mut ibv_cq_init_attr_ex,
}

impl CqInitAttr {
    pub fn new() -> Self {
        let attr_ptr = unsafe { alloc_zeroed(Layout::new::<ibv_cq_init_attr_ex>()) as *mut ibv_cq_init_attr_ex };
        CqInitAttr { attr_ptr }
    }

    pub fn set_cqe(self, cqe: u32) -> Self {
        unsafe {
            (*self.attr_ptr).cqe = cqe;
        }
        self
    }

    pub fn set_pd(self, pd: &ProtectionDomain) -> Self {
        unsafe {
            (*self.attr_ptr).parent_domain = pd.pd_ptr;
        }
        self
    }
}

impl Drop for CqInitAttr {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.attr_ptr as _, Layout::new::<ibv_cq_init_attr_ex>());
        }
    }
}

#[derive(Debug)]
pub struct CompletionQueue<'ctx, 'channel> {
    pub(crate) cq: ptr::NonNull<ibv_cq>,
    // phantom data for dev_ctx & comp_channel
    _phantom: PhantomData<(&'ctx RdmaContext, &'channel CompletionChannel<'ctx>)>,
}

impl<'ctx, 'channel> Drop for CompletionQueue<'ctx, 'channel> {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_cq(self.cq.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

#[derive(Debug)]
pub struct CompletionQueueEx {
    pub(crate) cq_ptr: *mut ibv_cq_ex,
}

#[derive(Debug)]
pub struct CompletionQueueExtended<'ctx, 'channel> {
    pub(crate) cq_ex: ptr::NonNull<ibv_cq_ex>,
    // phantom data for dev_ctx & comp_channel
    _phantom: PhantomData<(&'ctx RdmaContext, &'channel CompletionChannel<'ctx>)>,
}

impl<'ctx, 'channel> Drop for CompletionQueueExtended<'ctx, 'channel> {
    fn drop(&mut self) {
        // TODO convert cq_ex to cq (port ibv_cq_ex_to_cq in rdma-mummy-sys)
        let ret = unsafe { ibv_destroy_cq(self.cq_ex.as_ptr().cast()) };
        assert_eq!(ret, 0);
    }
}

// generic builder for both cq and cq_ex
pub struct CompletionQueueBuilder<'ctx, 'channel> {
    dev_ctx: &'ctx RdmaContext,
    init_attr: ibv_cq_init_attr_ex,
    _phantom: PhantomData<&'channel CompletionChannel<'ctx>>,
}

impl<'ctx, 'channel> CompletionQueueBuilder<'ctx, 'channel> {
    pub fn new(dev_ctx: &'ctx RdmaContext) -> Self {
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
            _phantom: PhantomData,
        }
    }

    // TODO(zhp): new, set various attributes
    pub fn setup_cqe(&mut self, cqe: u32) -> &mut Self {
        self.init_attr.cqe = cqe;
        self
    }

    pub fn setup_cq_context(&mut self, cq_context: *mut c_void) -> &mut Self {
        self.init_attr.cq_context = cq_context;
        self
    }

    pub fn setup_comp_channel(&mut self, channel: &'channel CompletionChannel<'ctx>, comp_vector: u32) -> &mut Self {
        self.init_attr.channel = channel.channel.as_ptr();
        self.init_attr.comp_vector = comp_vector;
        self
    }

    // build cq_ex
    pub fn build_ex(&self) -> Result<CompletionQueueExtended<'ctx, 'channel>, String> {
        // create a copy of init_attr since ibv_create_cq_ex requires a mutable pointer to it
        let mut init_attr = self.init_attr.clone();
        match unsafe { ibv_create_cq_ex(self.dev_ctx.context, &mut init_attr as *mut _) } {
            Some(cq_ex) => Ok(CompletionQueueExtended {
                cq_ex: ptr::NonNull::new(cq_ex).ok_or(String::from("ibv_create_cq_ex failed"))?,
                // associate the lifetime of dev_ctx & comp_channel with CQ
                _phantom: PhantomData,
            }),
            None => Err(String::from("ibv_create_cq_ex failed")),
        }
    }

    // build legacy cq
    pub fn build(&self) -> Result<CompletionQueue<'ctx, 'channel>, String> {
        let cq = unsafe {
            ibv_create_cq(
                self.dev_ctx.context,
                self.init_attr.cqe as _,
                self.init_attr.cq_context,
                self.init_attr.channel,
                self.init_attr.comp_vector as _,
            )
        };
        Ok(CompletionQueue {
            cq: ptr::NonNull::new(cq).ok_or(String::from("ibv_create_cq failed"))?,
            // associate the lifetime of dev_ctx & comp_channel with CQ
            _phantom: PhantomData,
        })
    }
}

// TODO trait for both cq and cq_ex?
