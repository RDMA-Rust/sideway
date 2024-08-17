use std::os::raw::c_void;
use std::ptr;
use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    marker::PhantomData,
};

use super::{protection_domain::ProtectionDomain, rdma_context::RdmaContext};
use rdma_mummy_sys::{
    ibv_comp_channel, ibv_cq, ibv_cq_ex, ibv_cq_init_attr_ex, ibv_create_cq_ex, ibv_destroy_cq, ibv_pd,
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
pub struct CompletionQueue {
    pub(crate) cq_ptr: *mut ibv_cq,
}

impl Drop for CompletionQueue {
    fn drop(&mut self) {
        unsafe {
            ibv_destroy_cq(self.cq_ptr);
        }
    }
}

#[derive(Debug)]
pub struct CompletionQueueEx {
    pub(crate) cq_ptr: *mut ibv_cq_ex,
}

#[derive(Debug)]
pub struct ExtendedCompletionQueue<'ctx> {
    pub(crate) cq_ex: ptr::NonNull<ibv_cq_ex>,
    // phantom data for device context
    _dev_ctx: PhantomData<&'ctx ()>,
    // TODO(zhp): comp_channel, lifetime
}

impl<'ctx> Drop for ExtendedCompletionQueue<'ctx> {
    fn drop(&mut self) {
        // TODO convert cq_ex to cq (port ibv_cq_ex_to_cq in rdma-mummy-sys)
        let ret = unsafe { ibv_destroy_cq(self.cq_ex.as_ptr().cast()) };
        assert_eq!(ret, 0);
    }
}

pub struct ExtendedCompletionQueueBuilder<'ctx> {
    dev_ctx: &'ctx RdmaContext,
    init_attr: ibv_cq_init_attr_ex,
}

impl<'ctx> ExtendedCompletionQueueBuilder<'ctx> {
    pub fn new<'a>(dev_ctx: &'a RdmaContext) -> ExtendedCompletionQueueBuilder<'a> {
        // set default params for init_attr
        ExtendedCompletionQueueBuilder {
            dev_ctx,
            init_attr: ibv_cq_init_attr_ex {
                cqe: 1024,
                cq_context: ptr::null::<c_void>() as *mut _,
                channel: ptr::null::<ibv_comp_channel>() as *mut _,
                comp_vector: 0,
                // TODO(zhp): setup default flags for CQ
                wc_flags: 0,
                comp_mask: 0,
                flags: 0,
                parent_domain: ptr::null::<ibv_pd>() as *mut _,
            },
        }
    }
    // TODO(zhp): setup comp_channel?

    // TODO(zhp): new, set various attributes
    pub fn setup_cqe(&mut self, cqe: u32) -> &mut Self {
        self.init_attr.cqe = cqe;
        self
    }

    pub fn build(&self) -> Result<ExtendedCompletionQueue<'ctx>, String> {
        // create a copy of init_attr since ibv_create_cq_ex requires a mutable pointer to it
        let mut init_attr = self.init_attr.clone();
        match unsafe { ibv_create_cq_ex(self.dev_ctx.context, &mut init_attr as *mut _) } {
            Some(cq_ex) => Ok(ExtendedCompletionQueue {
                cq_ex: ptr::NonNull::new(cq_ex).ok_or(String::from("ibv_create_cq_ex failed"))?,
                // TODO should associate the lifetime of dev_ctx with CQ
                _dev_ctx: PhantomData,
            }),
            None => Err(String::from("ibv_create_cq_ex failed")),
        }
    }
}

// TODO trait for both cq and cq_ex?
