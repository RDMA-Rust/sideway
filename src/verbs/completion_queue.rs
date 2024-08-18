use std::os::raw::c_void;
use std::ptr;
use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    marker::PhantomData,
};

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
pub struct CompletionQueue<'ctx> {
    pub(crate) cq: ptr::NonNull<ibv_cq>,
    // phantom data for device context
    _dev_ctx: PhantomData<&'ctx ()>,
}

impl<'ctx> Drop for CompletionQueue<'ctx> {
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
pub struct CompletionQueueExtended<'ctx> {
    pub(crate) cq_ex: ptr::NonNull<ibv_cq_ex>,
    // phantom data for device context
    _dev_ctx: PhantomData<&'ctx ()>,
    // TODO(zhp): comp_channel, lifetime
}

impl<'ctx> Drop for CompletionQueueExtended<'ctx> {
    fn drop(&mut self) {
        // TODO convert cq_ex to cq (port ibv_cq_ex_to_cq in rdma-mummy-sys)
        let ret = unsafe { ibv_destroy_cq(self.cq_ex.as_ptr().cast()) };
        assert_eq!(ret, 0);
    }
}

// generic builder for both cq and cq_ex
pub struct CompletionQueueBuilder<'ctx> {
    dev_ctx: &'ctx RdmaContext,
    init_attr: ibv_cq_init_attr_ex,
}

impl<'ctx> CompletionQueueBuilder<'ctx> {
    pub fn new<'a>(dev_ctx: &'a RdmaContext) -> CompletionQueueBuilder<'a> {
        // set default params for init_attr
        CompletionQueueBuilder {
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

    // TODO(zhp): new, set various attributes
    pub fn setup_cqe(&mut self, cqe: u32) -> &mut Self {
        self.init_attr.cqe = cqe;
        self
    }

    pub fn setup_cq_context(&mut self, cq_context: *mut c_void) -> &mut Self {
        self.init_attr.cq_context = cq_context;
        self
    }

    // TODO(zhp): setup_comp_channel (comp_channel, comp_vector)

    // build cq_ex
    pub fn build_ex(&self) -> Result<CompletionQueueExtended<'ctx>, String> {
        // create a copy of init_attr since ibv_create_cq_ex requires a mutable pointer to it
        let mut init_attr = self.init_attr.clone();
        match unsafe { ibv_create_cq_ex(self.dev_ctx.context, &mut init_attr as *mut _) } {
            Some(cq_ex) => Ok(CompletionQueueExtended {
                cq_ex: ptr::NonNull::new(cq_ex).ok_or(String::from("ibv_create_cq_ex failed"))?,
                // TODO should associate the lifetime of dev_ctx with CQ
                _dev_ctx: PhantomData,
            }),
            None => Err(String::from("ibv_create_cq_ex failed")),
        }
    }

    // build legacy cq
    pub fn build(&self) -> Result<CompletionQueue<'ctx>, String> {
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
            // TODO should associate the lifetime of dev_ctx with CQ
            _dev_ctx: PhantomData,
        })
    }
}

// TODO trait for both cq and cq_ex?
