use std::alloc::{alloc_zeroed, dealloc, Layout};

use super::protection_domain::ProtectionDomain;
use rdma_mummy_sys::{ibv_cq, ibv_cq_ex, ibv_cq_init_attr_ex, ibv_destroy_cq};

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
