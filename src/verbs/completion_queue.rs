use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::marker::PhantomData;
use std::ptr::NonNull;

use super::device_context::DeviceContext;
use super::protection_domain::ProtectionDomain;
use rdma_mummy_sys::{ibv_cq, ibv_cq_ex, ibv_cq_init_attr_ex, ibv_destroy_cq};

#[derive(Debug)]
pub struct CompletionQueue<'ctx> {
    pub(crate) cq: NonNull<ibv_cq>,
    _dev_ctx: PhantomData<&'ctx ()>,
}

impl Drop for CompletionQueue<'_> {
    fn drop(&mut self) {
        unsafe {
            ibv_destroy_cq(self.cq.as_mut());
        }
    }
}

impl CompletionQueue<'_> {
    pub(crate) fn new<'ctx>(_ctx: &'ctx DeviceContext, cq: NonNull<ibv_cq>) -> Self {
        CompletionQueue {
            // This should not fail as the caller ensures cq is not NULL
            cq,
            _dev_ctx: PhantomData,
        }
    }
}
