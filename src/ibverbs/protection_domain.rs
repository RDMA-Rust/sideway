use rdma_mummy_sys::{ibv_dealloc_pd, ibv_pd};
use std::marker::PhantomData;
use std::ptr::NonNull;

use super::{
    device_context::DeviceContext,
    memory_region::{MemoryRegion, RegisterMemoryRegionError},
    queue_pair::QueuePairBuilder,
    AccessFlags,
};

#[derive(Debug)]
pub struct ProtectionDomain<'ctx> {
    pub(crate) pd: NonNull<ibv_pd>,
    _dev_ctx: PhantomData<&'ctx ()>,
}

unsafe impl Send for ProtectionDomain<'_> {}
unsafe impl Sync for ProtectionDomain<'_> {}

impl Drop for ProtectionDomain<'_> {
    fn drop(&mut self) {
        unsafe {
            ibv_dealloc_pd(self.pd.as_mut());
        }
    }
}

impl ProtectionDomain<'_> {
    pub(crate) fn new(_ctx: &DeviceContext, pd: NonNull<ibv_pd>) -> Self {
        ProtectionDomain {
            // This should not fail as the caller ensures pd is not NULL
            pd,
            _dev_ctx: PhantomData,
        }
    }

    /// Register a memory region that was allocated outside this module.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid for `len` bytes
    /// and that the memory remains accessible and unmodified as needed.
    pub unsafe fn reg_mr(
        &self, ptr: usize, len: usize, access: AccessFlags,
    ) -> Result<MemoryRegion, RegisterMemoryRegionError> {
        MemoryRegion::reg_mr(self, ptr, len, access)
    }

    pub fn create_qp_builder(&self) -> QueuePairBuilder {
        QueuePairBuilder::new(self)
    }
}
