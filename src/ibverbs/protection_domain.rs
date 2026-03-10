//! A protection domain is used to associate [`QueuePair`]s with [`MemoryRegion`]s, as a means for
//! enabling and controlling network adapter access to Host System memory.
//!
//! [`QueuePair`]: crate::ibverbs::queue_pair::QueuePair
//!
use rdma_mummy_sys::{ibv_dealloc_pd, ibv_pd};
use std::ptr::NonNull;
use std::sync::Arc;

use super::{
    address::{AddressHandle, AddressHandleAttribute, CreateAddressHandleError},
    device_context::DeviceContext,
    memory_region::{MemoryRegion, RegisterMemoryRegionError},
    queue_pair::QueuePairBuilder,
    AccessFlags,
};

/// A protection domain that could be used to creating RDMA QP and RDMA MR on it to associate them
/// together.
#[derive(Debug)]
pub struct ProtectionDomain {
    pub(crate) pd: NonNull<ibv_pd>,
    pub(crate) _dev_ctx: Arc<DeviceContext>,
}

unsafe impl Send for ProtectionDomain {}
unsafe impl Sync for ProtectionDomain {}

impl Drop for ProtectionDomain {
    fn drop(&mut self) {
        unsafe {
            ibv_dealloc_pd(self.pd.as_mut());
        }
    }
}

impl ProtectionDomain {
    pub(crate) fn new(dev_ctx: Arc<DeviceContext>, pd: NonNull<ibv_pd>) -> Self {
        ProtectionDomain {
            // This should not fail as the caller ensures pd is not NULL
            pd,
            _dev_ctx: dev_ctx,
        }
    }

    /// Register a memory region that was allocated outside this module.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid for `len` bytes
    /// and that the memory remains accessible and unmodified as needed.
    pub unsafe fn reg_mr(
        self: &Arc<Self>, ptr: usize, len: usize, access: AccessFlags,
    ) -> Result<Arc<MemoryRegion>, RegisterMemoryRegionError> {
        Ok(Arc::new(MemoryRegion::reg_mr(Arc::clone(self), ptr, len, access)?))
    }

    /// Create a new address handle on this protection domain.
    pub fn create_ah(
        self: &Arc<Self>, attr: &mut AddressHandleAttribute,
    ) -> Result<AddressHandle, CreateAddressHandleError> {
        AddressHandle::new(Arc::clone(self), attr)
    }

    /// Create a [`QueuePairBuilder`] for building QPs on this protection domain
    /// later.
    pub fn create_qp_builder(self: &Arc<Self>) -> QueuePairBuilder {
        QueuePairBuilder::new(self)
    }

    /// # Safety
    ///
    /// Return the handle of protection domain.
    /// We mark this method unsafe because the lifetime of `ibv_pd` is not associated
    /// with the return value.
    pub unsafe fn pd(&self) -> NonNull<ibv_pd> {
        self.pd
    }
}
