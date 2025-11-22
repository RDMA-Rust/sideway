//! Users need to register memory they allocated as memory region for accessing it later.
use rdma_mummy_sys::{ibv_dereg_mr, ibv_mr, ibv_reg_mr};
use std::{io, ptr::NonNull, sync::Arc};

use super::protection_domain::ProtectionDomain;
use super::AccessFlags;

/// Error returned by [`ProtectionDomain::reg_mr`] for registering a new RDMA MR.
#[derive(Debug, thiserror::Error)]
#[error("failed to register memory region")]
#[non_exhaustive]
pub struct RegisterMemoryRegionError(#[from] pub RegisterMemoryRegionErrorKind);

/// The enum type for [`RegisterMemoryRegionError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum RegisterMemoryRegionErrorKind {
    Ibverbs(#[from] io::Error),
    #[error("unexpected null pointer provided")]
    UnexpectedNullPointer,
}

/// A registered memory region abstraction that wraps an RDMA memory region.
#[derive(Debug)]
pub struct MemoryRegion {
    mr: NonNull<ibv_mr>,
    _pd: Arc<ProtectionDomain>,
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        unsafe {
            ibv_dereg_mr(self.mr.as_mut());
        }
    }
}

impl MemoryRegion {
    /// Returns the RDMA local key.
    pub fn lkey(&self) -> u32 {
        unsafe { self.mr.as_ref().lkey }
    }

    /// Returns the RDMA remote key.
    pub fn rkey(&self) -> u32 {
        unsafe { self.mr.as_ref().rkey }
    }

    /// Returns the length of the registered region.
    pub fn region_len(&self) -> usize {
        unsafe { self.mr.as_ref().length }
    }

    /// Returns the starting pointer if the memory is host memory.
    /// Device memory is opaque and thus returns `None`.
    pub fn get_ptr(&self) -> usize {
        unsafe { self.mr.as_ref().addr as _ }
    }

    /// # Safety
    ///
    /// Return the handle of memory region.
    /// We mark this method unsafe because the lifetime of `ibv_mr` is not associated
    /// with the return value.
    pub unsafe fn mr(&self) -> NonNull<ibv_mr> {
        self.mr
    }
}

impl MemoryRegion {
    /// Register a memory region that was allocated outside this module.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid for `len` bytes
    /// and that the memory remains accessible and unmodified as needed.
    pub(crate) unsafe fn reg_mr(
        pd: Arc<ProtectionDomain>, ptr: usize, len: usize, access: AccessFlags,
    ) -> Result<Self, RegisterMemoryRegionError> {
        let mr = unsafe { ibv_reg_mr(pd.pd.as_ptr(), ptr as _, len, access.into()) };

        if mr.is_null() {
            return Err(RegisterMemoryRegionErrorKind::Ibverbs(io::Error::last_os_error()).into());
        }

        Ok(Self {
            mr: NonNull::new(mr).unwrap(),
            _pd: pd,
        })
    }
}

unsafe impl Send for MemoryRegion {}
unsafe impl Sync for MemoryRegion {}
