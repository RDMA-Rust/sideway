use rdma_mummy_sys::{ibv_create_qp_ex, ibv_dealloc_pd, ibv_pd, ibv_qp_init_attr_ex, ibv_reg_mr};
use std::io;
use std::marker::PhantomData;
use std::ptr::NonNull;

use super::{
    device_context::DeviceContext,
    memory_region::{Buffer, MemoryRegion},
};

#[derive(Debug)]
pub struct ProtectionDomain<'ctx> {
    pub(crate) pd: NonNull<ibv_pd>,
    _dev_ctx: PhantomData<&'ctx ()>,
}

impl Drop for ProtectionDomain<'_> {
    fn drop(&mut self) {
        unsafe {
            ibv_dealloc_pd(self.pd.as_mut());
        }
    }
}

impl ProtectionDomain<'_> {
    pub(crate) fn new<'ctx>(_ctx: &'ctx DeviceContext, pd: NonNull<ibv_pd>) -> Self {
        ProtectionDomain {
            // This should not fail as the caller ensures pd is not NULL
            pd,
            _dev_ctx: PhantomData,
        }
    }

    pub fn reg_managed_mr(&mut self, size: usize) -> Result<MemoryRegion, String> {
        let buf = Buffer::from_len_zeroed(size);

        let mr = unsafe { ibv_reg_mr(self.pd.as_mut(), buf.data.as_ptr() as _, buf.len, 0) };

        if mr.is_null() {
            return Err(format!("{:?}", io::Error::last_os_error()));
        }

        Ok(MemoryRegion::new(self, buf, unsafe {
            NonNull::new(mr).unwrap_unchecked()
        }))
    }

    pub fn reg_user_mr(&self) -> Result<MemoryRegion, String> {
        todo!();
    }
}
