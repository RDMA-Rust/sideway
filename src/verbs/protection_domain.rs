use rdma_mummy_sys::{ibv_create_qp_ex, ibv_dealloc_pd, ibv_pd, ibv_qp_init_attr_ex, ibv_reg_mr};
use std::io;

use super::{
    memory_region::{Buffer, MemoryRegion},
    queue_pair::{QueuePair, QueuePairInitAttr},
};

#[derive(Debug)]
pub struct ProtectionDomain {
    pub(crate) pd_ptr: *mut ibv_pd,
}

impl Drop for ProtectionDomain {
    fn drop(&mut self) {
        unsafe {
            ibv_dealloc_pd(self.pd_ptr);
        }
    }
}

impl ProtectionDomain {
    pub fn reg_managed_mr(&self, size: usize) -> Result<MemoryRegion, String> {
        let buf = Buffer::from_len_zeroed(size);

        let mr_ptr = unsafe { ibv_reg_mr(self.pd_ptr, buf.data.as_ptr() as _, buf.len, 0) };

        if mr_ptr.is_null() {
            return Err(format!("{:?}", io::Error::last_os_error()));
        }

        Ok(MemoryRegion { buf, mr_ptr })
    }

    pub fn reg_user_mr(&self) -> Result<MemoryRegion, String> {
        todo!();
    }

    pub fn create_qp(&self, init_attr: QueuePairInitAttr) -> Result<QueuePair, String> {
        unsafe {
            let qp_init_attr: *mut ibv_qp_init_attr_ex = match init_attr.clone().try_into() {
                Ok(attr) => attr,
                Err(err) => return Err(format!("Failed to translate attr {:?}", err)),
            };

            let qp_ptr = ibv_create_qp_ex((*self.pd_ptr).context, qp_init_attr);
            match qp_ptr {
                Some(qp) => Ok(QueuePair { qp_ptr: qp }),
                None => Err(format!("Failed to create QP {:?}", init_attr)),
            }
        }
    }
}
