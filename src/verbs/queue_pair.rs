use rdma_mummy_sys::{self, ibv_qp, ibv_qp_init_attr_ex};
use std::ptr::NonNull;

use super::protection_domain::ProtectionDomain;

pub struct QueuePair<'pd> {
    pub(crate) qp: NonNull<ibv_qp>,
    _pd: &'pd ProtectionDomain<'pd>,
}

impl QueuePair<'_> {
    pub(crate) fn new<'pd>(pd: &'pd ProtectionDomain) -> Self {
        todo!()
    }
}
