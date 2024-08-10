use rdma_mummy_sys::{self, ibv_qp, ibv_qp_init_attr_ex};

#[derive(Debug, Clone, Copy)]
pub struct QueuePairInitAttr {
    _attr_ptr: *mut ibv_qp_init_attr_ex,
}

impl QueuePairInitAttr {
}

pub struct QueuePair {
    pub(crate) qp_ptr: *mut ibv_qp,
}

impl TryFrom<QueuePairInitAttr> for *mut ibv_qp_init_attr_ex {
    type Error = &'static str;

    fn try_from(_init_attr: QueuePairInitAttr) -> Result<*mut ibv_qp_init_attr_ex, &'static str> {
        todo!();
    }
}

impl QueuePair {}
