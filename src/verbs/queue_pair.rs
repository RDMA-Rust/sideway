use rdma_mummy_sys::{
    self, ibv_create_qp, ibv_destroy_qp, ibv_qp, ibv_qp_cap, ibv_qp_ex, ibv_qp_init_attr, ibv_qp_init_attr_ex,
    ibv_qp_type, ibv_rx_hash_conf,
};
use std::{
    io,
    marker::PhantomData,
    mem::MaybeUninit,
    path::Path,
    ptr::{null, null_mut, NonNull},
};

use super::{completion::CompletionQueue, protection_domain::ProtectionDomain};

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum QueuePairType {
    ReliableConnection = ibv_qp_type::IBV_QPT_RC,
    UnreliableConnection = ibv_qp_type::IBV_QPT_UC,
    UnreliableDatagram = ibv_qp_type::IBV_QPT_UD,
    RawPacket = ibv_qp_type::IBV_QPT_RAW_PACKET,
    ReliableConnectionExtendedSend = ibv_qp_type::IBV_QPT_XRC_SEND,
    ReliableConnectionExtendedRecv = ibv_qp_type::IBV_QPT_XRC_RECV,
}

#[derive(Debug)]
pub struct QueuePair<'res> {
    pub(crate) qp: NonNull<ibv_qp>,
    _phantom: PhantomData<&'res ()>,
}

impl Drop for QueuePair<'_> {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_qp(self.qp.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

pub struct QueuePairExtended<'res> {
    pub(crate) qp_ex: NonNull<ibv_qp_ex>,
    _phantom: PhantomData<&'res ()>,
}

pub struct QueuePairBuilder<'res> {
    init_attr: ibv_qp_init_attr_ex,
    _phantom: PhantomData<&'res ()>,
}

impl<'res> QueuePairBuilder<'res> {
    pub fn new<'pd>(pd: &'pd ProtectionDomain) -> QueuePairBuilder<'res>
    where
        'pd: 'res,
    {
        QueuePairBuilder {
            init_attr: ibv_qp_init_attr_ex {
                qp_context: null_mut(),
                send_cq: null_mut(),
                recv_cq: null_mut(),
                srq: null_mut(),
                cap: ibv_qp_cap {
                    max_send_wr: 16,
                    max_recv_wr: 16,
                    max_send_sge: 1,
                    max_recv_sge: 1,
                    max_inline_data: 0,
                },
                qp_type: QueuePairType::ReliableConnection as _,
                sq_sig_all: 0,
                comp_mask: 0,
                pd: pd.pd.as_ptr(),
                xrcd: null_mut(),
                create_flags: 0,
                max_tso_header: 0,
                rwq_ind_tbl: null_mut(),
                rx_hash_conf: unsafe { MaybeUninit::<ibv_rx_hash_conf>::uninit().assume_init() },
                source_qpn: 0,
                send_ops_flags: 0,
            },
            _phantom: PhantomData,
        }
    }

    pub fn setup_qp_type(&mut self, qp_type: QueuePairType) -> &mut Self {
        self.init_attr.qp_type = qp_type as u32;
        self
    }

    pub fn setup_max_send_wr(&mut self, max_send_wr: u32) -> &mut Self {
        self.init_attr.cap.max_send_wr = max_send_wr;
        self
    }

    pub fn setup_max_recv_wr(&mut self, max_recv_wr: u32) -> &mut Self {
        self.init_attr.cap.max_recv_wr = max_recv_wr;
        self
    }

    pub fn setup_max_send_sge(&mut self, max_send_sge: u32) -> &mut Self {
        self.init_attr.cap.max_send_sge = max_send_sge;
        self
    }

    pub fn setup_max_recv_sge(&mut self, max_recv_sge: u32) -> &mut Self {
        self.init_attr.cap.max_recv_sge = max_recv_sge;
        self
    }

    pub fn setup_max_inline_data(&mut self, max_inline_data: u32) -> &mut Self {
        self.init_attr.cap.max_inline_data = max_inline_data;
        self
    }

    pub fn setup_send_cq<'sq>(&mut self, send_cq: &'sq CompletionQueue) -> &mut Self
    where
        'sq: 'res,
    {
        self.init_attr.send_cq = send_cq.cq.as_ptr();
        self
    }

    pub fn setup_recv_cq<'rq>(&mut self, recv_cq: &'rq CompletionQueue) -> &mut Self
    where
        'rq: 'res,
    {
        self.init_attr.recv_cq = recv_cq.cq.as_ptr();
        self
    }

    pub fn build(&self) -> Result<QueuePair<'res>, String> {
        let qp = unsafe {
            ibv_create_qp(
                self.init_attr.pd,
                &mut ibv_qp_init_attr {
                    qp_context: null_mut(),
                    send_cq: self.init_attr.send_cq,
                    recv_cq: self.init_attr.recv_cq,
                    srq: null_mut(),
                    cap: self.init_attr.cap,
                    qp_type: QueuePairType::ReliableConnection as _,
                    sq_sig_all: 0,
                },
            )
        };

        Ok(QueuePair {
            qp: NonNull::new(qp).ok_or(format!("ibv_create_qp failed, {}", io::Error::last_os_error()))?,
            _phantom: PhantomData,
        })
    }

    pub fn build_ex() -> () {
        todo!();
    }
}

impl QueuePair<'_> {
    pub(crate) fn new<'pd>(pd: &'pd ProtectionDomain) -> Self {
        todo!()
    }
}
