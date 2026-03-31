use rdma_mummy_sys::mlx5dv;
use rdma_mummy_sys::{
    ibv_qp_init_attr_mask, ibv_qp_create_send_ops_flags, ibv_qp_type,
};
use std::ptr::NonNull;
use std::sync::Arc;

use crate::ibverbs::completion::GenericCompletionQueue;
use crate::ibverbs::protection_domain::ProtectionDomain;

fn cq_raw_ptr(cq: &GenericCompletionQueue) -> *mut rdma_mummy_sys::ibv_cq {
    match cq {
        GenericCompletionQueue::Basic(cq) => cq.cq.as_ptr(),
        GenericCompletionQueue::Extended(cq) => cq.cq_ex.as_ptr() as *mut rdma_mummy_sys::ibv_cq,
    }
}

/// DC transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcType {
    /// DC Initiator — client side, can address any DCT.
    Initiator,
    /// DC Target — server side, accepts from any DCI.
    Target,
}

/// DC Initiator QP. Can send RDMA WRITE/READ to any DCT by specifying
/// the target address per work request via `wr_set_dc_addr()`.
///
/// Drop order: QP destroyed first (via ibv_destroy_qp), then CQs freed.
pub struct DcInitiator {
    qp: NonNull<rdma_mummy_sys::ibv_qp>,
    qp_ex: NonNull<rdma_mummy_sys::ibv_qp_ex>,
    mlx5_qp_ex: NonNull<mlx5dv::mlx5dv_qp_ex>,
    _pd: Arc<ProtectionDomain>,
    // CQs held to ensure they outlive the QP (Rust drops fields in declaration order)
    _send_cq: GenericCompletionQueue,
    _recv_cq: GenericCompletionQueue,
}

unsafe impl Send for DcInitiator {}
unsafe impl Sync for DcInitiator {}

/// DC Target QP. Listens for incoming RDMA operations from any DCI.
///
/// Drop order: QP destroyed first, then CQs freed.
pub struct DcTarget {
    qp: NonNull<rdma_mummy_sys::ibv_qp>,
    dctn: u32,
    _pd: Arc<ProtectionDomain>,
    _send_cq: GenericCompletionQueue,
    _recv_cq: GenericCompletionQueue,
}

unsafe impl Send for DcTarget {}
unsafe impl Sync for DcTarget {}

/// Builder for creating DC QPs.
pub struct DcQpBuilder {
    pd: Arc<ProtectionDomain>,
    dc_type: DcType,
    send_cq: Option<GenericCompletionQueue>,
    recv_cq: Option<GenericCompletionQueue>,
    srq: Option<*mut rdma_mummy_sys::ibv_srq>,
    max_send_wr: u32,
    max_recv_wr: u32,
    max_send_sge: u32,
    max_recv_sge: u32,
    dc_access_key: u64,
}

impl DcQpBuilder {
    pub fn new(pd: &Arc<ProtectionDomain>, dc_type: DcType) -> Self {
        Self {
            pd: pd.clone(),
            dc_type,
            send_cq: None,
            recv_cq: None,
            srq: None,
            max_send_wr: 128,
            max_recv_wr: 128,
            max_send_sge: 1,
            max_recv_sge: 1,
            dc_access_key: 0,
        }
    }

    pub fn send_cq(mut self, cq: GenericCompletionQueue) -> Self {
        self.send_cq = Some(cq);
        self
    }

    pub fn recv_cq(mut self, cq: GenericCompletionQueue) -> Self {
        self.recv_cq = Some(cq);
        self
    }

    pub fn max_send_wr(mut self, n: u32) -> Self {
        self.max_send_wr = n;
        self
    }

    pub fn max_recv_wr(mut self, n: u32) -> Self {
        self.max_recv_wr = n;
        self
    }

    /// Set the SRQ for DCT (required for DC Target).
    ///
    /// # Safety
    /// The SRQ must outlive the QP.
    pub unsafe fn srq(mut self, srq: *mut rdma_mummy_sys::ibv_srq) -> Self {
        self.srq = Some(srq);
        self
    }

    pub fn dc_access_key(mut self, key: u64) -> Self {
        self.dc_access_key = key;
        self
    }

    /// Build the DC QP via mlx5dv_create_qp().
    pub fn build_dci(self) -> Result<DcInitiator, DcError> {
        assert!(matches!(self.dc_type, DcType::Initiator));

        let send_cq = self.send_cq.ok_or(DcError::MissingSendCq)?;
        let recv_cq = self.recv_cq.ok_or(DcError::MissingRecvCq)?;

        let send_cq_ptr = cq_raw_ptr(&send_cq);
        let recv_cq_ptr = cq_raw_ptr(&recv_cq);

        let mut qp_attr: rdma_mummy_sys::ibv_qp_init_attr_ex = unsafe { std::mem::zeroed() };
        qp_attr.qp_type = ibv_qp_type::IBV_QPT_DRIVER;
        qp_attr.send_cq = send_cq_ptr;
        qp_attr.recv_cq = recv_cq_ptr;
        qp_attr.pd = self.pd.pd.as_ptr();
        qp_attr.cap.max_send_wr = self.max_send_wr;
        qp_attr.cap.max_recv_wr = 0; // DCI doesn't receive
        qp_attr.cap.max_send_sge = self.max_send_sge;
        qp_attr.comp_mask = (ibv_qp_init_attr_mask::IBV_QP_INIT_ATTR_PD
            | ibv_qp_init_attr_mask::IBV_QP_INIT_ATTR_SEND_OPS_FLAGS).0;
        qp_attr.send_ops_flags = (ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_RDMA_WRITE
            | ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_RDMA_READ
            | ibv_qp_create_send_ops_flags::IBV_QP_EX_WITH_SEND).0 as u64;

        let mut mlx5_attr: mlx5dv::mlx5dv_qp_init_attr = unsafe { std::mem::zeroed() };
        mlx5_attr.comp_mask = mlx5dv::MLX5DV_QP_INIT_ATTR_MASK_DC as u64;
        mlx5_attr.dc_init_attr.dc_type = mlx5dv::MLX5DV_DCTYPE_DCI as u32;

        let qp_ptr = unsafe {
            mlx5dv::mlx5dv_create_qp(
                self.pd._dev_ctx.context.as_ptr().cast(),
                (&mut qp_attr as *mut rdma_mummy_sys::ibv_qp_init_attr_ex).cast(),
                &mut mlx5_attr,
            )
        };
        if qp_ptr.is_null() {
            let errno = std::io::Error::last_os_error();
            return Err(DcError::CreateFailedWithErrno(errno));
        }
        let qp = NonNull::new(qp_ptr.cast::<rdma_mummy_sys::ibv_qp>()).unwrap();

        let qp_ex_ptr = unsafe { rdma_mummy_sys::ibv_qp_to_qp_ex(qp.as_ptr()) };
        let qp_ex = NonNull::new(qp_ex_ptr).ok_or(DcError::ExtendedQpFailed)?;

        // Get mlx5 extended QP for DC addressing — cast qp_ex to mlx5dv's type
        let mlx5_qp_ex_ptr = unsafe {
            mlx5dv::mlx5dv_qp_ex_from_ibv_qp_ex(qp_ex.as_ptr().cast())
        };
        let mlx5_qp_ex = NonNull::new(mlx5_qp_ex_ptr).ok_or(DcError::Mlx5QpExFailed)?;

        Ok(DcInitiator {
            qp,
            qp_ex,
            mlx5_qp_ex,
            _pd: self.pd,
            _send_cq: send_cq,
            _recv_cq: recv_cq,
        })
    }

    /// Build a DC Target QP. Requires SRQ to be set.
    pub fn build_dct(self) -> Result<DcTarget, DcError> {
        assert!(matches!(self.dc_type, DcType::Target));

        let send_cq = self.send_cq.ok_or(DcError::MissingSendCq)?;
        let recv_cq = self.recv_cq.ok_or(DcError::MissingRecvCq)?;
        let srq = self.srq.ok_or(DcError::MissingSrq)?;

        let send_cq_ptr = cq_raw_ptr(&send_cq);
        let recv_cq_ptr = cq_raw_ptr(&recv_cq);

        let mut qp_attr: rdma_mummy_sys::ibv_qp_init_attr_ex = unsafe { std::mem::zeroed() };
        qp_attr.qp_type = ibv_qp_type::IBV_QPT_DRIVER;
        qp_attr.send_cq = send_cq_ptr;
        qp_attr.recv_cq = recv_cq_ptr;
        qp_attr.srq = srq;
        qp_attr.pd = self.pd.pd.as_ptr();
        qp_attr.cap.max_recv_wr = 0;
        qp_attr.cap.max_recv_sge = 1;
        qp_attr.comp_mask = ibv_qp_init_attr_mask::IBV_QP_INIT_ATTR_PD.0;

        let mut mlx5_attr: mlx5dv::mlx5dv_qp_init_attr = unsafe { std::mem::zeroed() };
        mlx5_attr.comp_mask = mlx5dv::MLX5DV_QP_INIT_ATTR_MASK_DC as u64;
        mlx5_attr.dc_init_attr.dc_type = mlx5dv::MLX5DV_DCTYPE_DCT as u32;
        mlx5_attr.dc_init_attr.__bindgen_anon_1.dct_access_key = self.dc_access_key;

        let qp_ptr = unsafe {
            mlx5dv::mlx5dv_create_qp(
                self.pd._dev_ctx.context.as_ptr().cast(),
                (&mut qp_attr as *mut rdma_mummy_sys::ibv_qp_init_attr_ex).cast(),
                &mut mlx5_attr,
            )
        };
        if qp_ptr.is_null() {
            let errno = std::io::Error::last_os_error();
            return Err(DcError::CreateFailedWithErrno(errno));
        }
        let qp = NonNull::new(qp_ptr.cast::<rdma_mummy_sys::ibv_qp>()).unwrap();
        let dctn = unsafe { (*qp.as_ptr()).qp_num };

        Ok(DcTarget {
            qp,
            dctn,
            _pd: self.pd,
            _send_cq: send_cq,
            _recv_cq: recv_cq,
        })
    }
}

impl DcInitiator {
    /// QP number.
    pub fn qp_number(&self) -> u32 {
        unsafe { (*self.qp.as_ptr()).qp_num }
    }

    /// Set the DC target address for the next work request.
    /// Must be called after `ibv_wr_start()` and before the operation (write/read/send).
    ///
    /// # Safety
    /// The address handle must be valid and the remote DCTN must be reachable.
    pub unsafe fn wr_set_dc_addr(
        &mut self,
        ah: *mut rdma_mummy_sys::ibv_ah,
        remote_dctn: u32,
        dc_key: u64,
    ) {
        let fn_ptr = (*self.mlx5_qp_ex.as_ptr()).wr_set_dc_addr.unwrap();
        fn_ptr(self.mlx5_qp_ex.as_ptr(), ah.cast(), remote_dctn, dc_key);
    }

    /// Get raw ibv_qp_ex pointer for extended send operations.
    pub fn as_qp_ex_ptr(&mut self) -> *mut rdma_mummy_sys::ibv_qp_ex {
        self.qp_ex.as_ptr()
    }

    /// Get raw ibv_qp pointer for state transitions.
    pub fn as_raw_ptr(&self) -> *mut rdma_mummy_sys::ibv_qp {
        self.qp.as_ptr()
    }
}

impl DcTarget {
    /// QP number (DCTN — used by DCI to address this target).
    pub fn dctn(&self) -> u32 {
        self.dctn
    }

    /// Get raw ibv_qp pointer for state transitions.
    pub fn as_raw_ptr(&self) -> *mut rdma_mummy_sys::ibv_qp {
        self.qp.as_ptr()
    }
}

impl Drop for DcInitiator {
    fn drop(&mut self) {
        unsafe {
            rdma_mummy_sys::ibv_destroy_qp(self.qp.as_ptr());
        }
    }
}

impl Drop for DcTarget {
    fn drop(&mut self) {
        unsafe {
            rdma_mummy_sys::ibv_destroy_qp(self.qp.as_ptr());
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DcError {
    #[error("mlx5dv_create_qp failed: {0}")]
    CreateFailedWithErrno(std::io::Error),
    #[error("ibv_qp_to_qp_ex failed")]
    ExtendedQpFailed,
    #[error("mlx5dv_qp_ex_from_ibv_qp_ex failed")]
    Mlx5QpExFailed,
    #[error("send CQ not set")]
    MissingSendCq,
    #[error("recv CQ not set")]
    MissingRecvCq,
    #[error("SRQ not set (required for DCT)")]
    MissingSrq,
}
