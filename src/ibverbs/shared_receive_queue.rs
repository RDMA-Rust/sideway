//! A [`SharedReceiveQueue`] is a receive queue that can be shared by multiple [`QueuePair`]s, so
//! that receive buffers are posted once into a common pool instead of to every QP's own recv queue.
//!
//! [`QueuePair`]: crate::ibverbs::queue_pair::QueuePair
//!
use rdma_mummy_sys::{
    ibv_create_srq, ibv_destroy_srq, ibv_modify_srq, ibv_query_srq, ibv_srq, ibv_srq_attr, ibv_srq_attr_mask,
    ibv_srq_init_attr,
};
use std::{fmt, io, ptr::NonNull, sync::Arc};

use super::protection_domain::ProtectionDomain;
use super::queue_pair::{PostRecvGuard, RecvTarget};

/// Error returned by [`SharedReceiveQueueBuilder::build`] for creating a new RDMA SRQ.
#[derive(Debug, thiserror::Error)]
#[error("failed to create shared receive queue")]
#[non_exhaustive]
pub struct CreateSharedReceiveQueueError(#[from] pub CreateSharedReceiveQueueErrorKind);

/// The enum type for [`CreateSharedReceiveQueueError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum CreateSharedReceiveQueueErrorKind {
    Ibverbs(#[from] io::Error),
}

/// Error returned by [`SharedReceiveQueue::modify`] for modifying a RDMA SRQ's attributes.
#[derive(Debug, thiserror::Error)]
#[error("failed to modify shared receive queue")]
#[non_exhaustive]
pub struct ModifySharedReceiveQueueError(#[from] pub ModifySharedReceiveQueueErrorKind);

/// The enum type for [`ModifySharedReceiveQueueError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum ModifySharedReceiveQueueErrorKind {
    Ibverbs(#[from] io::Error),
}

/// Error returned by [`SharedReceiveQueue::query`] for querying a RDMA SRQ's attributes.
#[derive(Debug, thiserror::Error)]
#[error("failed to query shared receive queue")]
#[non_exhaustive]
pub struct QuerySharedReceiveQueueError(#[from] pub QuerySharedReceiveQueueErrorKind);

/// The enum type for [`QuerySharedReceiveQueueError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum QuerySharedReceiveQueueErrorKind {
    Ibverbs(#[from] io::Error),
}

/// A shared receive queue, created with [`SharedReceiveQueueBuilder::build`].
///
/// It could be attached to [`QueuePair`]s with [`QueuePairBuilder::setup_shared_receive_queue`],
/// each [`QueuePair`] holds a reference to it, so it is destroyed only after every [`QueuePair`]
/// using it is destroyed.
///
/// [`QueuePair`]: crate::ibverbs::queue_pair::QueuePair
/// [`QueuePairBuilder::setup_shared_receive_queue`]: crate::ibverbs::queue_pair::QueuePairBuilder::setup_shared_receive_queue
///
#[derive(Debug)]
pub struct SharedReceiveQueue {
    srq: NonNull<ibv_srq>,
    _pd: Arc<ProtectionDomain>,
}

// libibverbs guarantees that ibv_post_srq_recv is thread safe.
unsafe impl Send for SharedReceiveQueue {}
unsafe impl Sync for SharedReceiveQueue {}

impl Drop for SharedReceiveQueue {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_srq(self.srq.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

impl SharedReceiveQueue {
    /// # Safety
    ///
    /// Return the handle of shared receive queue.
    /// We mark this method unsafe because the lifetime of `ibv_srq` is not associated
    /// with the return value.
    pub unsafe fn srq(&self) -> NonNull<ibv_srq> {
        self.srq
    }

    /// Starts a post receive operation, the posted Work Requests would be consumed by any
    /// [`QueuePair`] attached to this SRQ.
    ///
    /// As posting to a SRQ is thread safe, multiple [`PostRecvGuard`]s could be held at the same
    /// time.
    ///
    /// [`QueuePair`]: crate::ibverbs::queue_pair::QueuePair
    ///
    pub fn start_post_recv(&self) -> PostRecvGuard<'_> {
        PostRecvGuard::new(RecvTarget::SharedReceiveQueue(self.srq))
    }

    /// Modify the attributes of this SRQ, only the attributes set on `attr` would be modified.
    pub fn modify(&self, attr: &SharedReceiveQueueAttribute) -> Result<(), ModifySharedReceiveQueueError> {
        let mut raw = attr.attr;
        let ret = unsafe { ibv_modify_srq(self.srq.as_ptr(), &mut raw, attr.attr_mask as _) };
        match ret {
            0 => Ok(()),
            err => Err(ModifySharedReceiveQueueErrorKind::Ibverbs(io::Error::from_raw_os_error(err)).into()),
        }
    }

    /// Query the current attributes of this SRQ.
    pub fn query(&self) -> Result<SharedReceiveQueueAttribute, QuerySharedReceiveQueueError> {
        let mut attr = SharedReceiveQueueAttribute::new();
        let ret = unsafe { ibv_query_srq(self.srq.as_ptr(), &mut attr.attr) };
        match ret {
            0 => Ok(attr),
            err => Err(QuerySharedReceiveQueueErrorKind::Ibverbs(io::Error::from_raw_os_error(err)).into()),
        }
    }
}

/// Describe the attributes of a [`SharedReceiveQueue`], could be used for getting current
/// attributes with [`SharedReceiveQueue::query`] or modifying them with
/// [`SharedReceiveQueue::modify`].
#[derive(Clone, Copy)]
pub struct SharedReceiveQueueAttribute {
    attr: ibv_srq_attr,
    attr_mask: u32,
}

impl fmt::Debug for SharedReceiveQueueAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedReceiveQueueAttribute")
            .field("max_wr", &self.attr.max_wr)
            .field("max_sge", &self.attr.max_sge)
            .field("srq_limit", &self.attr.srq_limit)
            .field("attr_mask", &self.attr_mask)
            .finish()
    }
}

impl Default for SharedReceiveQueueAttribute {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedReceiveQueueAttribute {
    pub fn new() -> Self {
        SharedReceiveQueueAttribute {
            attr: ibv_srq_attr {
                max_wr: 0,
                max_sge: 0,
                srq_limit: 0,
            },
            attr_mask: 0,
        }
    }

    /// Setup the maximum number of outstanding RDMA Work Requests in the SRQ, used for resizing
    /// it, the device must support [`DeviceCapabilityFlags::SharedReceiveQueueResize`].
    ///
    /// [`DeviceCapabilityFlags::SharedReceiveQueueResize`]: crate::ibverbs::device_context::DeviceCapabilityFlags::SharedReceiveQueueResize
    ///
    pub fn setup_max_wr(&mut self, max_wr: u32) -> &mut Self {
        self.attr.max_wr = max_wr;
        self.attr_mask |= ibv_srq_attr_mask::IBV_SRQ_MAX_WR.0;
        self
    }

    /// Setup the limit of the SRQ, when the number of outstanding Work Requests drops below it, an
    /// `IBV_EVENT_SRQ_LIMIT_REACHED` asynchronous event would be generated, the limit is then
    /// disarmed and needs to be set again. `0` means the limit is disarmed.
    pub fn setup_srq_limit(&mut self, srq_limit: u32) -> &mut Self {
        self.attr.srq_limit = srq_limit;
        self.attr_mask |= ibv_srq_attr_mask::IBV_SRQ_LIMIT.0;
        self
    }

    /// Returns the maximum number of outstanding RDMA Work Requests in the SRQ.
    pub fn max_wr(&self) -> u32 {
        self.attr.max_wr
    }

    /// Returns the maximum number of scatter / gather elements in any RDMA Work Request.
    pub fn max_sge(&self) -> u32 {
        self.attr.max_sge
    }

    /// Returns the limit of the SRQ.
    pub fn srq_limit(&self) -> u32 {
        self.attr.srq_limit
    }
}

/// A factory for creating [`SharedReceiveQueue`] with the specified parameters.
pub struct SharedReceiveQueueBuilder {
    init_attr: ibv_srq_init_attr,
    pd: Arc<ProtectionDomain>,
}

impl SharedReceiveQueueBuilder {
    pub fn new(pd: &Arc<ProtectionDomain>) -> SharedReceiveQueueBuilder {
        SharedReceiveQueueBuilder {
            init_attr: ibv_srq_init_attr {
                srq_context: std::ptr::null_mut(),
                attr: ibv_srq_attr {
                    max_wr: 16,
                    max_sge: 1,
                    srq_limit: 0,
                },
            },
            pd: Arc::clone(pd),
        }
    }

    /// Setup the maximum number of outstanding RDMA Work Requests that can be posted to the SRQ.
    pub fn setup_max_wr(&mut self, max_wr: u32) -> &mut Self {
        self.init_attr.attr.max_wr = max_wr;
        self
    }

    /// Setup the maximum number of scatter / gather elements in any RDMA Work Request that can be
    /// posted to the SRQ.
    pub fn setup_max_sge(&mut self, max_sge: u32) -> &mut Self {
        self.init_attr.attr.max_sge = max_sge;
        self
    }

    /// Create a [`SharedReceiveQueue`] with [`ibv_create_srq`].
    ///
    /// The actual `max_wr` and `max_sge` could be greater than the requested values, use
    /// [`SharedReceiveQueue::query`] to get them.
    ///
    /// [`ibv_create_srq`]: https://man7.org/linux/man-pages/man3/ibv_create_srq.3.html
    ///
    pub fn build(&self) -> Result<Arc<SharedReceiveQueue>, CreateSharedReceiveQueueError> {
        let mut init_attr = self.init_attr;
        let srq = unsafe { ibv_create_srq(self.pd.pd.as_ptr(), &mut init_attr) };

        Ok(Arc::new(SharedReceiveQueue {
            srq: NonNull::new(srq).ok_or::<CreateSharedReceiveQueueError>(
                CreateSharedReceiveQueueErrorKind::Ibverbs(io::Error::last_os_error()).into(),
            )?,
            _pd: Arc::clone(&self.pd),
        }))
    }
}
