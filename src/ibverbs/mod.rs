pub mod address;
pub mod completion;
pub mod device;
pub mod device_context;
pub mod memory_region;
pub mod protection_domain;
pub mod queue_pair;

use bitmask_enum::bitmask;
use rdma_mummy_sys::ibv_access_flags;

/// [`AccessFlags`] would be used for modifying [`QueuePair`] or creating [`MemoryRegion`].
///
/// # Example
///
/// ```no_run
/// use sideway::ibverbs::AccessFlags;
/// use sideway::ibverbs::device::DeviceList;
/// use sideway::ibverbs::protection_domain::ProtectionDomain;
/// use sideway::ibverbs::queue_pair::{QueuePair, QueuePairAttribute, QueuePairState, GenericQueuePair};
///
/// let mut flags = AccessFlags::LocalWrite | AccessFlags::RemoteWrite | AccessFlags::RemoteRead;
///
/// let device_list = DeviceList::new().unwrap();
/// let device = device_list.get(0).unwrap();
/// let context = device.open().unwrap();
/// let pd = context.alloc_pd().unwrap();
/// let mut qp = pd.create_qp_builder().build().unwrap();
///
/// let data: [u8; 8] = [8; 8];
/// // We would use flags for creating MR here
/// let mut mr = unsafe { pd.reg_mr(data.as_ptr() as usize, data.len(), flags) };
///
/// let mut attr = QueuePairAttribute::new();
/// // We would use flags for modifying QP to INIT state here
/// attr.setup_state(QueuePairState::Init)
///     .setup_pkey_index(0)
///     .setup_port(1)
///     .setup_access_flags(flags);
///
/// qp.modify(&attr);
/// ```
///
/// # Notice
///
/// If [`AccessFlags::RemoteWrite`] or [`AccessFlags::RemoteAtomic`] is set, then
/// [`AccessFlags::LocalWrite`] must be set too.
///
/// Local read access if always enabled for the [`MemoryRegion`]. To create an implicit On-Demand
/// Paging (ODP) [`MemoryRegion`], [`AccessFlags::OnDemand`] should be set, addr should be `0` and
/// length should be [`usize::MAX`].
///
/// If [`AccessFlags::HugeTlb`] is set, then application awares that for this [`MemoryRegion`] all
/// pages are huge and must promise it will never do anything to break huge pages.
///
/// # Reference
///
/// - RDMAmojo: [`ibv_modify_qp`](https://www.rdmamojo.com/2013/01/12/ibv_modify_qp/), [`ibv_reg_mr`](https://www.rdmamojo.com/2012/09/07/ibv_reg_mr/)
/// - rdma-core manpages: [`ibv_reg_mr`](https://man7.org/linux/man-pages/man3/ibv_reg_mr.3.html)
///
/// [`QueuePair`]: queue_pair::QueuePair
/// [`MemoryRegion`]: memory_region::MemoryRegion
///
#[bitmask(i32)]
#[bitmask_config(vec_debug)]
pub enum AccessFlags {
    /// Enable Local Write Access.
    LocalWrite = ibv_access_flags::IBV_ACCESS_LOCAL_WRITE.0 as _,
    /// Enable Remote Write Access.
    RemoteWrite = ibv_access_flags::IBV_ACCESS_REMOTE_WRITE.0 as _,
    /// Enable Remote Read Access.
    RemoteRead = ibv_access_flags::IBV_ACCESS_REMOTE_READ.0 as _,
    /// Enable Remote Atomic Operation Access (if supported).
    RemoteAtomic = ibv_access_flags::IBV_ACCESS_REMOTE_ATOMIC.0 as _,
    /// Enable Memory Window Binding.
    MemoryWindowBind = ibv_access_flags::IBV_ACCESS_MW_BIND.0 as _,
    /// Use byte offset from beginning of MR to access this MR, instead of a pointer address.
    ZeroBased = ibv_access_flags::IBV_ACCESS_ZERO_BASED.0 as _,
    /// Create an on-demand paging (ODP) MR.
    OnDemand = ibv_access_flags::IBV_ACCESS_ON_DEMAND.0 as _,
    /// Huge pages are guaranteed to be used for this MR, applicable with [`AccessFlags::OnDemand`]
    /// in explicit mode only.
    HugeTlb = ibv_access_flags::IBV_ACCESS_HUGETLB.0 as _,
    /// Enable Remote Flush Operation with global visibility placement type (if supported).
    FlushGlobal = ibv_access_flags::IBV_ACCESS_FLUSH_GLOBAL.0 as _,
    /// Enable Remote Flush Operation with persistence placement type (if supported).
    FlushPersistent = ibv_access_flags::IBV_ACCESS_FLUSH_PERSISTENT.0 as _,
    /// This setting allows the NIC to relax the order that data is transferred between the
    /// network and the target memory region. Relaxed ordering allows network initiated
    /// writes (such as incoming message send or RDMA write operations) to reach memory
    /// in an arbitrary order. This can improve the performance of some applications.
    /// However, relaxed ordering has the following impact: RDMA write-after-write message
    /// order is no longer guaranteed. (Send messages will still match posted receive buffers
    /// in order.) Back-to-back network writes that target the same memory region
    /// leave the region in an unknown state. Relaxed ordering does not change completion
    /// semantics, such as data visibility. That is, a completion still ensures that all
    /// data is visible, including data from prior transfers. Relaxed ordered operations
    /// will also not bypass atomic operations.
    RelaxedOrdering = ibv_access_flags::IBV_ACCESS_RELAXED_ORDERING.0 as _,
}
