pub mod address;
pub mod completion;
pub mod device;
pub mod device_context;
pub mod memory_region;
pub mod protection_domain;
pub mod queue_pair;

use bitmask_enum::bitmask;
use rdma_mummy_sys::ibv_access_flags;

#[bitmask(i32)]
#[bitmask_config(vec_debug)]
pub enum AccessFlags {
    LocalWrite = ibv_access_flags::IBV_ACCESS_LOCAL_WRITE.0 as _,
    RemoteWrite = ibv_access_flags::IBV_ACCESS_REMOTE_WRITE.0 as _,
    RemoteRead = ibv_access_flags::IBV_ACCESS_REMOTE_READ.0 as _,
    RemoteAtomic = ibv_access_flags::IBV_ACCESS_REMOTE_ATOMIC.0 as _,
    MemoryWindowBind = ibv_access_flags::IBV_ACCESS_MW_BIND.0 as _,
    ZeroBased = ibv_access_flags::IBV_ACCESS_ZERO_BASED.0 as _,
    OnDemand = ibv_access_flags::IBV_ACCESS_ON_DEMAND.0 as _,
    HugeTlb = ibv_access_flags::IBV_ACCESS_HUGETLB.0 as _,
    FlushGlobal = ibv_access_flags::IBV_ACCESS_FLUSH_GLOBAL.0 as _,
    FlushPersistent = ibv_access_flags::IBV_ACCESS_FLUSH_PERSISTENT.0 as _,
    RelaxedOrdering = ibv_access_flags::IBV_ACCESS_RELAXED_ORDERING.0 as _,
}
