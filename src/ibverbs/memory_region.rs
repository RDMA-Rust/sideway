use rdma_mummy_sys::{ibv_dereg_mr, ibv_mr, ibv_reg_mr};
use std::{io, marker::PhantomData, ptr::NonNull};

use super::protection_domain::ProtectionDomain;
use super::AccessFlags;

#[derive(Debug, thiserror::Error)]
#[error("failed to register memory region")]
#[non_exhaustive]
pub struct RegisterMemoryRegionError(#[from] pub RegisterMemoryRegionErrorKind);

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
pub struct MemoryRegion<'pd> {
    mr: NonNull<ibv_mr>,
    _pd: PhantomData<&'pd ()>,
}

impl Drop for MemoryRegion<'_> {
    fn drop(&mut self) {
        unsafe {
            ibv_dereg_mr(self.mr.as_mut());
        }
    }
}

impl MemoryRegion<'_> {
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
}

impl<'pd> MemoryRegion<'pd> {
    /// Register a memory region that was allocated outside this module.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid for `len` bytes
    /// and that the memory remains accessible and unmodified as needed.
    pub(crate) unsafe fn reg_mr(
        pd: &'pd ProtectionDomain, ptr: usize, len: usize, access: AccessFlags,
    ) -> Result<Self, RegisterMemoryRegionError> {
        let mr = unsafe { ibv_reg_mr(pd.pd.as_ptr(), ptr as _, len, access.into()) };

        if mr.is_null() {
            return Err(RegisterMemoryRegionErrorKind::Ibverbs(io::Error::last_os_error()).into());
        }

        Ok(Self {
            mr: NonNull::new(mr).unwrap(),
            _pd: PhantomData,
        })
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::ibverbs::{device, protection_domain::ProtectionDomain};
//     use std::ptr;

//     // Helper to get a PD for testing
//     fn get_test_pd() -> ProtectionDomain<'static> {
//         let devices = device::DeviceList::new().unwrap();
//         for device in &devices {
//             let ctx = device.open().unwrap();
//             return ctx.alloc_pd().unwrap()
//         }
//     }

//     #[test]
//     fn test_buffer_allocation() {
//         let buffer = Buffer::from_len_zeroed(1024);
//         assert_eq!(buffer.len, 1024);
//         assert!(!buffer.data.is_null());

//         // Verify buffer is zeroed
//         unsafe {
//             let slice = std::slice::from_raw_parts(buffer.data.as_ptr(), buffer.len);
//             assert!(slice.iter().all(|&x| x == 0));
//         }
//     }

//     #[test]
//     fn test_managed_mr_registration() {
//         let pd = get_test_pd();
//         let size = 4096;
//         let mr = pd.reg_managed_mr(size, AccessFlags::LocalWrite).unwrap();

//         assert_eq!(mr.region_len(), size);
//         assert_eq!(mr.memory_type(), MemoryType::Host);
//         assert!(mr.get_ptr().is_some());

//         // Verify memory properties
//         let ptr = mr.get_ptr().unwrap();
//         assert!(!ptr.is_null());
//         assert!(mr.lkey() != 0);
//         assert!(mr.rkey() != 0);
//     }

//     #[test]
//     fn test_user_mr_registration() {
//         let pd = get_test_pd();
//         let size = 4096;
//         let buffer = Buffer::from_len_zeroed(size);

//         unsafe {
//             let mr = pd.reg_user_mr(buffer.data.as_ptr(), size, AccessFlags::LocalWrite).unwrap();
//             assert_eq!(mr.region_len(), size);
//             assert_eq!(mr.memory_type(), MemoryType::Host);
//             assert_eq!(mr.get_ptr().unwrap(), buffer.data.as_ptr());
//         }
//     }

//     #[test]
//     fn test_device_mr_registration() {
//         let pd = get_test_pd();
//         let size = 4096;
//         let handle = DeviceMemoryHandle(0x1000); // Simulated device memory handle

//         unsafe {
//             let mr = pd.reg_device_mr(handle, size, AccessFlags::LocalWrite).unwrap();
//             assert_eq!(mr.region_len(), size);
//             assert_eq!(mr.memory_type(), MemoryType::Device);
//             assert_eq!(mr.handle(), handle.0);
//             assert!(mr.get_ptr().is_none()); // Device memory has no host pointer
//         }
//     }

//     #[test]
//     fn test_mr_error_handling() {
//         let pd = get_test_pd();

//         // Test null pointer error
//         unsafe {
//             let result = pd.reg_user_mr(ptr::null_mut(), 1024, AccessFlags::LocalWrite);
//             assert!(matches!(
//                 result.unwrap_err().0,
//                 RegisterMemoryRegionErrorKind::UnexpectedNullPointer
//             ));
//         }

//         // Test invalid device handle
//         unsafe {
//             let result = pd.reg_device_mr(DeviceMemoryHandle(0), 1024, AccessFlags::LocalWrite);
//             assert!(matches!(
//                 result.unwrap_err().0,
//                 RegisterMemoryRegionErrorKind::UnexpectedNullPointer
//             ));
//         }
//     }

//     #[test]
//     fn test_mr_offset_access() {
//         let pd = get_test_pd();
//         let size = 4096;
//         let mr = pd.reg_managed_mr(size, AccessFlags::LocalWrite).unwrap();

//         // Valid offset
//         assert!(mr.get_ptr_by_offset(100).is_some());

//         // Invalid offset
//         assert!(mr.get_ptr_by_offset(size + 1).is_none());
//     }

//     #[test]
//     fn test_memory_cleanup() {
//         let pd = get_test_pd();
//         let size = 4096;

//         // Test managed MR cleanup
//         {
//             let _mr = pd.reg_managed_mr(size, AccessFlags::LocalWrite).unwrap();
//             // MR should be deregistered and memory freed when dropped
//         }

//         // Test user MR cleanup
//         {
//             let buffer = Buffer::from_len_zeroed(size);
//             unsafe {
//                 let _mr = pd.reg_user_mr(buffer.data.as_ptr(), size, AccessFlags::LocalWrite).unwrap();
//                 // MR should be deregistered when dropped
//             }
//             // Buffer cleaned up here
//         }
//     }
// }
