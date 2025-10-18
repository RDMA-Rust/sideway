//! The device is used for creating a device context, everything about RDMA starts here.
use std::ops::Index;
use std::sync::Arc;
use std::{ffi::CStr, io, marker::PhantomData};

use rdma_mummy_sys::{
    ibv_device, ibv_free_device_list, ibv_get_device_guid, ibv_get_device_list, ibv_get_device_name, ibv_open_device,
    ibv_transport_type,
};

use super::device_context::DeviceContext;
use super::device_context::Guid;

/// Error returned by [`DeviceList::new`] for getting a new [`DeviceList`].
#[derive(Debug, thiserror::Error)]
#[error("failed to get device list")]
#[non_exhaustive]
pub struct GetDeviceListError(#[from] pub GetDeviceListErrorKind);

/// The enum type for [`GetDeviceListError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum GetDeviceListErrorKind {
    Ibverbs(#[from] io::Error),
}

/// Error returned by [`Device::open`] for open the device to create a [`DeviceContext`].
#[derive(Debug, thiserror::Error)]
#[error("failed to open device")]
#[non_exhaustive]
pub struct OpenDeviceError(#[from] pub OpenDeviceErrorKind);

/// The enum type for [`OpenDeviceError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum OpenDeviceErrorKind {
    Ibverbs(#[from] io::Error),
}

/// The RDMA device list which contains all RDMA devices based on the environment configuration.
pub struct DeviceList {
    devices: *mut *mut ibv_device,
    num_devices: usize,
}

impl DeviceList {
    /// Get a new RDMA device list based on current environment.
    pub fn new() -> Result<DeviceList, GetDeviceListError> {
        let mut num_devices: i32 = 0;
        let devices = unsafe { ibv_get_device_list(&mut num_devices as *mut _) };
        if devices.is_null() {
            return Err(GetDeviceListErrorKind::Ibverbs(io::Error::last_os_error()).into());
        }

        Ok(DeviceList {
            devices,
            num_devices: num_devices as usize,
        })
    }

    /// Get a device list iterator.
    pub fn iter(&self) -> DeviceListIter<'_> {
        DeviceListIter {
            current: 0,
            total: self.num_devices,
            devices: self,
        }
    }

    /// Get a device list slice from current device list.
    pub fn as_device_slice<'list>(&'list self) -> &'list [Device<'list>] {
        unsafe { std::slice::from_raw_parts(self.devices as *const Device<'list>, self.num_devices) }
    }

    /// Get the device from device list by index.
    pub fn get(&self, index: usize) -> Option<Device<'_>> {
        if index >= self.num_devices {
            None
        } else {
            unsafe {
                let device = *self.devices.add(index);
                if device.is_null() {
                    None
                } else {
                    Some(Device::new(device, self))
                }
            }
        }
    }

    /// Get the device list length.
    pub fn len(&self) -> usize {
        self.num_devices
    }

    /// Check if current device list is empty.
    pub fn is_empty(&self) -> bool {
        self.num_devices == 0
    }
}

impl<'list> Index<usize> for &'list DeviceList {
    type Output = Device<'list>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_device_slice()[index]
    }
}

impl Drop for DeviceList {
    fn drop(&mut self) {
        unsafe { ibv_free_device_list(self.devices) };
    }
}

impl<'list> IntoIterator for &'list DeviceList {
    type Item = <DeviceListIter<'list> as Iterator>::Item;
    type IntoIter = DeviceListIter<'list>;

    fn into_iter(self) -> Self::IntoIter {
        DeviceListIter {
            current: 0,
            total: self.num_devices,
            devices: self,
        }
    }
}

/// The iterator of the [`DeviceList`].
pub struct DeviceListIter<'list> {
    current: usize,
    total: usize,
    devices: &'list DeviceList,
}

impl<'list> Iterator for DeviceListIter<'list> {
    type Item = Device<'list>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            None
        } else {
            unsafe {
                let device = *self.devices.devices.add(self.current);
                self.current += 1;
                Some(Device::new(device, self.devices))
            }
        }
    }
}

/// The underlying transport type of the device.
#[repr(i32)]
#[derive(PartialEq, Eq, Debug)]
pub enum TransportType {
    Unknown = ibv_transport_type::IBV_TRANSPORT_UNKNOWN,
    InfiniBand = ibv_transport_type::IBV_TRANSPORT_IB,
    IWarp = ibv_transport_type::IBV_TRANSPORT_IWARP,
    Usnic = ibv_transport_type::IBV_TRANSPORT_USNIC,
    UsnicUdp = ibv_transport_type::IBV_TRANSPORT_USNIC_UDP,
    Unspecified = ibv_transport_type::IBV_TRANSPORT_UNSPECIFIED,
}

impl From<i32> for TransportType {
    fn from(trans: i32) -> Self {
        match trans {
            ibv_transport_type::IBV_TRANSPORT_UNKNOWN => TransportType::Unknown,
            ibv_transport_type::IBV_TRANSPORT_IB => TransportType::InfiniBand,
            ibv_transport_type::IBV_TRANSPORT_IWARP => TransportType::IWarp,
            ibv_transport_type::IBV_TRANSPORT_USNIC => TransportType::Usnic,
            ibv_transport_type::IBV_TRANSPORT_USNIC_UDP => TransportType::UsnicUdp,
            ibv_transport_type::IBV_TRANSPORT_UNSPECIFIED => TransportType::Unspecified,
            _ => panic!("Unknown transport type value: {trans}"),
        }
    }
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::InfiniBand => write!(f, "InfiniBand"),
            TransportType::IWarp => write!(f, "iWARP"),
            TransportType::Usnic => write!(f, "usNIC"),
            TransportType::UsnicUdp => write!(f, "usNIC UDP"),
            TransportType::Unspecified => write!(f, "Unspecified"),
            TransportType::Unknown => write!(f, "Invalid transport"),
        }
    }
}

/// A safe wrapper around a raw RDMA device pointer.
///
/// The lifetime parameter ensures that a Device cannot outlive the DeviceList
/// from which it was derived.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Device<'list> {
    device: *mut ibv_device,
    _dev_list: PhantomData<&'list ()>,
}

impl Device<'_> {
    pub fn new(device: *mut ibv_device, _devices: &DeviceList) -> Self {
        Device {
            device,
            _dev_list: PhantomData,
        }
    }

    /// Open the device to create a [`DeviceContext`] for querying / creating all other RDMA
    /// resources later.
    pub fn open(&self) -> Result<Arc<DeviceContext>, OpenDeviceError> {
        unsafe {
            let context = ibv_open_device(self.device);
            if context.is_null() {
                return Err(OpenDeviceErrorKind::Ibverbs(io::Error::last_os_error()).into());
            }
            Ok(Arc::new(DeviceContext { context }))
        }
    }
}

/// Trait for common device information access.
pub trait DeviceInfo {
    /// Get the name of the device, for example, `mlx5_0`.
    fn name(&self) -> String;

    /// Get the GUID of the device.
    fn guid(&self) -> Guid;

    /// Get the transport type of the device.
    fn transport_type(&self) -> TransportType;
}

impl DeviceInfo for Device<'_> {
    fn name(&self) -> String {
        unsafe {
            let name = ibv_get_device_name(self.device);
            if name.is_null() {
                String::new()
            } else {
                String::from_utf8_lossy(CStr::from_ptr(name).to_bytes()).to_string()
            }
        }
    }

    fn guid(&self) -> Guid {
        unsafe { Guid(ibv_get_device_guid(self.device)) }
    }

    fn transport_type(&self) -> TransportType {
        unsafe { (*self.device).transport_type.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdma_mummy_sys::{_ibv_device_ops, ibv_node_type};
    use std::ffi::CString;

    #[test]
    fn test_transport_type_conversion() {
        assert_eq!(
            TransportType::from(ibv_transport_type::IBV_TRANSPORT_UNKNOWN),
            TransportType::Unknown
        );
        assert_eq!(
            TransportType::from(ibv_transport_type::IBV_TRANSPORT_IB),
            TransportType::InfiniBand
        );
        assert_eq!(
            TransportType::from(ibv_transport_type::IBV_TRANSPORT_IWARP),
            TransportType::IWarp
        );
        assert_eq!(
            TransportType::from(ibv_transport_type::IBV_TRANSPORT_USNIC),
            TransportType::Usnic
        );
        assert_eq!(
            TransportType::from(ibv_transport_type::IBV_TRANSPORT_USNIC_UDP),
            TransportType::UsnicUdp
        );
        assert_eq!(
            TransportType::from(ibv_transport_type::IBV_TRANSPORT_UNSPECIFIED),
            TransportType::Unspecified
        );
    }

    #[test]
    #[should_panic(expected = "Unknown transport type value")]
    fn test_invalid_transport_type_conversion() {
        let _ = TransportType::from(999);
    }

    #[test]
    fn test_iterations() {
        // Mock some `ibv_device` on heap
        let dev_num = 8;
        let mut ibv_dev_ptrs: Vec<*mut ibv_device> = Vec::with_capacity(dev_num);
        for i in 0..dev_num {
            let mut ibv_dev = Box::new(ibv_device {
                _ops: _ibv_device_ops {
                    _dummy1: None,
                    _dummy2: None,
                },
                node_type: ibv_node_type::IBV_NODE_CA,
                transport_type: ibv_transport_type::IBV_TRANSPORT_IB,
                name: [0; 64usize],
                dev_name: [0; 64usize],
                dev_path: [0; 256usize],
                ibdev_path: [0; 256usize],
            });
            for (j, &b) in CString::new(format!("mock{i}")).unwrap().as_bytes().iter().enumerate() {
                ibv_dev.name[j] = b as std::os::raw::c_char;
            }
            ibv_dev_ptrs.push(Box::into_raw(ibv_dev));
        }
        let dev_list = DeviceList {
            devices: ibv_dev_ptrs.as_mut_ptr(),
            num_devices: dev_num,
        };

        assert_eq!(dev_list.len(), dev_num);
        assert_eq!(dev_list.is_empty(), dev_num == 0);
        for i in 0..dev_num {
            let expect_name = format!("mock{i}");
            assert_eq!(dev_list.get(i).unwrap().name(), expect_name);
            assert_eq!((&dev_list).index(i).name(), expect_name);
            assert_eq!((&dev_list)[i].name(), expect_name);
        }

        // Slice
        let dev_slice = dev_list.as_device_slice();
        assert_eq!(dev_slice.len(), dev_num);
        for (i, _) in dev_slice.iter().enumerate() {
            assert_eq!(dev_slice[i].name(), format!("mock{i}"));
        }

        // Iterator
        let mut iter = dev_list.iter();
        for i in 0..dev_num {
            assert_eq!(iter.next().unwrap().name(), format!("mock{i}"));
        }
        assert!(iter.next().is_none());

        // IntoIterator
        for dev in &dev_list {
            assert_eq!(dev.transport_type(), TransportType::InfiniBand);
        }

        // Avoid calling `ibv_free_device_list` for mock devices,
        // or it will cause panic in rdma-core
        std::mem::forget(dev_list);
    }

    #[test]
    fn test_get_first_and_last() -> Result<(), Box<dyn std::error::Error>> {
        let devices = DeviceList::new().unwrap();

        assert!(devices.get(devices.len()).is_none());

        if !devices.is_empty() {
            let first = devices.get(0);
            let last = devices.get(devices.len() - 1);

            assert!(!first.unwrap().device.is_null());
            assert!(!last.unwrap().device.is_null());

            if devices.len() == 1 {
                assert_eq!(first.unwrap().device, last.unwrap().device);
            } else {
                assert_ne!(first.unwrap().device, last.unwrap().device);
            }
        }

        Ok(())
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_out_of_bound_index() {
        let devices = DeviceList::new().unwrap();

        let _ = (&devices)[devices.len()];
    }
}
