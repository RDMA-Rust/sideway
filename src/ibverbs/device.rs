use std::{ffi::CStr, io, marker::PhantomData};

use rdma_mummy_sys::{
    ibv_device, ibv_free_device_list, ibv_get_device_guid, ibv_get_device_list, ibv_get_device_name, ibv_open_device,
    ibv_transport_type,
};

use super::device_context::DeviceContext;
use super::device_context::Guid;

pub struct DeviceList {
    devices: *mut *mut ibv_device,
    num_devices: usize,
}

impl DeviceList {
    pub fn new() -> io::Result<DeviceList> {
        let mut num_devices: i32 = 0;
        let devices = unsafe { ibv_get_device_list(&mut num_devices as *mut _) };
        if devices.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(DeviceList {
            devices,
            num_devices: num_devices as usize,
        })
    }

    pub fn iter(&self) -> DeviceListIter<'_> {
        DeviceListIter {
            current: 0,
            total: self.num_devices,
            devices: self,
        }
    }

    pub fn len(&self) -> usize {
        self.num_devices
    }

    pub fn is_empty(&self) -> bool {
        self.num_devices != 0
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

#[repr(i32)]
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

    pub fn open(&self) -> io::Result<DeviceContext> {
        unsafe {
            let context = ibv_open_device(self.device);
            if context.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(DeviceContext { context })
        }
    }

    pub fn name(&self) -> Option<String> {
        unsafe {
            let name = ibv_get_device_name(self.device);
            if name.is_null() {
                None
            } else {
                Some(String::from_utf8_lossy(CStr::from_ptr(name).to_bytes()).to_string())
            }
        }
    }

    pub fn guid(&self) -> Guid {
        unsafe { Guid(ibv_get_device_guid(self.device)) }
    }

    pub fn transport_type(&self) -> TransportType {
        unsafe { (*self.device).transport_type.into() }
    }
}
