use std::{ffi::CStr, io, marker::PhantomData};

use rdma_mummy_sys::{
    ibv_device, ibv_free_device_list, ibv_get_device_guid, ibv_get_device_list, ibv_get_device_name, ibv_open_device,
};

use crate::verbs::device_context::DeviceContext;

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

    pub fn iter<'list>(&'list self) -> DeviceListIter<'list> {
        DeviceListIter {
            current: 0,
            total: self.num_devices,
            devices: self,
        }
    }

    pub fn len(&self) -> usize {
        self.num_devices
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

pub struct Device<'list> {
    device: *mut ibv_device,
    _dev_list: PhantomData<&'list ()>,
}

impl Device<'_> {
    pub fn new<'list>(device: *mut ibv_device, _devices: &'list DeviceList) -> Self {
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

    pub fn guid(&self) -> u64 {
        unsafe { ibv_get_device_guid(self.device) }
    }
}
