use std::{ffi::CStr, io};

use rdma_mummy_sys::{
    ibv_device, ibv_free_device_list, ibv_get_device_guid, ibv_get_device_list, ibv_get_device_name, ibv_open_device,
};

use crate::verbs::rdma_context::RdmaContext;

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

    pub fn iter(&self) -> DeviceIter {
        DeviceIter {
            current: 0,
            total: self.num_devices,
            devices: self.devices,
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

pub struct DeviceIter {
    current: usize,
    total: usize,
    devices: *mut *mut ibv_device,
}

impl Iterator for DeviceIter {
    type Item = *mut ibv_device;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.total {
            None
        } else {
            unsafe {
                let device = *self.devices.add(self.current);
                self.current += 1;
                Some(device)
            }
        }
    }
}

pub struct Device {
    device: *mut ibv_device,
}

impl Device {
    pub fn new(device: *mut ibv_device) -> Self {
        Device { device }
    }

    pub fn open(&self) -> io::Result<RdmaContext> {
        unsafe {
            let context = ibv_open_device(self.device);
            if context.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(RdmaContext { context })
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
