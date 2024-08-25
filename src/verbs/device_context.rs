use crate::verbs::address_handle::Gid;
use std::io;
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};

use rdma_mummy_sys::{
    ___ibv_query_port, ibv_alloc_pd, ibv_close_device, ibv_context, ibv_device_attr_ex, ibv_mtu, ibv_port_attr,
    ibv_query_device_ex, ibv_query_gid, ibv_query_gid_type,
};

use super::completion::{CompletionChannel, CompletionQueueBuilder};
use super::protection_domain::ProtectionDomain;

pub struct DeviceContext {
    pub(crate) context: *mut ibv_context,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Mtu {
    Mtu256 = ibv_mtu::IBV_MTU_256,
    Mtu512 = ibv_mtu::IBV_MTU_512,
    Mtu1024 = ibv_mtu::IBV_MTU_1024,
    Mtu2048 = ibv_mtu::IBV_MTU_2048,
    Mtu4096 = ibv_mtu::IBV_MTU_4096,
}

impl From<u32> for Mtu {
    fn from(mtu: u32) -> Self {
        match mtu {
            ibv_mtu::IBV_MTU_256 => Mtu::Mtu256,
            ibv_mtu::IBV_MTU_512 => Mtu::Mtu512,
            ibv_mtu::IBV_MTU_1024 => Mtu::Mtu1024,
            ibv_mtu::IBV_MTU_2048 => Mtu::Mtu2048,
            ibv_mtu::IBV_MTU_4096 => Mtu::Mtu4096,
            _ => panic!("Unknown MTU value: {mtu}"),
        }
    }
}

pub struct PortAttr {
    attr: ibv_port_attr,
}

impl PortAttr {
    pub fn max_mtu(&self) -> Mtu {
        self.attr.max_mtu.into()
    }

    pub fn active_mtu(&self) -> Mtu {
        self.attr.active_mtu.into()
    }

    pub fn gid_tbl_len(&self) -> i32 {
        self.attr.gid_tbl_len
    }
}

pub struct DeviceAttr {
    pub attr: ibv_device_attr_ex,
}

impl DeviceAttr {
    pub fn phys_port_cnt(&self) -> u8 {
        self.attr.orig_attr.phys_port_cnt
    }
}

impl Drop for DeviceContext {
    fn drop(&mut self) {
        unsafe {
            ibv_close_device(self.context);
        }
    }
}

impl DeviceContext {
    pub fn alloc_pd(&self) -> Result<ProtectionDomain, String> {
        let pd = unsafe { ibv_alloc_pd(self.context) };

        if pd.is_null() {
            return Err(format!("Create pd failed! {:?}", io::Error::last_os_error()));
        }

        Ok(ProtectionDomain::new(&self, unsafe {
            NonNull::new(pd).unwrap_unchecked()
        }))
    }

    pub fn create_comp_channel(&self) -> Result<CompletionChannel, String> {
        CompletionChannel::new(&self)
    }

    pub fn create_cq_builder(&self) -> CompletionQueueBuilder {
        CompletionQueueBuilder::new(&self)
    }

    pub fn query_device(&self) -> Result<DeviceAttr, String> {
        let mut attr = MaybeUninit::<ibv_device_attr_ex>::uninit();
        unsafe {
            match ibv_query_device_ex(self.context, ptr::null(), attr.as_mut_ptr()) {
                0 => Ok(DeviceAttr {
                    attr: attr.assume_init(),
                }),
                ret => Err(format!("Failed to query device, returned {ret}")),
            }
        }
    }

    pub fn query_port(&self, port_num: u8) -> Result<PortAttr, String> {
        let mut attr = MaybeUninit::<ibv_port_attr>::uninit();
        unsafe {
            match ___ibv_query_port(self.context, port_num, attr.as_mut_ptr()) {
                0 => Ok(PortAttr {
                    attr: attr.assume_init(),
                }),
                ret => Err(format!("Failed to query port {port_num}, returned {ret}")),
            }
        }
    }

    pub fn query_gid(&self, port_num: u8, gid_index: i32) -> Result<Gid, String> {
        let mut gid = Gid::default();
        unsafe {
            match ibv_query_gid(self.context, port_num, gid_index, gid.as_mut()) {
                0 => Ok(gid),
                ret => Err(format!(
                    "Failed to query gid_index {gid_index} on port {port_num}, returned {ret}"
                )),
            }
        }
    }

    pub fn query_gid_type(&self, port_num: u8, gid_index: u32) -> Result<u32, String> {
        let mut gid_type = u32::default();
        unsafe {
            match ibv_query_gid_type(self.context, port_num, gid_index, &mut gid_type) {
                0 => Ok(gid_type),
                ret => Err(format!(
                    "Failed to query gid_index {gid_index} on port {port_num}, returned {ret}"
                )),
            }
        }
    }
}
