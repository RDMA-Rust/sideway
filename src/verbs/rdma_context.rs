use crate::verbs::address_handle::Gid;
use std::io;
use std::mem::MaybeUninit;
use std::ptr::{self, null_mut};

use rdma_mummy_sys::{
    ___ibv_query_port, ibv_alloc_pd, ibv_close_device, ibv_context, ibv_create_cq, ibv_create_cq_ex,
    ibv_device_attr_ex, ibv_port_attr, ibv_query_device_ex, ibv_query_gid, ibv_query_gid_type,
};

use super::completion_queue::{CompletionQueue, CompletionQueueEx, CqInitAttr};
use super::protection_domain::ProtectionDomain;

pub struct RdmaContext {
    pub(crate) context: *mut ibv_context,
}

#[derive(Debug, Clone, Copy)]
pub enum Mtu {
    IbvMtu256 = 1,
    IbvMtu512 = 2,
    IbvMtu1024 = 3,
    IbvMtu2048 = 4,
    IbvMtu4096 = 5,
    Unknown,
}

impl From<u32> for Mtu {
    fn from(mtu: u32) -> Self {
        match mtu {
            _ if mtu == Mtu::IbvMtu256 as u32 => Mtu::IbvMtu256,
            _ if mtu == Mtu::IbvMtu512 as u32 => Mtu::IbvMtu512,
            _ if mtu == Mtu::IbvMtu1024 as u32 => Mtu::IbvMtu1024,
            _ if mtu == Mtu::IbvMtu2048 as u32 => Mtu::IbvMtu2048,
            _ if mtu == Mtu::IbvMtu4096 as u32 => Mtu::IbvMtu4096,
            _ => Mtu::Unknown,
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

impl Drop for RdmaContext {
    fn drop(&mut self) {
        unsafe {
            ibv_close_device(self.context);
        }
    }
}

impl RdmaContext {
    pub fn alloc_pd(&self) -> Result<ProtectionDomain, String> {
        let pd_ptr = unsafe { ibv_alloc_pd(self.context) };

        if pd_ptr.is_null() {
            return Err(format!("{:?}", io::Error::last_os_error()));
        }

        Ok(ProtectionDomain { pd_ptr })
    }

    pub fn create_cq(&self, cqe: i32) -> Result<CompletionQueue, String> {
        let cq_ptr = unsafe { ibv_create_cq(self.context, cqe, null_mut(), null_mut(), 0) };

        if cq_ptr.is_null() {
            return Err(format!("Create cq failed! {:?}", io::Error::last_os_error()));
        }

        Ok(CompletionQueue { cq_ptr })
    }

    pub fn create_cq_ex(&self, init_attr: CqInitAttr) -> Result<CompletionQueueEx, String> {
        let cq_ptr = unsafe { ibv_create_cq_ex(self.context, init_attr.attr_ptr) };
        match cq_ptr {
            Some(cq_ptr) => Ok(CompletionQueueEx { cq_ptr }),
            None => Err(format!("Create cq ex failed! {:?}", io::Error::last_os_error())),
        }
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
                ret => Err(format!("Failed to query gid_index {gid_index} on port {port_num}, returned {ret}")),
            }
        }
    }

    pub fn query_gid_type(&self, port_num: u8, gid_index: u32) -> Result<u32, String> {
        let mut gid_type = u32::default();
        unsafe {
            match ibv_query_gid_type(self.context, port_num, gid_index, &mut gid_type) {
                0 => Ok(gid_type),
                ret => Err(format!("Failed to query gid_index {gid_index} on port {port_num}, returned {ret}")),
            }
        }
    }
}
