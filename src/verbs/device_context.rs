use crate::verbs::address::Gid;
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};

use rdma_mummy_sys::{
    _ibv_query_gid_table, ibv_alloc_pd, ibv_close_device, ibv_context, ibv_device_attr_ex, ibv_get_device_name,
    ibv_gid_entry, ibv_mtu, ibv_port_attr, ibv_query_device_ex, ibv_query_gid, ibv_query_gid_type, ibv_query_port,
    IBV_GID_TYPE_IB, IBV_GID_TYPE_ROCE_V1, IBV_GID_TYPE_ROCE_V2, IBV_GID_TYPE_SYSFS_IB_ROCE_V1,
    IBV_GID_TYPE_SYSFS_ROCE_V2, IBV_LINK_LAYER_ETHERNET, IBV_LINK_LAYER_INFINIBAND,
};

use super::address::GidEntry;
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

    pub fn link_layer(&self) -> u8 {
        self.attr.link_layer
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

        Ok(ProtectionDomain::new(self, unsafe {
            NonNull::new(pd).unwrap_unchecked()
        }))
    }

    pub fn create_comp_channel(&self) -> Result<CompletionChannel, String> {
        CompletionChannel::new(self)
    }

    pub fn create_cq_builder(&self) -> CompletionQueueBuilder {
        CompletionQueueBuilder::new(self)
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
            match ibv_query_port(self.context, port_num, attr.as_mut_ptr()) {
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

    pub(crate) fn query_gid_table_fallback(&self) -> Result<Vec<GidEntry>, String> {
        let mut res = Vec::new();
        let dev_attr = self.query_device().unwrap();
        let mut gid_type;

        for port_num in 1..(dev_attr.phys_port_cnt() + 1) {
            let port_attr = self.query_port(port_num).unwrap();

            if let Some(name) = self.name() {
                for gid_index in 0..port_attr.gid_tbl_len() {
                    let gid = self.query_gid(port_num, gid_index).unwrap();
                    let netdev_index;

                    if gid.is_zero() {
                        continue;
                    }

                    unsafe {
                        gid_type = match self.query_gid_type(port_num, gid_index as u32).unwrap_unchecked() {
                            IBV_GID_TYPE_SYSFS_IB_ROCE_V1 if port_attr.link_layer() == IBV_LINK_LAYER_INFINIBAND => {
                                IBV_GID_TYPE_IB
                            },
                            IBV_GID_TYPE_SYSFS_IB_ROCE_V1 if port_attr.link_layer() == IBV_LINK_LAYER_ETHERNET => {
                                IBV_GID_TYPE_ROCE_V1
                            },
                            IBV_GID_TYPE_SYSFS_ROCE_V2 => IBV_GID_TYPE_ROCE_V2,
                            num => panic!("unknown gid type {num}!"),
                        };
                    }

                    let netdev = unsafe {
                        fs::read_to_string(format!(
                            "/sys/class/infiniband/{}/ports/{}/gid_attrs/ndevs/{}",
                            name, port_num, gid_index
                        ))
                        .unwrap_unchecked()
                        .trim_ascii_end()
                        .to_string()
                    };

                    unsafe {
                        netdev_index = libc::if_nametoindex(CString::new(netdev).unwrap_unchecked().as_ptr());
                    }

                    res.push(GidEntry(ibv_gid_entry {
                        gid: gid.into(),
                        gid_index: gid_index as u32,
                        port_num: port_num.into(),
                        gid_type,
                        ndev_ifindex: netdev_index,
                    }))
                }
            } else {
                return Err("device doesn't have a valid name".to_string());
            }
        }

        Ok(res)
    }

    #[inline]
    pub fn query_gid_table(&self) -> Result<Vec<GidEntry>, String> {
        let dev_attr = self.query_device()?;

        let valid_size;

        // According to the man page, the gid table entries array should be able
        // to contain all the valid GID. Thus we need to accmulate the gid table
        // len of every port on the device.
        let size: i32 = (1..(dev_attr.phys_port_cnt() + 1)).fold(0, |acc, port_num| {
            acc + self.query_port(port_num).unwrap().gid_tbl_len()
        });

        let mut entries = vec![GidEntry::default(); size as _];

        unsafe {
            valid_size = _ibv_query_gid_table(
                self.context,
                entries.as_mut_ptr() as _,
                entries.len(),
                0,
                size_of::<GidEntry>(),
            );
        };

        if valid_size == (-libc::EOPNOTSUPP).try_into().unwrap() {
            return self.query_gid_table_fallback();
        }
        if valid_size < 0 {
            return Err(format!("failed to query gid table {valid_size}"));
        }

        entries.truncate(valid_size.try_into().unwrap());
        Ok(entries)
    }

    pub fn name(&self) -> Option<String> {
        unsafe {
            let name = ibv_get_device_name((*self.context).device);
            if name.is_null() {
                None
            } else {
                Some(String::from_utf8_lossy(CStr::from_ptr(name).to_bytes()).to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::verbs::device;

    #[test]
    fn test_query_gid_table_fallback() -> Result<(), Box<dyn std::error::Error>> {
        let device_list = device::DeviceList::new()?;
        for device in &device_list {
            let ctx = device.open().unwrap();

            let gid_entries = ctx.query_gid_table().unwrap();
            let gid_entries_fallback = ctx.query_gid_table_fallback().unwrap();

            assert_eq!(gid_entries.len(), gid_entries_fallback.len());
            for i in 0..gid_entries.len() {
                assert_eq!(gid_entries[i].gid(), gid_entries_fallback[i].gid());
                assert_eq!(gid_entries[i].gid_index(), gid_entries_fallback[i].gid_index());
                assert_eq!(gid_entries[i].gid_type(), gid_entries_fallback[i].gid_type());
                assert_eq!(gid_entries[i].netdev_index(), gid_entries_fallback[i].netdev_index());
                assert_eq!(gid_entries[i].netdev_name(), gid_entries_fallback[i].netdev_name());
                assert_eq!(gid_entries[i].port_num(), gid_entries_fallback[i].port_num());
            }
        }

        Ok(())
    }
}
