use std::ffi::{CStr, CString};
use std::fmt;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};

use rdma_mummy_sys::{
    ibv_alloc_pd, ibv_close_device, ibv_context, ibv_device_attr_ex, ibv_get_device_guid, ibv_get_device_name,
    ibv_gid_entry, ibv_mtu, ibv_port_attr, ibv_port_state, ibv_query_device_ex, ibv_query_gid, ibv_query_gid_ex,
    ibv_query_gid_table, ibv_query_gid_type, ibv_query_port, IBV_GID_TYPE_IB, IBV_GID_TYPE_ROCE_V1,
    IBV_GID_TYPE_ROCE_V2, IBV_GID_TYPE_SYSFS_IB_ROCE_V1, IBV_GID_TYPE_SYSFS_ROCE_V2, IBV_LINK_LAYER_ETHERNET,
    IBV_LINK_LAYER_INFINIBAND, IBV_LINK_LAYER_UNSPECIFIED,
};
use serde::{Deserialize, Serialize};

use super::address::{Gid, GidEntry};
use super::completion::{CompletionChannel, CompletionQueueBuilder};
use super::device::{DeviceInfo, TransportType};
use super::protection_domain::ProtectionDomain;

#[derive(Debug, thiserror::Error)]
#[error("failed to alloc protection domain")]
#[non_exhaustive]
pub struct AllocateProtectionDomainError(#[from] pub AllocateProtectionDomainErrorKind);

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum AllocateProtectionDomainErrorKind {
    Ibverbs(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("failed to query device")]
#[non_exhaustive]
pub struct QueryDeviceError(#[from] pub QueryDeviceErrorKind);

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum QueryDeviceErrorKind {
    Ibverbs(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("failed to query port (port_num={port_num})")]
#[non_exhaustive]
pub struct QueryPortError {
    pub port_num: u8,
    pub source: QueryPortErrorKind,
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum QueryPortErrorKind {
    Ibverbs(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("failed to query GID table")]
#[non_exhaustive]
pub struct QueryGidTableError(#[from] pub QueryGidTableErrorKind);

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum QueryGidTableErrorKind {
    Ibverbs(#[from] io::Error),
    QueryDevice(#[from] QueryDeviceError),
    QueryPort(#[from] QueryPortError),
    QueryGid(#[from] QueryGidError),
    #[error("invalid device name")]
    InvalidDeviceName,
}

#[derive(Debug, thiserror::Error)]
#[error("failed to query GID (port_num={port_num}, gid_idex={gid_index})")]
#[non_exhaustive]
pub struct QueryGidError {
    pub port_num: u8,
    pub gid_index: u32,
    pub source: QueryGidErrorKind,
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum QueryGidErrorKind {
    Ibverbs(#[from] io::Error),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Guid(pub(crate) u64);

impl Guid {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}:{:04x}:{:04x}:{:04x}",
            (self.0 >> 48) & 0xFFFF,
            (self.0 >> 32) & 0xFFFF,
            (self.0 >> 16) & 0xFFFF,
            self.0 & 0xFFFF
        )
    }
}

pub struct DeviceContext {
    pub(crate) context: *mut ibv_context,
}

unsafe impl Send for DeviceContext {}
unsafe impl Sync for DeviceContext {}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortWidth {
    Width1X = 1,
    Width2X = 2,
    Width4X = 4,
    Width8X = 8,
    Width12X = 12,
}

impl From<u8> for PortWidth {
    fn from(width: u8) -> Self {
        match width {
            1 => PortWidth::Width1X,
            16 => PortWidth::Width2X,
            2 => PortWidth::Width4X,
            4 => PortWidth::Width8X,
            8 => PortWidth::Width12X,
            _ => panic!("Unknown port width value: {width}"),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortSpeed {
    SingleDataRate = 1,
    DoubleDataRate = (1 << 1),
    QuadrupleDataRate = (1 << 2),
    FourteenDataRateTen = (1 << 3),
    FourteenDataRate = (1 << 4),
    EnhancedDataRate = (1 << 5),
    HighDataRate = (1 << 6),
    NextDataRate = (1 << 7),
    ExtendedDataRate = (1 << 8),
}

impl From<u32> for PortSpeed {
    fn from(speed: u32) -> Self {
        match speed {
            1 => PortSpeed::SingleDataRate,
            2 => PortSpeed::DoubleDataRate,
            4 => PortSpeed::QuadrupleDataRate,
            8 => PortSpeed::FourteenDataRateTen,
            16 => PortSpeed::FourteenDataRate,
            32 => PortSpeed::EnhancedDataRate,
            64 => PortSpeed::HighDataRate,
            128 => PortSpeed::NextDataRate,
            256 => PortSpeed::ExtendedDataRate,
            _ => panic!("Unknown port speed value: {speed}"),
        }
    }
}

impl PortSpeed {
    /// According to the [wikipedia](https://en.wikipedia.org/wiki/InfiniBand),
    /// InfiniBand speed has signaling rate and actual rate (throughput), just as below
    ///
    /// | Generation | Release Year | Line Code | Signaling Rate (Gbit/s) | Throughput (Gbit/s) | Latency (μs) |
    /// |------------|--------------|-----------|-------------------------|---------------------|--------------|
    /// | SDR        | 2001/2003    | 8b/10b    | 2.5                     | 2.0                 | 5.0          |
    /// | DDR        | 2005         | 8b/10b    | 5.0                     | 4.0                 | 2.5          |
    /// | QDR        | 2007         | 8b/10b    | 10.0                    | 8.0                 | 1.3          |
    /// | FDR10      | 2011         | 64b/66b   | 10.3125                 | 10.0                | 0.7          |
    /// | FDR        | 2011         | 64b/66b   | 14.0625                 | 13.64               | 0.7          |
    /// | EDR        | 2014         | 64b/66b   | 25.78125                | 25.0                | 0.5          |
    /// | HDR        | 2018         | PAM4      | 53.125                  | 50.0                | <0.6         |
    /// | NDR        | 2022         | 256b/257b | 106.25                  | 100.0               | N/A          |
    /// | XDR        | 2024         | TBD       | 200.0                   | 200.0               | TBD          |
    /// | GDR        | TBA          | TBD       | 400.0                   | 400.0               | TBD          |
    pub fn to_signaling_rate(&self) -> f64 {
        match self {
            PortSpeed::SingleDataRate => 2.5,
            PortSpeed::DoubleDataRate => 5.0,
            PortSpeed::QuadrupleDataRate => 10.0,
            PortSpeed::FourteenDataRateTen => 10.3125,
            PortSpeed::FourteenDataRate => 14.0625,
            PortSpeed::EnhancedDataRate => 25.78125,
            PortSpeed::HighDataRate => 53.125,
            PortSpeed::NextDataRate => 106.25,
            PortSpeed::ExtendedDataRate => 250.0,
        }
    }

    pub fn to_throughput(&self) -> f64 {
        match self {
            PortSpeed::SingleDataRate => 2.0,
            PortSpeed::DoubleDataRate => 4.0,
            PortSpeed::QuadrupleDataRate => 8.0,
            PortSpeed::FourteenDataRateTen => 10.0,
            PortSpeed::FourteenDataRate => 13.64,
            PortSpeed::EnhancedDataRate => 25.0,
            PortSpeed::HighDataRate => 50.0,
            PortSpeed::NextDataRate => 100.0,
            PortSpeed::ExtendedDataRate => 250.0,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkLayer {
    Unspecified = IBV_LINK_LAYER_UNSPECIFIED,
    Infiniband = IBV_LINK_LAYER_INFINIBAND,
    Ethernet = IBV_LINK_LAYER_ETHERNET,
}

impl From<u8> for LinkLayer {
    fn from(link: u8) -> Self {
        match link {
            IBV_LINK_LAYER_UNSPECIFIED => LinkLayer::Unspecified,
            IBV_LINK_LAYER_INFINIBAND => LinkLayer::Infiniband,
            IBV_LINK_LAYER_ETHERNET => LinkLayer::Ethernet,
            _ => panic!("Unknown link layer value: {link}"),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortState {
    Nop = ibv_port_state::IBV_PORT_NOP,
    Down = ibv_port_state::IBV_PORT_DOWN,
    Initializing = ibv_port_state::IBV_PORT_INIT,
    Armed = ibv_port_state::IBV_PORT_ARMED,
    Active = ibv_port_state::IBV_PORT_ACTIVE,
    ActiveDefer = ibv_port_state::IBV_PORT_ACTIVE_DEFER,
}

impl From<u32> for PortState {
    fn from(port_state: u32) -> Self {
        match port_state {
            ibv_port_state::IBV_PORT_NOP => PortState::Nop,
            ibv_port_state::IBV_PORT_DOWN => PortState::Down,
            ibv_port_state::IBV_PORT_INIT => PortState::Initializing,
            ibv_port_state::IBV_PORT_ARMED => PortState::Armed,
            ibv_port_state::IBV_PORT_ACTIVE => PortState::Active,
            ibv_port_state::IBV_PORT_ACTIVE_DEFER => PortState::ActiveDefer,
            _ => panic!("Unknown port state value: {port_state}"),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PhysicalState {
    NoStateChange,
    Sleep,
    Polling,
    Disabled,
    PortConfigurationTraining,
    LinkUp,
    LinkErrorRecovery,
    PhyTest,
}

impl From<u8> for PhysicalState {
    fn from(phy_state: u8) -> Self {
        match phy_state {
            0 => PhysicalState::NoStateChange,
            1 => PhysicalState::Sleep,
            2 => PhysicalState::Polling,
            3 => PhysicalState::Disabled,
            4 => PhysicalState::PortConfigurationTraining,
            5 => PhysicalState::LinkUp,
            6 => PhysicalState::LinkErrorRecovery,
            7 => PhysicalState::PhyTest,
            _ => panic!("Unknown port state value: {phy_state}"),
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

    pub fn link_layer(&self) -> LinkLayer {
        self.attr.link_layer.into()
    }

    pub fn port_state(&self) -> PortState {
        self.attr.state.into()
    }

    pub fn phys_state(&self) -> PhysicalState {
        self.attr.phys_state.into()
    }

    pub fn active_width(&self) -> PortWidth {
        self.attr.active_width.into()
    }

    pub fn active_speed(&self) -> PortSpeed {
        if self.attr.active_speed_ex != 0 {
            return self.attr.active_speed_ex.into();
        }
        (self.attr.active_speed as u32).into()
    }
}

pub struct DeviceAttr {
    pub attr: ibv_device_attr_ex,
}

impl DeviceAttr {
    pub fn phys_port_cnt(&self) -> u8 {
        self.attr.orig_attr.phys_port_cnt
    }

    pub fn completion_timestamp_mask(&self) -> u64 {
        self.attr.completion_timestamp_mask
    }

    pub fn vendor_id(&self) -> u32 {
        self.attr.orig_attr.vendor_id
    }

    pub fn vendor_part_id(&self) -> u32 {
        self.attr.orig_attr.vendor_part_id
    }

    pub fn firmware_version(&self) -> String {
        self.attr
            .orig_attr
            .fw_ver
            .iter()
            .take_while(|&&c| c > 0)
            .map(|&c| c as u8 as char)
            .collect()
    }

    pub fn hardware_version(&self) -> u32 {
        self.attr.orig_attr.hw_ver
    }

    pub fn sys_image_guid(&self) -> Guid {
        Guid(self.attr.orig_attr.sys_image_guid)
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
    pub fn alloc_pd(&self) -> Result<ProtectionDomain, AllocateProtectionDomainError> {
        let pd = unsafe { ibv_alloc_pd(self.context) };

        if pd.is_null() {
            return Err(AllocateProtectionDomainErrorKind::Ibverbs(io::Error::last_os_error()).into());
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

    pub fn query_device(&self) -> Result<DeviceAttr, QueryDeviceError> {
        let mut attr = MaybeUninit::<ibv_device_attr_ex>::uninit();
        unsafe {
            match ibv_query_device_ex(self.context, ptr::null(), attr.as_mut_ptr()) {
                0 => Ok(DeviceAttr {
                    attr: attr.assume_init(),
                }),
                ret => Err(QueryDeviceErrorKind::Ibverbs(io::Error::from_raw_os_error(ret)).into()),
            }
        }
    }

    pub fn query_port(&self, port_num: u8) -> Result<PortAttr, QueryPortError> {
        let mut attr = MaybeUninit::<ibv_port_attr>::uninit();
        unsafe {
            match ibv_query_port(self.context, port_num, attr.as_mut_ptr()) {
                0 => Ok(PortAttr {
                    attr: attr.assume_init(),
                }),
                ret => Err(QueryPortError {
                    port_num,
                    source: io::Error::from_raw_os_error(ret).into(),
                }),
            }
        }
    }

    pub fn query_gid(&self, port_num: u8, gid_index: u32) -> Result<Gid, QueryGidError> {
        let mut gid = Gid::default();
        unsafe {
            match ibv_query_gid(self.context, port_num, gid_index as i32, gid.as_mut()) {
                0 => Ok(gid),
                ret => Err(QueryGidError {
                    port_num,
                    gid_index,
                    source: io::Error::from_raw_os_error(ret).into(),
                }),
            }
        }
    }

    pub fn query_gid_ex(&self, port_num: u8, gid_index: u32) -> Result<GidEntry, QueryGidError> {
        let mut entry = GidEntry::default();
        unsafe {
            match ibv_query_gid_ex(self.context, port_num as u32, gid_index, &mut entry.0, 0) {
                0 => Ok(entry),
                ret => Err(QueryGidError {
                    port_num,
                    gid_index,
                    source: io::Error::from_raw_os_error(ret).into(),
                }),
            }
        }
    }

    pub fn query_gid_type(&self, port_num: u8, gid_index: u32) -> Result<u32, QueryGidError> {
        let mut gid_type = u32::default();
        unsafe {
            match ibv_query_gid_type(self.context, port_num, gid_index, &mut gid_type) {
                0 => Ok(gid_type),
                ret => Err(QueryGidError {
                    port_num,
                    gid_index,
                    source: io::Error::from_raw_os_error(ret).into(),
                }),
            }
        }
    }

    pub(crate) fn query_gid_table_fallback(&self) -> Result<Vec<GidEntry>, QueryGidTableError> {
        let mut res = Vec::new();
        let dev_attr = self.query_device().unwrap();
        let mut gid_type;

        for port_num in 1..(dev_attr.phys_port_cnt() + 1) {
            let port_attr = self.query_port(port_num).unwrap();

            if let Some(name) = self.name() {
                for gid_index in 0..port_attr.gid_tbl_len() {
                    let gid = self
                        .query_gid(port_num, gid_index as u32)
                        .map_err(QueryGidTableErrorKind::QueryGid)?;
                    let netdev_index;

                    if gid.is_zero() {
                        continue;
                    }

                    gid_type = match self
                        .query_gid_type(port_num, gid_index as u32)
                        .map_err(QueryGidTableErrorKind::QueryGid)?
                    {
                        IBV_GID_TYPE_SYSFS_IB_ROCE_V1 if port_attr.link_layer() == LinkLayer::Infiniband => {
                            IBV_GID_TYPE_IB
                        },
                        IBV_GID_TYPE_SYSFS_IB_ROCE_V1 if port_attr.link_layer() == LinkLayer::Ethernet => {
                            IBV_GID_TYPE_ROCE_V1
                        },
                        IBV_GID_TYPE_SYSFS_ROCE_V2 => IBV_GID_TYPE_ROCE_V2,
                        num => panic!("unknown gid type {num}!"),
                    };

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
                return Err(QueryGidTableErrorKind::InvalidDeviceName.into());
            }
        }

        Ok(res)
    }

    #[inline]
    pub fn query_gid_table(&self) -> Result<Vec<GidEntry>, QueryGidTableError> {
        let dev_attr = self.query_device().map_err(QueryGidTableErrorKind::QueryDevice)?;

        let valid_size;

        // According to the man page, the gid table entries array should be able
        // to contain all the valid GID. Thus we need to accmulate the gid table
        // len of every port on the device.
        let size: i32 = (1..(dev_attr.phys_port_cnt() + 1)).fold(0, |acc, port_num| {
            acc + self.query_port(port_num).unwrap().gid_tbl_len()
        });

        let mut entries = vec![GidEntry::default(); size as _];

        unsafe {
            valid_size = ibv_query_gid_table(self.context, entries.as_mut_ptr() as _, entries.len(), 0);
        };

        if valid_size == (-libc::EOPNOTSUPP).try_into().unwrap() {
            return self.query_gid_table_fallback();
        }
        if valid_size < 0 {
            return Err(QueryGidTableErrorKind::Ibverbs(io::Error::from_raw_os_error(-valid_size as i32)).into());
        }

        entries.truncate(valid_size.try_into().unwrap());
        Ok(entries)
    }
}

impl DeviceInfo for DeviceContext {
    fn name(&self) -> Option<String> {
        unsafe {
            let name = ibv_get_device_name((*self.context).device);
            if name.is_null() {
                None
            } else {
                Some(String::from_utf8_lossy(CStr::from_ptr(name).to_bytes()).to_string())
            }
        }
    }

    fn guid(&self) -> Guid {
        unsafe { Guid(ibv_get_device_guid((*self.context).device)) }
    }

    fn transport_type(&self) -> TransportType {
        unsafe { (*(*self.context).device).transport_type.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ibverbs::device::{self, DeviceInfo};

    #[test]
    fn test_mtu_conversion() {
        assert_eq!(Mtu::from(ibv_mtu::IBV_MTU_256), Mtu::Mtu256);
        assert_eq!(Mtu::from(ibv_mtu::IBV_MTU_512), Mtu::Mtu512);
        assert_eq!(Mtu::from(ibv_mtu::IBV_MTU_1024), Mtu::Mtu1024);
        assert_eq!(Mtu::from(ibv_mtu::IBV_MTU_2048), Mtu::Mtu2048);
        assert_eq!(Mtu::from(ibv_mtu::IBV_MTU_4096), Mtu::Mtu4096);
    }

    #[test]
    #[should_panic(expected = "Unknown MTU value")]
    fn test_invalid_mtu_conversion() {
        let _ = Mtu::from(999);
    }

    #[test]
    fn test_port_width_conversion() {
        assert_eq!(PortWidth::from(1), PortWidth::Width1X);
        assert_eq!(PortWidth::from(16), PortWidth::Width2X);
        assert_eq!(PortWidth::from(2), PortWidth::Width4X);
        assert_eq!(PortWidth::from(4), PortWidth::Width8X);
        assert_eq!(PortWidth::from(8), PortWidth::Width12X);
    }

    #[test]
    fn test_port_width_multiplier() {
        assert_eq!(PortWidth::Width1X as u8, 1);
        assert_eq!(PortWidth::Width2X as u8, 2);
        assert_eq!(PortWidth::Width4X as u8, 4);
        assert_eq!(PortWidth::Width8X as u8, 8);
        assert_eq!(PortWidth::Width12X as u8, 12);
    }

    #[test]
    fn test_port_speed_conversion() {
        assert_eq!(PortSpeed::from(1), PortSpeed::SingleDataRate);
        assert_eq!(PortSpeed::from(2), PortSpeed::DoubleDataRate);
        assert_eq!(PortSpeed::from(4), PortSpeed::QuadrupleDataRate);
        assert_eq!(PortSpeed::from(8), PortSpeed::FourteenDataRateTen);
        assert_eq!(PortSpeed::from(16), PortSpeed::FourteenDataRate);
        assert_eq!(PortSpeed::from(32), PortSpeed::EnhancedDataRate);
        assert_eq!(PortSpeed::from(64), PortSpeed::HighDataRate);
        assert_eq!(PortSpeed::from(128), PortSpeed::NextDataRate);
        assert_eq!(PortSpeed::from(256), PortSpeed::ExtendedDataRate);
    }

    #[test]
    fn test_port_speed_rates() {
        assert_eq!(PortSpeed::SingleDataRate.to_signaling_rate(), 2.5);
        assert_eq!(PortSpeed::SingleDataRate.to_throughput(), 2.0);

        assert_eq!(PortSpeed::DoubleDataRate.to_signaling_rate(), 5.0);
        assert_eq!(PortSpeed::DoubleDataRate.to_throughput(), 4.0);

        assert_eq!(PortSpeed::QuadrupleDataRate.to_signaling_rate(), 10.0);
        assert_eq!(PortSpeed::QuadrupleDataRate.to_throughput(), 8.0);

        assert_eq!(PortSpeed::FourteenDataRateTen.to_signaling_rate(), 10.3125);
        assert_eq!(PortSpeed::FourteenDataRateTen.to_throughput(), 10.0);

        assert_eq!(PortSpeed::FourteenDataRate.to_signaling_rate(), 14.0625);
        assert_eq!(PortSpeed::FourteenDataRate.to_throughput(), 13.64);

        assert_eq!(PortSpeed::EnhancedDataRate.to_signaling_rate(), 25.78125);
        assert_eq!(PortSpeed::EnhancedDataRate.to_throughput(), 25.0);

        assert_eq!(PortSpeed::HighDataRate.to_signaling_rate(), 53.125);
        assert_eq!(PortSpeed::HighDataRate.to_throughput(), 50.0);

        assert_eq!(PortSpeed::NextDataRate.to_signaling_rate(), 106.25);
        assert_eq!(PortSpeed::NextDataRate.to_throughput(), 100.0);

        assert_eq!(PortSpeed::ExtendedDataRate.to_signaling_rate(), 250.0);
        assert_eq!(PortSpeed::ExtendedDataRate.to_throughput(), 250.0);
    }

    #[test]
    fn test_link_layer_conversion() {
        assert_eq!(LinkLayer::from(IBV_LINK_LAYER_UNSPECIFIED), LinkLayer::Unspecified);
        assert_eq!(LinkLayer::from(IBV_LINK_LAYER_INFINIBAND), LinkLayer::Infiniband);
        assert_eq!(LinkLayer::from(IBV_LINK_LAYER_ETHERNET), LinkLayer::Ethernet);
    }

    #[test]
    fn test_port_state_conversion() {
        assert_eq!(PortState::from(0), PortState::Nop);
        assert_eq!(PortState::from(1), PortState::Down);
        assert_eq!(PortState::from(2), PortState::Initializing);
        assert_eq!(PortState::from(3), PortState::Armed);
        assert_eq!(PortState::from(4), PortState::Active);
        assert_eq!(PortState::from(5), PortState::ActiveDefer);
    }

    #[test]
    fn test_physical_state_conversion() {
        assert_eq!(PhysicalState::from(0), PhysicalState::NoStateChange);
        assert_eq!(PhysicalState::from(1), PhysicalState::Sleep);
        assert_eq!(PhysicalState::from(2), PhysicalState::Polling);
        assert_eq!(PhysicalState::from(3), PhysicalState::Disabled);
        assert_eq!(PhysicalState::from(4), PhysicalState::PortConfigurationTraining);
        assert_eq!(PhysicalState::from(5), PhysicalState::LinkUp);
        assert_eq!(PhysicalState::from(6), PhysicalState::LinkErrorRecovery);
        assert_eq!(PhysicalState::from(7), PhysicalState::PhyTest);
    }

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

    #[test]
    fn test_query_port_error() -> Result<(), Box<dyn std::error::Error>> {
        let invalid_port_num: u8 = 255;
        let device_list = device::DeviceList::new()?;
        for device in &device_list {
            let ctx = device.open().unwrap();
            let error = ctx.query_port(invalid_port_num).err().unwrap();
            assert_eq!(error.port_num, invalid_port_num);
            match error.source {
                QueryPortErrorKind::Ibverbs(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
            };
        }
        Ok(())
    }

    #[test]
    fn test_get_device_info_from_context() -> Result<(), Box<dyn std::error::Error>> {
        let device_list = device::DeviceList::new()?;
        for device in &device_list {
            let ctx = device.open().unwrap();
            assert_eq!(ctx.name(), device.name());
            assert_eq!(ctx.guid(), device.guid());
            assert_eq!(ctx.transport_type(), device.transport_type());
        }
        Ok(())
    }
}
