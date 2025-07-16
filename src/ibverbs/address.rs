use libc::IF_NAMESIZE;
use rdma_mummy_sys::{
    ibv_ah_attr, ibv_gid, ibv_gid_entry, ibv_global_route, IBV_GID_TYPE_IB, IBV_GID_TYPE_ROCE_V1, IBV_GID_TYPE_ROCE_V2,
};
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::io;
use std::{fmt, mem::MaybeUninit, net::Ipv6Addr};

#[derive(Default, Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Gid {
    pub raw: [u8; 16],
}

impl AsMut<ibv_gid> for Gid {
    fn as_mut(&mut self) -> &mut ibv_gid {
        unsafe { &mut *self.raw.as_mut_ptr().cast::<ibv_gid>() }
    }
}

impl From<ibv_gid> for Gid {
    fn from(gid: ibv_gid) -> Self {
        Self {
            raw: unsafe { gid.raw },
        }
    }
}

impl From<Gid> for ibv_gid {
    fn from(mut gid: Gid) -> Self {
        *gid.as_mut()
    }
}

impl From<Gid> for Ipv6Addr {
    fn from(gid: Gid) -> Self {
        Ipv6Addr::from(gid.raw)
    }
}

impl From<Ipv6Addr> for Gid {
    fn from(addr: Ipv6Addr) -> Self {
        Gid { raw: addr.octets() }
    }
}

impl fmt::Display for Gid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, &byte) in self.raw.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                write!(f, ":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Gid {
    pub fn is_zero(&self) -> bool {
        let (prefix, aligned, suffix) = unsafe { self.raw.align_to::<u128>() };

        prefix.iter().all(|&x| x == 0) && suffix.iter().all(|&x| x == 0) && aligned.iter().all(|&x| x == 0)
    }

    pub fn is_unicast_link_local(&self) -> bool {
        self.raw[0] == 0xfe && self.raw[1] & 0xc0 == 0x80
    }
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub enum GidType {
    InfiniBand = IBV_GID_TYPE_IB,
    RoceV1 = IBV_GID_TYPE_ROCE_V1,
    RoceV2 = IBV_GID_TYPE_ROCE_V2,
}

impl From<u32> for GidType {
    fn from(gid_type: u32) -> Self {
        match gid_type {
            IBV_GID_TYPE_IB => GidType::InfiniBand,
            IBV_GID_TYPE_ROCE_V1 => GidType::RoceV1,
            IBV_GID_TYPE_ROCE_V2 => GidType::RoceV2,
            _ => panic!("Unknown Gid type: {gid_type}"),
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct GidEntry(pub(crate) ibv_gid_entry);

impl Default for GidEntry {
    fn default() -> Self {
        GidEntry(ibv_gid_entry {
            gid: Gid::default().into(),
            gid_index: 0,
            port_num: 1,
            gid_type: 0,
            ndev_ifindex: 0,
        })
    }
}

impl GidEntry {
    #[inline]
    pub fn gid_index(&self) -> u32 {
        self.0.gid_index
    }

    #[inline]
    pub fn port_num(&self) -> u32 {
        self.0.port_num
    }

    #[inline]
    pub fn gid_type(&self) -> GidType {
        self.0.gid_type.into()
    }

    #[inline]
    pub fn netdev_index(&self) -> u32 {
        self.0.ndev_ifindex
    }

    pub fn netdev_name(&self) -> Result<String, String> {
        let mut buf = vec![0u8; IF_NAMESIZE];

        let return_buf = unsafe { libc::if_indextoname(self.netdev_index(), buf.as_mut_ptr().cast()) };

        if return_buf.is_null() {
            return Err(format!("get netdev name failed {:?}", io::Error::last_os_error()));
        }

        Ok(CStr::from_bytes_until_nul(buf.as_slice())
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned())
    }

    #[inline]
    pub fn gid(&self) -> Gid {
        unsafe { Gid { raw: self.0.gid.raw } }
    }
}

pub struct AddressHandleAttribute {
    pub(crate) attr: ibv_ah_attr,
}

impl Default for AddressHandleAttribute {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressHandleAttribute {
    pub fn new() -> Self {
        AddressHandleAttribute {
            attr: unsafe { MaybeUninit::zeroed().assume_init() },
        }
    }

    pub fn setup_dest_lid(&mut self, dest_lid: u16) -> &mut Self {
        self.attr.dlid = dest_lid;
        self
    }

    pub fn setup_service_level(&mut self, sl: u8) -> &mut Self {
        self.attr.sl = sl;
        self
    }

    pub fn setup_port(&mut self, port_num: u8) -> &mut Self {
        self.attr.port_num = port_num;
        self
    }

    // TODO: should we setup the grh at once or set each fields separately?
    pub fn setup_grh(
        &mut self, dest_gid: &Gid, flow_label: u32, src_gid_index: u8, hop_limit: u8, traffic_class: u8,
    ) -> &mut Self {
        self.attr.grh = ibv_global_route {
            dgid: (*dest_gid).into(),
            flow_label,
            sgid_index: src_gid_index,
            hop_limit,
            traffic_class,
        };
        self.attr.is_global = 1;
        self
    }

    pub fn setup_grh_dest_gid(&mut self, dest_gid: &Gid) -> &mut Self {
        self.attr.grh.dgid = (*dest_gid).into();
        self.attr.is_global = 1;
        self
    }

    pub fn setup_grh_src_gid_index(&mut self, src_gid_index: u8) -> &mut Self {
        self.attr.grh.sgid_index = src_gid_index;
        self.attr.is_global = 1;
        self
    }

    pub fn setup_grh_hop_limit(&mut self, hop_limit: u8) -> &mut Self {
        self.attr.grh.hop_limit = hop_limit;
        self.attr.is_global = 1;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::ibverbs::address::Gid;
    use rdma_mummy_sys::ibv_gid;
    use rstest::rstest;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    #[rstest]
    #[case("fe80::", true)]
    #[case("fe80::1", true)]
    #[case("fd80::1", false)]
    #[case("2001:dead:beef:dead:beef:dead:beef:dead", false)]
    fn test_link_local_gid(#[case] ip_str: &str, #[case] expected: bool) {
        let ip = Ipv6Addr::from_str(ip_str).unwrap();

        let gid: Gid = ip.into();

        assert_eq!(expected, gid.is_unicast_link_local())
    }

    #[rstest]
    #[case([0xfe, 0x80, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad], "fe80:dead:beef:dead:beef:dead:beef:dead")]
    #[case([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "fe80:0000:0000:0000:0000:0000:0000:0000")]
    fn test_from_ibv_gid(#[case] octets: [u8; 16], #[case] expected: &str) {
        let gid_ = ibv_gid { raw: octets };
        let gid = Gid::from(gid_);
        assert_eq!(format!("{gid}"), expected);
    }
}
