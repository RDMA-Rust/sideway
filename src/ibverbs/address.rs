use libc::IF_NAMESIZE;
use rdma_mummy_sys::{
    ibv_ah_attr, ibv_gid, ibv_gid_entry, ibv_global_route, IBV_GID_TYPE_IB, IBV_GID_TYPE_ROCE_V1, IBV_GID_TYPE_ROCE_V2,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
            write!(f, "{:02x}", byte)?;
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
#[derive(PartialEq, Eq, Debug)]
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

impl Serialize for GidEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("GidEntry", 5)?;

        // Serialize each field of ibv_gid_entry
        let mut hex = String::with_capacity(32);
        for &b in unsafe { self.0.gid.raw.iter() } {
            use std::fmt::Write;
            write!(&mut hex, "{:02x}", b).unwrap();
        }
        state.serialize_field("gid", &hex)?;

        state.serialize_field("gid_index", &self.0.gid_index)?;
        state.serialize_field("port_num", &self.0.port_num)?;
        state.serialize_field("gid_type", &self.0.gid_type)?;
        state.serialize_field("ndev_ifindex", &self.0.ndev_ifindex)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for GidEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct GidEntryVisitor;

        impl<'de> Visitor<'de> for GidEntryVisitor {
            type Value = GidEntry;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct GidEntry")
            }

            fn visit_map<V>(self, mut map: V) -> Result<GidEntry, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut gid = None;
                let mut gid_index = None;
                let mut port_num = None;
                let mut gid_type = None;
                let mut ndev_ifindex = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "gid" => {
                            let hex: String = map.next_value()?;
                            if hex.len() != 32 {
                                return Err(de::Error::custom(format!(
                                    "invalid gid length: expected 32 hex chars, got {}",
                                    hex.len()
                                )));
                            }

                            let mut raw_gid = [0u8; 16];
                            for i in 0..16 {
                                raw_gid[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                                    .map_err(|e| de::Error::custom(format!("invalid hex: {}", e)))?;
                            }

                            let mut gid_struct: ibv_gid = unsafe { std::mem::zeroed() };
                            gid_struct.raw = raw_gid;
                            gid = Some(gid_struct);
                        },
                        "gid_index" => gid_index = Some(map.next_value()?),
                        "port_num" => port_num = Some(map.next_value()?),
                        "gid_type" => gid_type = Some(map.next_value()?),
                        "ndev_ifindex" => ndev_ifindex = Some(map.next_value()?),
                        _ => return Err(de::Error::unknown_field(key, FIELDS)),
                    }
                }

                let gid = gid.ok_or_else(|| de::Error::missing_field("gid"))?;
                let gid_index = gid_index.ok_or_else(|| de::Error::missing_field("gid_index"))?;
                let port_num = port_num.ok_or_else(|| de::Error::missing_field("port_num"))?;
                let gid_type = gid_type.ok_or_else(|| de::Error::missing_field("gid_type"))?;
                let ndev_ifindex = ndev_ifindex.ok_or_else(|| de::Error::missing_field("ndev_ifindex"))?;

                Ok(GidEntry(ibv_gid_entry {
                    gid,
                    gid_index,
                    port_num,
                    gid_type,
                    ndev_ifindex,
                }))
            }
        }

        const FIELDS: &[&str] = &["gid", "gid_index", "port_num", "gid_type", "ndev_ifindex"];
        deserializer.deserialize_struct("GidEntry", FIELDS, GidEntryVisitor)
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
    use super::*;
    use rdma_mummy_sys::ibv_gid;
    use rstest::rstest;
    use serde_json;
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

    #[test]
    fn test_gid_entry_serialize_deserialize() {
        let mut entry = GidEntry::default();
        entry.0.gid.raw = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x86, 0xff, 0xfe, 0x40, 0x00, 0x01,
        ];
        entry.0.gid_index = 1;
        entry.0.port_num = 2;
        entry.0.gid_type = IBV_GID_TYPE_ROCE_V2;
        entry.0.ndev_ifindex = 3;

        let serialized = serde_json::to_string(&entry).unwrap();

        let deserialized: GidEntry = serde_json::from_str(&serialized).unwrap();

        // Verify raw data matches
        unsafe {
            assert_eq!(entry.0.gid.raw, deserialized.0.gid.raw);
        }
        assert_eq!(entry.0.gid_index, deserialized.0.gid_index);
        assert_eq!(entry.0.port_num, deserialized.0.port_num);
        assert_eq!(entry.0.gid_type, deserialized.0.gid_type);
        assert_eq!(entry.0.ndev_ifindex, deserialized.0.ndev_ifindex);

        // Test getter methods on deserialized object
        assert_eq!(deserialized.gid_index(), 1);
        assert_eq!(deserialized.port_num(), 2);
        assert_eq!(deserialized.gid_type(), GidType::RoceV2);
        assert_eq!(deserialized.netdev_index(), 3);

        // Test GID functionality
        let gid = deserialized.gid();
        assert!(gid.is_unicast_link_local());
        assert!(!gid.is_zero());

        // Test IPv6 conversion
        let ipv6: Ipv6Addr = gid.into();
        assert_eq!(ipv6.segments(), [0xfe80, 0x0, 0x0, 0x0, 0x200, 0x86ff, 0xfe40, 0x1]);

        // Test display formatting
        assert_eq!(format!("{}", gid), "fe80:0000:0000:0000:0200:86ff:fe40:0001");
    }

    #[test]
    fn test_gid_entry_zero_gid() {
        let entry = GidEntry::default();
        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: GidEntry = serde_json::from_str(&serialized).unwrap();
        unsafe {
            assert_eq!(entry.0.gid.raw, deserialized.0.gid.raw);
        }
    }

    #[test]
    fn test_gid_entry_invalid_hex() {
        let invalid_json = r#"{
                "gid": "invalid_hex_string",
                "gid_index": 1,
                "port_num": 1,
                "gid_type": 0,
                "ndev_ifindex": 0
            }"#;

        let result = serde_json::from_str::<GidEntry>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_gid_entry_wrong_length() {
        let invalid_json = r#"{
                "gid": "0123456789",
                "gid_index": 1,
                "port_num": 1,
                "gid_type": 0,
                "ndev_ifindex": 0
            }"#;

        let result = serde_json::from_str::<GidEntry>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_gid_entry_missing_field() {
        let invalid_json = r#"{
                "gid_index": 1,
                "port_num": 1,
                "gid_type": 0,
                "ndev_ifindex": 0
            }"#;

        let result = serde_json::from_str::<GidEntry>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_gid_entry_format() {
        let mut entry = GidEntry::default();
        entry.0.gid.raw = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x86, 0xff, 0xfe, 0x40, 0x00, 0x01,
        ];

        let serialized = serde_json::to_string(&entry).unwrap();
        let json: serde_json::Value = serde_json::from_str(&serialized).unwrap();

        // Verify the GID is properly formatted as hex string
        assert_eq!(json["gid"].as_str().unwrap(), "fe80000000000000020086fffe400001");
    }
}
