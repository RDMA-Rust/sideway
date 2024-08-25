use rdma_mummy_sys::{ibv_ah_attr, ibv_gid, ibv_global_route};
use std::{fmt, mem::MaybeUninit, net::Ipv6Addr};

#[derive(Default, Clone, Copy, Debug)]
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
}

pub struct AddressHandleAttribute {
    pub(crate) attr: ibv_ah_attr,
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
            dgid: dest_gid.clone().into(),
            flow_label,
            sgid_index: src_gid_index,
            hop_limit,
            traffic_class
        };
        self.attr.is_global = 1;
        self
    }
}
