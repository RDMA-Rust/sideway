use rdma_mummy_sys::ibv_gid;
use std::{
    fmt,
    net::Ipv6Addr,
};

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
