use std::{mem::MaybeUninit, net::SocketAddr};

use os_socketaddr::OsSocketAddr;
use rdma_mummy_sys::{
    rdma_bind_addr, rdma_cm_event, rdma_cm_id, rdma_create_event_channel, rdma_create_id, rdma_destroy_event_channel,
    rdma_destroy_id, rdma_event_channel, rdma_listen, rdma_port_space,
};

use crate::verbs::rdma_context::RdmaContext;

pub struct Event {
    _event_ptr: *mut rdma_cm_event,
}

pub struct EventChannel {
    channel_ptr: *mut rdma_event_channel,
}

pub struct ConnectionManager {
    cm_ptr: *mut rdma_cm_id,
}

pub enum PortSpace {
    Ib = rdma_port_space::RDMA_PS_IB as isize,
    Ipoib = rdma_port_space::RDMA_PS_IPOIB as isize,
    Tcp = rdma_port_space::RDMA_PS_TCP as isize,
    Udp = rdma_port_space::RDMA_PS_UDP as isize,
}

impl Drop for EventChannel {
    fn drop(&mut self) {
        unsafe {
            rdma_destroy_event_channel(self.channel_ptr);
        }
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        unsafe {
            rdma_destroy_id(self.cm_ptr);
        }
    }
}

impl EventChannel {
    pub fn new() -> Result<EventChannel, String> {
        let channel_ptr = unsafe { rdma_create_event_channel() };

        if channel_ptr.is_null() {
            return Err(format!("Failed to create event channel"));
        }

        Ok(EventChannel { channel_ptr })
    }

    pub fn create_id(&self, ctx: RdmaContext) -> Result<ConnectionManager, String> {
        let mut cm_ptr = MaybeUninit::<*mut rdma_cm_id>::uninit();
        let ret;

        unsafe {
            ret = rdma_create_id(
                self.channel_ptr,
                cm_ptr.as_mut_ptr(),
                ctx.context as _,
                PortSpace::Tcp as u32,
            );
        }

        if ret < 0 {
            return Err(format!("Failed to create cm_id {ret}"));
        }

        unsafe {
            cm_ptr.assume_init();
        }

        Ok(ConnectionManager {
            cm_ptr: unsafe { *cm_ptr.as_mut_ptr() },
        })
    }

    pub fn get_cm_event() -> Result<Event, String> {
        todo!();
    }
}

impl ConnectionManager {
    pub fn bind_addr(&self, addr: SocketAddr) -> Result<(), String> {
        let ret = unsafe { rdma_bind_addr(self.cm_ptr, OsSocketAddr::from(addr).as_mut_ptr()) };

        if ret < 0 {
            return Err(format!("Failed to bind addr {addr:?}, returned {ret}"));
        }

        Ok(())
    }

    pub fn listen(&self, backlog: i32) -> Result<(), String> {
        let ret = unsafe { rdma_listen(self.cm_ptr, backlog) };

        if ret < 0 {
            return Err(format!("Failed to listen {ret}"));
        }

        Ok(())
    }
}
