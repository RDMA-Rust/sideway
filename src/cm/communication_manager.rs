use std::{mem::MaybeUninit, net::SocketAddr, ptr::NonNull};

use os_socketaddr::OsSocketAddr;
use rdma_mummy_sys::{
    rdma_bind_addr, rdma_cm_event, rdma_cm_id, rdma_create_event_channel, rdma_create_id, rdma_destroy_event_channel,
    rdma_destroy_id, rdma_event_channel, rdma_listen, rdma_port_space,
};

use crate::verbs::device_context::DeviceContext;

pub struct Event {
    _event: NonNull<rdma_cm_event>,
}

pub struct EventChannel {
    channel: NonNull<rdma_event_channel>,
}

pub struct CommunicationManager {
    cm_id: NonNull<rdma_cm_id>,
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
            rdma_destroy_event_channel(self.channel.as_mut());
        }
    }
}

impl Drop for CommunicationManager {
    fn drop(&mut self) {
        unsafe {
            rdma_destroy_id(self.cm_id.as_mut());
        }
    }
}

impl EventChannel {
    pub fn new() -> Result<EventChannel, String> {
        let channel = unsafe { rdma_create_event_channel() };

        if channel.is_null() {
            return Err("Failed to create event channel".to_string());
        }

        Ok(EventChannel {
            channel: unsafe { NonNull::new(channel).unwrap_unchecked() },
        })
    }

    pub fn create_id(&mut self, ctx: DeviceContext) -> Result<CommunicationManager, String> {
        let mut cm_id = MaybeUninit::<*mut rdma_cm_id>::uninit();
        let ret;

        unsafe {
            ret = rdma_create_id(
                self.channel.as_mut(),
                cm_id.as_mut_ptr(),
                ctx.context as _,
                PortSpace::Tcp as u32,
            );
        }

        if ret < 0 {
            return Err(format!("Failed to create cm_id {ret}"));
        }

        unsafe {
            cm_id.assume_init();
        }

        Ok(CommunicationManager {
            cm_id: unsafe { NonNull::new(*cm_id.as_mut_ptr()).unwrap_unchecked() },
        })
    }

    pub fn get_cm_event() -> Result<Event, String> {
        todo!();
    }
}

impl CommunicationManager {
    pub fn bind_addr(&mut self, addr: SocketAddr) -> Result<(), String> {
        let ret = unsafe { rdma_bind_addr(self.cm_id.as_mut(), OsSocketAddr::from(addr).as_mut_ptr()) };

        if ret < 0 {
            return Err(format!("Failed to bind addr {addr:?}, returned {ret}"));
        }

        Ok(())
    }

    pub fn listen(&mut self, backlog: i32) -> Result<(), String> {
        let ret = unsafe { rdma_listen(self.cm_id.as_mut(), backlog) };

        if ret < 0 {
            return Err(format!("Failed to listen {ret}"));
        }

        Ok(())
    }
}
