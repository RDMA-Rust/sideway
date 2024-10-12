use std::mem::ManuallyDrop;
use std::ptr::{null, null_mut};
use std::sync::Weak;
use std::{cell::UnsafeCell, io, mem::MaybeUninit, net::SocketAddr, ptr::NonNull, sync::Arc};

use os_socketaddr::OsSocketAddr;
use rdma_mummy_sys::{
    ibv_qp_attr, rdma_accept, rdma_ack_cm_event, rdma_bind_addr, rdma_cm_event, rdma_cm_event_type, rdma_cm_id,
    rdma_conn_param, rdma_connect, rdma_create_event_channel, rdma_create_id, rdma_destroy_event_channel,
    rdma_destroy_id, rdma_establish, rdma_event_channel, rdma_get_cm_event, rdma_init_qp_attr, rdma_listen,
    rdma_port_space, rdma_resolve_addr, rdma_resolve_route,
};

use crate::verbs::device_context::DeviceContext;
use crate::verbs::queue_pair::QueuePairAttribute;

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventType {
    AddressResolved = rdma_cm_event_type::RDMA_CM_EVENT_ADDR_RESOLVED,
    AddressError = rdma_cm_event_type::RDMA_CM_EVENT_ADDR_ERROR,
    RouteResolved = rdma_cm_event_type::RDMA_CM_EVENT_ROUTE_RESOLVED,
    RouteError = rdma_cm_event_type::RDMA_CM_EVENT_ROUTE_ERROR,
    ConnectRequest = rdma_cm_event_type::RDMA_CM_EVENT_CONNECT_REQUEST,
    ConnectResponse = rdma_cm_event_type::RDMA_CM_EVENT_CONNECT_RESPONSE,
    ConnectError = rdma_cm_event_type::RDMA_CM_EVENT_CONNECT_ERROR,
    Unreachable = rdma_cm_event_type::RDMA_CM_EVENT_UNREACHABLE,
    Rejected = rdma_cm_event_type::RDMA_CM_EVENT_REJECTED,
    Established = rdma_cm_event_type::RDMA_CM_EVENT_ESTABLISHED,
    Disconnected = rdma_cm_event_type::RDMA_CM_EVENT_DISCONNECTED,
    DeviceRemoval = rdma_cm_event_type::RDMA_CM_EVENT_DEVICE_REMOVAL,
    MulticastJoin = rdma_cm_event_type::RDMA_CM_EVENT_MULTICAST_JOIN,
    MulticastError = rdma_cm_event_type::RDMA_CM_EVENT_MULTICAST_ERROR,
    AddressChange = rdma_cm_event_type::RDMA_CM_EVENT_ADDR_CHANGE,
    TimewaitExit = rdma_cm_event_type::RDMA_CM_EVENT_TIMEWAIT_EXIT,
}

impl From<u32> for EventType {
    fn from(event: u32) -> Self {
        match event {
            rdma_cm_event_type::RDMA_CM_EVENT_ADDR_RESOLVED => EventType::AddressResolved,
            rdma_cm_event_type::RDMA_CM_EVENT_ADDR_ERROR => EventType::AddressError,
            rdma_cm_event_type::RDMA_CM_EVENT_ROUTE_RESOLVED => EventType::RouteResolved,
            rdma_cm_event_type::RDMA_CM_EVENT_ROUTE_ERROR => EventType::RouteError,
            rdma_cm_event_type::RDMA_CM_EVENT_CONNECT_REQUEST => EventType::ConnectRequest,
            rdma_cm_event_type::RDMA_CM_EVENT_CONNECT_RESPONSE => EventType::ConnectResponse,
            rdma_cm_event_type::RDMA_CM_EVENT_CONNECT_ERROR => EventType::ConnectError,
            rdma_cm_event_type::RDMA_CM_EVENT_UNREACHABLE => EventType::Unreachable,
            rdma_cm_event_type::RDMA_CM_EVENT_REJECTED => EventType::Rejected,
            rdma_cm_event_type::RDMA_CM_EVENT_ESTABLISHED => EventType::Established,
            rdma_cm_event_type::RDMA_CM_EVENT_DISCONNECTED => EventType::Disconnected,
            rdma_cm_event_type::RDMA_CM_EVENT_DEVICE_REMOVAL => EventType::DeviceRemoval,
            rdma_cm_event_type::RDMA_CM_EVENT_MULTICAST_JOIN => EventType::MulticastJoin,
            rdma_cm_event_type::RDMA_CM_EVENT_MULTICAST_ERROR => EventType::MulticastError,
            rdma_cm_event_type::RDMA_CM_EVENT_ADDR_CHANGE => EventType::AddressChange,
            rdma_cm_event_type::RDMA_CM_EVENT_TIMEWAIT_EXIT => EventType::TimewaitExit,
            _ => panic!("Unknown RDMA CM event type: {event}"),
        }
    }
}

pub struct Event {
    event: NonNull<rdma_cm_event>,
    cm_id: Option<Arc<CommunicationManager>>,
    listener_id: Option<Arc<CommunicationManager>>,
}

pub struct EventChannel {
    channel: NonNull<rdma_event_channel>,
}

pub struct CommunicationManager {
    cm_id: UnsafeCell<NonNull<rdma_cm_id>>,
}

pub struct ConnectionParameter(rdma_conn_param);

pub enum PortSpace {
    /// Provides for any InfiniBand services (UD, UC, RC, XRC, etc.).
    InfiniBand = rdma_port_space::RDMA_PS_IB as isize,
    IpOverInfiniband = rdma_port_space::RDMA_PS_IPOIB as isize,
    /// Provides reliable, connection-oriented QP communication. Unlike TCP, the RDMA port space
    /// provides message, not stream, based communication. In other words, this would create a
    /// [`QueuePair`] for [`ReliableConnection`].
    ///
    /// [`QueuePair`]: crate::verbs::queue_pair::QueuePair
    /// [`ReliableConnection`]: crate::verbs::queue_pair::QueuePairType::ReliableConnection
    ///
    Tcp = rdma_port_space::RDMA_PS_TCP as isize,
    /// Provides unreliable, connectionless QP communication. Supports both datagram and multicast
    /// communication. In other words, this would create a [`QueuePair`] for [`UnreliableDatagram`].
    ///
    /// [`QueuePair`]: crate::verbs::queue_pair::QueuePair
    /// [`UnreliableDatagram`]: crate::verbs::queue_pair::QueuePairType::UnreliableDatagram
    ///
    Udp = rdma_port_space::RDMA_PS_UDP as isize,
}

impl Drop for EventChannel {
    fn drop(&mut self) {
        unsafe {
            rdma_destroy_event_channel(self.channel.as_mut());
        }
    }
}

impl Event {
    /// Get the [`CommunicationManager`] associated with this [`Event`].
    ///
    /// # Special cases
    ///
    /// - For [`EventType::ConnectRequest`]:
    ///   A new [`CommunicationManager`] is automatically created to handle
    ///   the incoming connection request. This is distinct from the listener
    ///   [`CommunicationManager`].
    ///
    /// - For other event types:
    ///   Returns the existing [`CommunicationManager`] associated with the event.
    ///
    /// # Note
    ///
    /// To access the listener [`CommunicationManager`] in case of a connect request,
    /// use the [`listener_id`] method instead.
    ///
    /// [`listener_id`]: crate::cm::communication_manager::Event::listener_id
    ///
    pub fn cm_id(&self) -> Option<Arc<CommunicationManager>> {
        self.cm_id.clone()
    }

    /// Get the listener [`CommunicationManager`] associated with this [`Event`].
    ///
    /// # Note
    ///
    /// This method is primarily useful for [`EventType::ConnectRequest`] events,
    /// allowing access to the listener that received the connection request, for
    /// other events, this method would return [`None`].
    pub fn listener_id(&self) -> Option<Arc<CommunicationManager>> {
        self.listener_id.clone()
    }

    /// Get the event type of this event.
    pub fn event_type(&self) -> EventType {
        unsafe { self.event.as_ref().event.into() }
    }

    /// Get the event status of this event, this would be useful when you get an error
    /// event, for example, [`EventType::Rejected`].
    pub fn status(&self) -> i32 {
        unsafe { self.event.as_ref().status }
    }

    /// Acknowledge and free the communication event.
    ///
    /// # Note
    ///
    /// This method should be called to release events allocated by [`get_cm_event`].
    /// There should be a one-to-one correspondence between successful gets and acks.
    /// This call frees the event structure and any memory that it references.
    ///
    /// [`get_cm_event`]: crate::cm::communication_manager::EventChannel::get_cm_event
    ///
    pub fn ack(mut self) -> Result<(), String> {
        let ret = unsafe { rdma_ack_cm_event(self.event.as_mut()) };

        if ret < 0 {
            return Err(format!("Failed to ack cm event {:?}", io::Error::last_os_error()));
        }

        self.cm_id.take();
        self.listener_id.take();

        // The event has been freed by rdma_ack_cm_event, so we don't need to drop it.
        std::mem::forget(self);

        Ok(())
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        unsafe {
            rdma_ack_cm_event(self.event.as_mut());
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

    pub fn create_id(&mut self, port_space: PortSpace) -> Result<Arc<CommunicationManager>, String> {
        let cm = Arc::new(CommunicationManager {
            cm_id: UnsafeCell::new(NonNull::dangling()), // We'll update this shortly
        });

        let mut cm_id_ptr = MaybeUninit::<*mut rdma_cm_id>::uninit();
        let ret = unsafe {
            rdma_create_id(
                self.channel.as_mut(),
                cm_id_ptr.as_mut_ptr(),
                Arc::downgrade(&cm).into_raw() as *mut std::ffi::c_void,
                port_space as u32,
            )
        };

        if ret < 0 {
            return Err(format!("Failed to create cm_id {ret}"));
        }

        let cm_id = unsafe { NonNull::new(cm_id_ptr.assume_init()).unwrap() };

        // Update the cm_id in the CommunicationManager
        unsafe {
            *cm.cm_id.get() = cm_id;
        }

        Ok(cm)
    }

    pub fn get_cm_event(&mut self) -> Result<Event, String> {
        let mut event_ptr = MaybeUninit::<*mut rdma_cm_event>::uninit();

        let ret = unsafe { rdma_get_cm_event(self.channel.as_ptr(), event_ptr.as_mut_ptr()) };

        if ret < 0 {
            return Err(format!("Failed to get cm event {:?}", io::Error::last_os_error()));
        }

        let event = unsafe { NonNull::new(event_ptr.assume_init()).unwrap() };

        let cm_id = unsafe {
            let raw_cm_id = event.as_ref().id;

            if !raw_cm_id.is_null() {
                if event.as_ref().event == EventType::ConnectRequest as u32 {
                    // For connect requests, create a new CommunicationManager
                    let cm = Arc::new(CommunicationManager {
                        cm_id: UnsafeCell::new(NonNull::new(raw_cm_id).unwrap()),
                    });

                    (*raw_cm_id).context = Arc::downgrade(&cm).into_raw() as *mut std::ffi::c_void;

                    Some(cm)
                } else {
                    // For other events, return the existing CommunicationManager
                    let context_ptr = (*raw_cm_id).context as *mut CommunicationManager;
                    if !context_ptr.is_null() {
                        Some(Weak::from_raw(context_ptr).upgrade().unwrap())
                    } else {
                        None
                    }
                }
            } else {
                None
            }
        };

        let listener_id = unsafe {
            let raw_listen_id = event.as_ref().listen_id;

            if !raw_listen_id.is_null() {
                let context_ptr = (*raw_listen_id).context;
                if !context_ptr.is_null() {
                    Some((*(context_ptr as *const Arc<CommunicationManager>)).clone())
                } else {
                    None
                }
            } else {
                None
            }
        };

        Ok(Event {
            event,
            cm_id,
            listener_id,
        })
    }
}

impl Drop for CommunicationManager {
    fn drop(&mut self) {
        let cm_id = unsafe { *self.cm_id.get() };
        unsafe {
            // The context is always an Arc<CommunicationManager>
            let _ = Arc::from_raw((*cm_id.as_ptr()).context as *mut Arc<CommunicationManager>);
            // Clear the context and destroy the ID
            (*cm_id.as_ptr()).context = std::ptr::null_mut();
            rdma_destroy_id(cm_id.as_ptr());
        }
    }
}

// Mark CommunicationManager as Sync & Send, implying that we guarantee its thread-safety
unsafe impl Sync for CommunicationManager {}
unsafe impl Send for CommunicationManager {}

impl CommunicationManager {
    pub fn bind_addr(&self, addr: SocketAddr) -> Result<(), String> {
        let cm_id = unsafe { &mut *self.cm_id.get() };
        let ret = unsafe { rdma_bind_addr(cm_id.as_mut(), OsSocketAddr::from(addr).as_mut_ptr()) };

        if ret < 0 {
            return Err(format!("Failed to bind addr {addr:?}, returned {ret}"));
        }

        Ok(())
    }

    pub fn resolve_addr(
        &self, src_addr: Option<SocketAddr>, dst_addr: Option<SocketAddr>, timeout_ms: i32,
    ) -> Result<(), String> {
        let cm_id = unsafe { &mut *self.cm_id.get() };

        let ret = unsafe {
            rdma_resolve_addr(
                cm_id.as_mut(),
                match src_addr {
                    Some(addr) => OsSocketAddr::from(addr).as_mut_ptr(),
                    None => null_mut(),
                },
                match dst_addr {
                    Some(addr) => OsSocketAddr::from(addr).as_mut_ptr(),
                    None => null_mut(),
                },
                timeout_ms,
            )
        };

        if ret < 0 {
            return Err(format!("Failed to resolve address {ret}"));
        }

        Ok(())
    }

    pub fn resolve_route(&self, timeout_ms: i32) -> Result<(), String> {
        let cm_id = unsafe { &mut *self.cm_id.get() };
        let ret = unsafe { rdma_resolve_route(cm_id.as_mut(), timeout_ms) };

        if ret < 0 {
            return Err(format!("Failed to resolve address {ret}"));
        }

        Ok(())
    }

    pub fn listen(&self, backlog: i32) -> Result<(), String> {
        let cm_id = unsafe { &mut *self.cm_id.get() };
        let ret = unsafe { rdma_listen(cm_id.as_mut(), backlog) };

        if ret < 0 {
            return Err(format!("Failed to listen {ret}"));
        }

        Ok(())
    }

    pub fn get_device_context(&self) -> Result<ManuallyDrop<DeviceContext>, String> {
        let cm_id = unsafe { *self.cm_id.get() };

        unsafe {
            Ok(ManuallyDrop::new(DeviceContext {
                context: (*cm_id.as_ptr()).verbs,
            }))
        }
    }

    pub fn connect(&self, conn_param: &mut ConnectionParameter) -> Result<(), String> {
        let cm_id = unsafe { &mut *self.cm_id.get() };
        let ret = unsafe { rdma_connect(cm_id.as_mut(), &mut conn_param.0) };

        if ret < 0 {
            return Err(format!("Failed to connect {ret}"));
        }

        Ok(())
    }

    pub fn accept(&self, conn_param: &mut ConnectionParameter) -> Result<(), String> {
        let cm_id = unsafe { &mut *self.cm_id.get() };
        let ret = unsafe { rdma_accept(cm_id.as_mut(), &mut conn_param.0) };

        if ret < 0 {
            return Err(format!("Failed to accept {ret}"));
        }

        Ok(())
    }

    pub fn establish(&self) -> Result<(), String> {
        let cm_id = unsafe { &mut *self.cm_id.get() };
        let ret = unsafe { rdma_establish(cm_id.as_mut()) };

        if ret < 0 {
            return Err(format!("Failed to establish {ret}"));
        }

        Ok(())
    }

    pub fn get_qp_attr(&self) -> Result<QueuePairAttribute, String> {
        let cm_id = unsafe { &mut *self.cm_id.get() };
        let mut attr = MaybeUninit::<ibv_qp_attr>::uninit();
        let mut mask = 0;

        let ret = unsafe { rdma_init_qp_attr(cm_id.as_mut(), attr.as_mut_ptr(), &mut mask) };

        if ret < 0 {
            return Err(format!("Failed to get qp attr {:?}", io::Error::last_os_error()));
        }

        Ok(QueuePairAttribute::from(unsafe { attr.assume_init_ref() }, mask))
    }
}

impl Default for ConnectionParameter {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionParameter {
    pub fn new() -> Self {
        Self(rdma_conn_param {
            private_data: null(),
            private_data_len: 0,
            responder_resources: 0,
            initiator_depth: 0,
            flow_control: 0,
            retry_count: 0,
            rnr_retry_count: 0,
            srq: 0,
            qp_num: 0,
        })
    }

    pub fn setup_qp_number(&mut self, qp_number: u32) -> &mut Self {
        self.0.qp_num = qp_number;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;

    #[test]
    fn test_cm_id_reference_count() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(mut channel) => {
                let id = channel.create_id(PortSpace::Tcp).unwrap();

                assert_eq!(Arc::strong_count(&id), 1);

                let _ = id.resolve_addr(
                    None,
                    Some(SocketAddr::from((
                        IpAddr::from_str("127.0.0.1").expect("Invalid IP address"),
                        0,
                    ))),
                    200,
                );

                let event = channel.get_cm_event().unwrap();

                assert_eq!(Arc::strong_count(&id), 2);

                let cm_id = event.cm_id().unwrap();

                assert_eq!(Arc::strong_count(&id), 3);
                assert_eq!(Arc::strong_count(&cm_id), 3);

                event.ack().unwrap();

                assert_eq!(Arc::strong_count(&id), 2);
                assert_eq!(Arc::strong_count(&cm_id), 2);

                Ok(())
            },
            Err(_) => Ok(()),
        }
    }
}
