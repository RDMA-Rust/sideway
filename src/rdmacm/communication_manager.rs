use std::any::Any;
use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
use std::ptr::{null, null_mut};
use std::sync::{LazyLock, Mutex, Weak};
use std::time::Duration;
use std::{io, mem::MaybeUninit, net::SocketAddr, ptr::NonNull, sync::Arc};

use os_socketaddr::OsSocketAddr;
use rdma_mummy_sys::{
    ibv_qp_attr, rdma_accept, rdma_ack_cm_event, rdma_bind_addr, rdma_cm_event, rdma_cm_event_type, rdma_cm_id,
    rdma_conn_param, rdma_connect, rdma_create_event_channel, rdma_create_id, rdma_destroy_event_channel,
    rdma_destroy_id, rdma_disconnect, rdma_establish, rdma_event_channel, rdma_get_cm_event, rdma_init_qp_attr,
    rdma_listen, rdma_port_space, rdma_resolve_addr, rdma_resolve_route,
};

use crate::ibverbs::device_context::DeviceContext;
use crate::ibverbs::queue_pair::{QueuePairAttribute, QueuePairState};

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

static DEVICE_LISTS: LazyLock<Mutex<HashMap<usize, Arc<DeviceContext>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct Event {
    event: NonNull<rdma_cm_event>,
    cm_id: Option<Arc<Identifier>>,
    listener_id: Option<Arc<Identifier>>,
}

pub struct EventChannel {
    channel: NonNull<rdma_event_channel>,
}

// enum QueuePairStatus {
//     SelfCreatedBound,
//     SelfCreatedDestroyed,
//     CommunicationManagerCreated,
//     CommunicationManagerDestroyed,
//     NoQueuePairBound,
// }

pub struct Identifier {
    cm_id: NonNull<rdma_cm_id>,
    // queue_pair_status: QueuePairStatus,
    user_context: Mutex<Option<Arc<dyn Any + Send + Sync>>>,
}

pub struct ConnectionParameter(rdma_conn_param);

pub enum PortSpace {
    /// Provides for any InfiniBand services (UD, UC, RC, XRC, etc.).
    InfiniBand = rdma_port_space::RDMA_PS_IB as isize,
    IpOverInfiniBand = rdma_port_space::RDMA_PS_IPOIB as isize,
    /// Provides reliable, connection-oriented QP communication. Unlike TCP, the RDMA port space
    /// provides message, not stream, based communication. In other words, this would create a
    /// [`QueuePair`] for [`ReliableConnection`].
    ///
    /// [`QueuePair`]: crate::ibverbs::queue_pair::QueuePair
    /// [`ReliableConnection`]: crate::ibverbs::queue_pair::QueuePairType::ReliableConnection
    ///
    Tcp = rdma_port_space::RDMA_PS_TCP as isize,
    /// Provides unreliable, connectionless QP communication. Supports both datagram and multicast
    /// communication. In other words, this would create a [`QueuePair`] for [`UnreliableDatagram`].
    ///
    /// [`QueuePair`]: crate::ibverbs::queue_pair::QueuePair
    /// [`UnreliableDatagram`]: crate::ibverbs::queue_pair::QueuePairType::UnreliableDatagram
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
    /// Get the [`Identifier`] associated with this [`Event`].
    ///
    /// # Special cases
    ///
    /// - For [`EventType::ConnectRequest`]:
    ///   A new [`Identifier`] is automatically created to handle
    ///   the incoming connection request. This is distinct from the listener
    ///   [`Identifier`].
    ///
    /// - For other event types:
    ///   Returns the existing [`Identifier`] associated with the event.
    ///
    /// # Note
    ///
    /// To access the listener [`Identifier`] in case of a connect request,
    /// use the [`listener_id`] method instead.
    ///
    /// [`listener_id`]: crate::rdmacm::communication_manager::Event::listener_id
    ///
    pub fn cm_id(&self) -> Option<Arc<Identifier>> {
        self.cm_id.clone()
    }

    /// Get the listener [`Identifier`] associated with this [`Event`].
    ///
    /// # Note
    ///
    /// This method is primarily useful for [`EventType::ConnectRequest`] events,
    /// allowing access to the listener that received the connection request, for
    /// other events, this method would return [`None`].
    pub fn listener_id(&self) -> Option<Arc<Identifier>> {
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
    /// [`get_cm_event`]: crate::rdmacm::communication_manager::EventChannel::get_cm_event
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

fn new_cm_id_for_raw(raw: *mut rdma_cm_id) -> Result<Arc<Identifier>, String> {
    let cm = Arc::new(Identifier {
        cm_id: NonNull::new(raw).unwrap(),
        user_context: Mutex::new(None),
    });

    let weak_cm = Arc::downgrade(&cm.clone());
    let boxed = Box::new(weak_cm);
    let raw_box = Box::into_raw(boxed);

    unsafe {
        (*raw).context = raw_box as *mut std::ffi::c_void;
    }

    Ok(cm)
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

    pub fn create_id(&mut self, port_space: PortSpace) -> Result<Arc<Identifier>, String> {
        let mut cm_id_ptr: *mut rdma_cm_id = null_mut();
        let ret = unsafe { rdma_create_id(self.channel.as_mut(), &mut cm_id_ptr, null_mut(), port_space as u32) };

        if ret < 0 {
            return Err(format!("Failed to create cm_id {ret}"));
        }

        new_cm_id_for_raw(cm_id_ptr)
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

            assert_ne!(raw_cm_id, null_mut());
            if event.as_ref().event == EventType::ConnectRequest as u32 {
                // For connect requests, create a new CommunicationManager
                Some(new_cm_id_for_raw(raw_cm_id).unwrap())
            } else {
                // For other events, return the existing CommunicationManager
                let context_ptr = (*raw_cm_id).context as *mut Weak<Identifier>;
                assert_ne!(context_ptr, null_mut());
                (*context_ptr).clone().upgrade()
            }
        };

        let listener_id = unsafe {
            let raw_listen_id = event.as_ref().listen_id;

            if !raw_listen_id.is_null() {
                let context_ptr = (*raw_listen_id).context as *mut Weak<Identifier>;
                assert_ne!(context_ptr, null_mut());
                (*context_ptr).clone().upgrade()
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

impl AsRawFd for EventChannel {
    fn as_raw_fd(&self) -> RawFd {
        unsafe {
            self.channel.as_ref().fd
        }
    }
}

unsafe impl Send for EventChannel {}
unsafe impl Sync for EventChannel {}

impl Drop for Identifier {
    fn drop(&mut self) {
        let cm_id = self.cm_id;
        unsafe {
            let ctx = cm_id.as_ref().context as *mut Weak<Identifier>;
            rdma_destroy_id(cm_id.as_ptr());
            let _ = Box::from_raw(ctx);
        }
    }
}

// Mark CommunicationManager as Sync & Send, implying that we guarantee its thread-safety
unsafe impl Sync for Identifier {}
unsafe impl Send for Identifier {}

impl Identifier {
    pub fn setup_context<C: Any + Send + Sync>(&self, ctx: C) {
        let mut user_data = self.user_context.lock().unwrap();
        *user_data = Some(Arc::new(ctx));
    }

    pub fn get_context<C: Any + Send + Sync>(&self) -> Option<Arc<C>> {
        let user_data = self.user_context.lock().unwrap();
        let arc_any = user_data.as_ref()?.clone();
        arc_any.downcast::<C>().ok()
    }

    pub fn port(&self) -> u8 {
        let cm_id = self.cm_id;

        unsafe { cm_id.as_ref().port_num }
    }

    pub fn bind_addr(&self, addr: SocketAddr) -> Result<(), String> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_bind_addr(cm_id.as_ptr(), OsSocketAddr::from(addr).as_mut_ptr()) };

        if ret < 0 {
            return Err(format!("Failed to bind addr {addr:?}, {}", io::Error::last_os_error()));
        }

        Ok(())
    }

    pub fn resolve_addr(
        &self, src_addr: Option<SocketAddr>, dst_addr: SocketAddr, timeout: Duration,
    ) -> Result<(), String> {
        let cm_id = self.cm_id;
        let timeout_ms: i32 = timeout.as_millis().try_into().unwrap();

        let ret = unsafe {
            rdma_resolve_addr(
                cm_id.as_ptr(),
                match src_addr {
                    Some(addr) => OsSocketAddr::from(addr).as_mut_ptr(),
                    None => null_mut(),
                },
                OsSocketAddr::from(dst_addr).as_mut_ptr(),
                timeout_ms,
            )
        };

        if ret < 0 {
            return Err(format!("Failed to resolve address {ret}"));
        }

        Ok(())
    }

    pub fn resolve_route(&self, timeout: Duration) -> Result<(), String> {
        let cm_id = self.cm_id;
        let timeout_ms: i32 = timeout.as_millis().try_into().unwrap();

        let ret = unsafe { rdma_resolve_route(cm_id.as_ptr(), timeout_ms) };

        if ret < 0 {
            return Err(format!("Failed to resolve route {ret}"));
        }

        Ok(())
    }

    pub fn listen(&self, backlog: i32) -> Result<(), String> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_listen(cm_id.as_ptr(), backlog) };

        if ret < 0 {
            return Err(format!("Failed to listen {ret}"));
        }

        Ok(())
    }

    pub fn get_device_context(&self) -> Option<Arc<DeviceContext>> {
        let cm_id = self.cm_id;

        unsafe {
            if (*cm_id.as_ptr()).verbs.is_null() {
                return None;
            }

            let mut guard = DEVICE_LISTS.lock().unwrap();
            let device_ctx = guard
                .entry((*cm_id.as_ptr()).verbs as usize)
                .or_insert(Arc::new(DeviceContext {
                    context: (*cm_id.as_ptr()).verbs,
                }));

            Some(device_ctx.clone())
        }
    }

    pub fn connect(&self, mut conn_param: ConnectionParameter) -> Result<(), String> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_connect(cm_id.as_ptr(), &mut conn_param.0) };

        if ret < 0 {
            return Err(format!("Failed to connect {:?}", io::Error::last_os_error()));
        }

        Ok(())
    }

    pub fn disconnect(&self) -> Result<(), String> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_disconnect(cm_id.as_ptr()) };

        if ret < 0 {
            return Err(format!("Failed to disconnect {:?}", io::Error::last_os_error()));
        }

        Ok(())
    }

    pub fn accept(&self, mut conn_param: ConnectionParameter) -> Result<(), String> {
        let cm_id = self.cm_id;

        let ret = unsafe { rdma_accept(cm_id.as_ptr(), &mut conn_param.0) };

        if ret < 0 {
            return Err(format!("Failed to accept {:?}", io::Error::last_os_error()));
        }

        Ok(())
    }

    pub fn establish(&self) -> Result<(), String> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_establish(cm_id.as_ptr()) };

        if ret < 0 {
            return Err(format!("Failed to establish {:?}", io::Error::last_os_error()));
        }

        Ok(())
    }

    pub fn get_qp_attr(&self, state: QueuePairState) -> Result<QueuePairAttribute, String> {
        let cm_id = self.cm_id;
        let mut attr = MaybeUninit::<ibv_qp_attr>::uninit();
        let mut mask = 0;

        unsafe { (*attr.as_mut_ptr()).qp_state = state as _ };

        let ret = unsafe { rdma_init_qp_attr(cm_id.as_ptr(), attr.as_mut_ptr(), &mut mask) };

        if ret < 0 {
            return Err(format!("Failed to get qp attr {:?}", io::Error::last_os_error()));
        }

        Ok(QueuePairAttribute::from(unsafe { attr.assume_init_ref() }, mask))
    }
}

impl Default for ConnectionParameter {
    fn default() -> Self {
        Self(rdma_conn_param {
            private_data: null(),
            private_data_len: 0,
            responder_resources: 1,
            initiator_depth: 1,
            flow_control: 0,
            retry_count: 7,
            rnr_retry_count: 7,
            srq: 0,
            qp_num: 0,
        })
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
                    SocketAddr::from((IpAddr::from_str("127.0.0.1").expect("Invalid IP address"), 0)),
                    Duration::new(0, 200000000),
                );

                assert_eq!(Arc::strong_count(&id), 1);

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

    #[test]
    fn test_bind_on_the_same_port() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(mut channel) => {
                let id = channel.create_id(PortSpace::Tcp).unwrap();

                let res = id.bind_addr(SocketAddr::from((
                    IpAddr::from_str("0.0.0.0").expect("Invalid IP address"),
                    8080,
                )));

                assert!(res.is_ok());

                let new_id = channel.create_id(PortSpace::Tcp).unwrap();

                let err = new_id.bind_addr(SocketAddr::from((
                    IpAddr::from_str("0.0.0.0").expect("Invalid IP address"),
                    8080,
                )));

                assert_eq!(
                    err.err().unwrap(),
                    "Failed to bind addr 0.0.0.0:8080, Cannot assign requested address (os error 99)"
                );
                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn test_conn_param() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(mut channel) => {
                let _id = channel.create_id(PortSpace::Tcp).unwrap();

                let _param = ConnectionParameter::new();

                Ok(())
            },
            Err(_) => Ok(()),
        }
    }
}
