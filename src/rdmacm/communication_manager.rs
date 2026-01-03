#![allow(clippy::needless_doctest_main)]
//!
//! The RDMA CM is a communication manager used to setup reliable, connected and unreliable datagram
//! transfers. It provides an RDMA transport neutral interface for establishing and tearing down
//! connections. Instead of operating on socket, users would create an [`EventChannel`] and
//! [`Identifier`]s to setup the connection.
//!
//! # Note
//!
//! - Compared to out-of-band connection setup, for example, using TCP / UDP to exchange the QP
//!   information, the RDMA CM doesn't require user to design the wire format, and provide a more
//!   unified interface. RDMA CM would also detect program termination and tear down the connection
//!   automatically. Besides, RDMA CM would use the same UDP source port just as the data path does,
//!   so that the user would detect the path failure in connection setup phase.
//! - The original `librdmacm` library provides `rdma_create_ep` and `rdma_create_qp` helpers to
//!   wrap more `libibverbs` functions, but it limits the user to control the detailed attributes
//!   of the QP (and the implementation has some [`race condition`]). So we decide not to wrap them,
//!   and let user to control the QP manually.
//!
//! # Examples
//!
//! - Server side:
//! ```no_run
//! use sideway::ibverbs::completion::GenericCompletionQueue;
//! use sideway::ibverbs::queue_pair::{QueuePair, QueuePairState};
//! use sideway::rdmacm::communication_manager::{ConnectionParameter, EventChannel, EventType, PortSpace};
//! use std::net::SocketAddr;
//! use std::str::FromStr;
//!
//! fn main() {
//!     let mut event_channel = EventChannel::new().unwrap();
//!     let id = event_channel.create_id(PortSpace::Tcp).unwrap();
//!
//!     // For RDMA CM, bind to a loopback address would lead to problems, so just bind to `0.0.0.0`
//!     // or `::` to get connection from any address. You could also bind to a specific address.
//!     id.bind_addr(SocketAddr::from_str("0.0.0.0:18515").unwrap()).unwrap();
//!
//!     id.listen(10).unwrap();
//!
//!     while let Ok(event) = event_channel.get_cm_event() {
//!         match event.event_type() {
//!             EventType::ConnectRequest => {
//!                 let new_id = event.cm_id().unwrap();
//!                 let ctx = new_id.get_device_context().unwrap();
//!                 let pd = ctx.alloc_pd().unwrap();
//!                 let cq = GenericCompletionQueue::from(ctx.create_cq_builder().setup_cqe(1).build_ex().unwrap());
//!
//!                 let mut qp_builder = pd.create_qp_builder();
//!                 qp_builder
//!                     .setup_max_send_wr(1)
//!                     .setup_max_send_sge(1)
//!                     .setup_max_recv_wr(1)
//!                     .setup_max_recv_sge(1)
//!                     .setup_send_cq(cq.clone())
//!                     .setup_recv_cq(cq.clone());
//!                 let mut qp = qp_builder.build_ex().unwrap();
//!
//!                 // You could change the attr after getting it, but for now we use the default one
//!                 let attr = new_id.get_qp_attr(QueuePairState::Init).unwrap();
//!                 qp.modify(&attr).unwrap();
//!
//!                 let attr = new_id.get_qp_attr(QueuePairState::ReadyToReceive).unwrap();
//!                 qp.modify(&attr).unwrap();
//!
//!                 let attr = new_id.get_qp_attr(QueuePairState::ReadyToSend).unwrap();
//!                 qp.modify(&attr).unwrap();
//!
//!                 let mut param = ConnectionParameter::new();
//!                 param.setup_qp_number(qp.qp_number());
//!                 new_id.accept(param).unwrap();
//!             },
//!             _ => todo!(),
//!         }
//!     }
//! }
//! ```
//!
//! - Client side:
//! ```no_run
//! use sideway::ibverbs::completion::{CreateCompletionQueueWorkCompletionFlags, GenericCompletionQueue};
//! use sideway::ibverbs::device_context::DeviceContext;
//! use sideway::ibverbs::protection_domain::ProtectionDomain;
//! use sideway::ibverbs::queue_pair::{ExtendedQueuePair, QueuePair, QueuePairState};
//! use sideway::rdmacm::communication_manager::{ConnectionParameter, EventChannel, EventType, PortSpace};
//! use std::net::SocketAddr;
//! use std::str::FromStr;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! struct EndpointResources {
//!     ctx: Arc<DeviceContext>,
//!     pd: Arc<ProtectionDomain>,
//!     cq: GenericCompletionQueue,
//!     qp: ExtendedQueuePair,
//! }
//!
//! fn main() {
//!     let mut event_channel = EventChannel::new().unwrap();
//!     let id = event_channel.create_id(PortSpace::Tcp).unwrap();
//!     let mut resources: Option<EndpointResources> = None;
//!
//!     id.resolve_addr(
//!         None,
//!         SocketAddr::from_str("172.17.8.28:18515").unwrap(),
//!         Duration::from_secs(1),
//!     )
//!     .unwrap();
//!
//!     while let Ok(event) = event_channel.get_cm_event() {
//!         match event.event_type() {
//!             EventType::AddressResolved => {
//!                 id.resolve_route(Duration::from_secs(1)).unwrap();
//!             },
//!             EventType::RouteResolved => {
//!                 let ctx = id.get_device_context().unwrap();
//!                 let pd = ctx.alloc_pd().unwrap();
//!                 let cq: GenericCompletionQueue = ctx
//!                     .create_cq_builder()
//!                     .setup_wc_flags(CreateCompletionQueueWorkCompletionFlags::StandardFlags)
//!                     .setup_cqe(1)
//!                     .build_ex()
//!                     .unwrap()
//!                     .into();
//!                 let mut qp_builder = pd.create_qp_builder();
//!                 let mut qp = qp_builder
//!                     .setup_send_cq(cq.clone())
//!                     .setup_recv_cq(cq.clone())
//!                     .build_ex()
//!                     .unwrap();
//!
//!                 qp.modify(&id.get_qp_attr(QueuePairState::Init).unwrap()).unwrap();
//!
//!                 let entry = resources.get_or_insert_with(|| EndpointResources { ctx, pd, cq, qp });
//!                 let attr = id.get_qp_attr(QueuePairState::Init).unwrap();
//!                 entry.qp.modify(&attr).unwrap();
//!                 let mut param = ConnectionParameter::new();
//!                 param.setup_qp_number(entry.qp.qp_number());
//!                 id.connect(param).unwrap();
//!             },
//!             EventType::ConnectResponse => {
//!                 if let Some(entry) = resources.as_mut() {
//!                     let attr = id.get_qp_attr(QueuePairState::ReadyToReceive).unwrap();
//!                     entry.qp.modify(&attr).unwrap();
//!
//!                     let attr = id.get_qp_attr(QueuePairState::ReadyToSend).unwrap();
//!                     entry.qp.modify(&attr).unwrap();
//!
//!                     id.establish().unwrap();
//!                 }
//!             },
//!             _ => todo!(),
//!         }
//!     }
//! }
//! ```
//!
//! [`race condition`]: https://github.com/linux-rdma/rdma-core/pull/1182
//!
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

/// The type of communication [`Event`] which occurred.
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

/// An RDMA event represents an event from an RDMA event channel, reported by an [`Identifier`].
pub struct Event {
    event: NonNull<rdma_cm_event>,
    cm_id: Option<Arc<Identifier>>,
    listener_id: Option<Arc<Identifier>>,
}

/// An RDMA event channel is used to create [`Identifier`]s and receive [`Event`]s.
pub struct EventChannel {
    channel: NonNull<rdma_event_channel>,
}

/// An RDMA CM identifier (`rdma_cm_id`), conceptually similar to a socket, an [`Identifier`] would
/// report some of the RDMA CM operations' result as an [`Event`] to its [`EventChannel`].
pub struct Identifier {
    _event_channel: Arc<EventChannel>,
    cm_id: NonNull<rdma_cm_id>,
    user_context: Mutex<Option<Arc<dyn Any + Send + Sync>>>,
}

/// A connection paramter used for configure the communication when connecting or establishing
/// datagram communication. Used in [`Identifier::connect`] and [`Identifier::accept`].
pub struct ConnectionParameter(rdma_conn_param);

/// The RDMA port space.
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

/// Error returned by [`EventChannel::new`] for creating a new RDMA CM [`EventChannel`].
#[derive(Debug, thiserror::Error)]
#[error("failed to create rdma cm event channel")]
#[non_exhaustive]
pub struct CreateEventChannelError(#[from] pub CreateEventChannelErrorKind);

/// The enum type for [`CreateEventChannelError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum CreateEventChannelErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`EventChannel::create_id`] for creating a new RDMA CM [`Identifier`].
#[derive(Debug, thiserror::Error)]
#[error("failed to create rdma cm identifier")]
#[non_exhaustive]
pub struct CreateIdentifierError(#[from] pub CreateIdentifierErrorKind);

/// The enum type for [`CreateIdentifierError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum CreateIdentifierErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`EventChannel::get_cm_event`] for getting a new event from [`EventChannel`].
#[derive(Debug, thiserror::Error)]
#[error("failed to get rdma cm event")]
#[non_exhaustive]
pub struct GetEventError(#[from] pub GetEventErrorKind);

/// The enum type for [`GetEventError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum GetEventErrorKind {
    Rdmacm(#[from] io::Error),
    #[error("no event in event channel")]
    NoEvent,
}

/// Error returned by [`Event::ack`] for acknowledging an event.
#[derive(Debug, thiserror::Error)]
#[error("failed to acknowledge rdma cm event")]
#[non_exhaustive]
pub struct AcknowledgeEventError(#[from] pub AcknowledgeEventErrorKind);

/// The enum type for [`AcknowledgeEventError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum AcknowledgeEventErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`Identifier::bind_addr`] for binding an IP address to [`Identifier`].
#[derive(Debug, thiserror::Error)]
#[error("failed to bind address (addr={addr})")]
#[non_exhaustive]
pub struct BindAddressError {
    pub addr: SocketAddr,
    pub source: BindAddressErrorKind,
}

/// The enum type for [`BindAddressError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum BindAddressErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`Identifier::resolve_addr`] for resolving address information to destination
/// address for an [`Identifier`].
#[derive(Debug, thiserror::Error)]
#[error("failed to resolve address (src_addr={:?}, dst_addr={dst_addr})", src_addr)]
#[non_exhaustive]
pub struct ResolveAddressError {
    pub src_addr: Option<SocketAddr>,
    pub dst_addr: SocketAddr,
    pub source: ResolveAddressErrorKind,
}

/// The enum type for [`ResolveAddressError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum ResolveAddressErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`Identifier::resolve_route`] for resolving routing information for an
/// [`Identifier`].
#[derive(Debug, thiserror::Error)]
#[error("failed to resolve route")]
#[non_exhaustive]
pub struct ResolveRouteError(#[from] pub ResolveRouteErrorKind);

/// The enum type for [`ResolveRouteError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum ResolveRouteErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`Identifier::listen`] for listening new connection requests.
#[derive(Debug, thiserror::Error)]
#[error("failed to listen")]
#[non_exhaustive]
pub struct ListenError(#[from] pub ListenErrorKind);

/// The enum type for [`ListenError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum ListenErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`Identifier::connect`] for connecting to a remote endpoint.
#[derive(Debug, thiserror::Error)]
#[error("failed to connect")]
#[non_exhaustive]
pub struct ConnectError(#[from] pub ConnectErrorKind);

/// The enum type for [`ConnectError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum ConnectErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`Identifier::accept`] for accepting a new connection.
#[derive(Debug, thiserror::Error)]
#[error("failed to accept")]
#[non_exhaustive]
pub struct AcceptError(#[from] pub AcceptErrorKind);

/// The enum type for [`AcceptError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum AcceptErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`Identifier::establish`] for establishing connection setup.
#[derive(Debug, thiserror::Error)]
#[error("failed to establish")]
#[non_exhaustive]
pub struct EstablishError(#[from] pub EstablishErrorKind);

/// The enum type for [`EstablishError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum EstablishErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`Identifier::disconnect`] for disconnecting a connection.
#[derive(Debug, thiserror::Error)]
#[error("failed to disconnect")]
#[non_exhaustive]
pub struct DisconnectError(#[from] pub DisconnectErrorKind);

/// The enum type for [`DisconnectError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum DisconnectErrorKind {
    Rdmacm(#[from] io::Error),
}

/// Error returned by [`Identifier::get_qp_attr`] for getting current stage's
/// [`QueuePairAttribute`] for modifying a QP.
#[derive(Debug, thiserror::Error)]
#[error("failed to get qp attribute")]
#[non_exhaustive]
pub struct GetQueuePairAttributeError(#[from] pub GetQueuePairAttributeErrorKind);

/// The enum type for [`GetQueuePairAttributeError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum GetQueuePairAttributeErrorKind {
    Rdmacm(#[from] io::Error),
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

    /// Get the private data sent by the remote peer.
    ///
    /// This is typically available for [`EventType::ConnectRequest`] and
    /// [`EventType::ConnectResponse`] events, where the remote peer may have
    /// sent private data as part of the connection setup.
    ///
    /// # Returns
    /// - `Some(&[u8])` - The private data slice if any was provided
    /// - `None` - If no private data was sent or the length is 0
    ///
    /// # Example
    /// ```ignore
    /// match event.event_type() {
    ///     EventType::ConnectRequest => {
    ///         if let Some(data) = event.get_private_data() {
    ///             println!("Received {} bytes of private data", data.len());
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// ```
    pub fn get_private_data(&self) -> Option<&[u8]> {
        unsafe {
            let param = &self.event.as_ref().param.conn;
            let len = param.private_data_len as usize;
            if len == 0 || param.private_data.is_null() {
                None
            } else {
                Some(std::slice::from_raw_parts(
                    param.private_data as *const u8,
                    len,
                ))
            }
        }
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
    pub fn ack(mut self) -> Result<(), AcknowledgeEventError> {
        let ret = unsafe { rdma_ack_cm_event(self.event.as_mut()) };

        if ret < 0 {
            return Err(AcknowledgeEventErrorKind::Rdmacm(io::Error::last_os_error()).into());
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

fn new_cm_id_for_raw(event_channel: Arc<EventChannel>, raw: *mut rdma_cm_id) -> Arc<Identifier> {
    let cm = unsafe {
        Arc::new(Identifier {
            _event_channel: event_channel,
            cm_id: NonNull::new(raw).unwrap_unchecked(),
            user_context: Mutex::new(None),
        })
    };

    let weak_cm = Arc::downgrade(&cm.clone());
    let boxed = Box::new(weak_cm);
    let raw_box = Box::into_raw(boxed);

    unsafe {
        (*raw).context = raw_box as *mut std::ffi::c_void;
    }

    cm
}

impl EventChannel {
    pub fn new() -> Result<Arc<EventChannel>, CreateEventChannelError> {
        let channel = unsafe { rdma_create_event_channel() };

        if channel.is_null() {
            return Err(CreateEventChannelErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        Ok(Arc::new(EventChannel {
            channel: unsafe { NonNull::new(channel).unwrap_unchecked() },
        }))
    }

    /// Create a new [`Identifier`] for the event channel, all later events associated with this
    /// [`Identifier`] would be delivered to the event channel.
    pub fn create_id(self: &Arc<Self>, port_space: PortSpace) -> Result<Arc<Identifier>, CreateIdentifierError> {
        let mut cm_id_ptr: *mut rdma_cm_id = null_mut();
        let ret = unsafe { rdma_create_id(self.channel.as_ptr(), &mut cm_id_ptr, null_mut(), port_space as u32) };

        if ret < 0 {
            return Err(CreateIdentifierErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        Ok(new_cm_id_for_raw(self.clone(), cm_id_ptr))
    }

    /// Get a new [`Event`] from the event channel, if the event channel is blocking mode, this
    /// method would block until a new event is available, otherwise, this method would return an
    /// error if no new event is available.
    pub fn get_cm_event(self: &Arc<Self>) -> Result<Event, GetEventError> {
        let mut event_ptr = MaybeUninit::<*mut rdma_cm_event>::uninit();

        let ret = unsafe { rdma_get_cm_event(self.channel.as_ptr(), event_ptr.as_mut_ptr()) };

        if ret < 0 {
            match io::Error::last_os_error().kind() {
                io::ErrorKind::WouldBlock => return Err(GetEventErrorKind::NoEvent.into()),
                err => return Err(GetEventErrorKind::Rdmacm(err.into()).into()),
            }
        }

        let event = unsafe { NonNull::new(event_ptr.assume_init()).unwrap() };

        let cm_id = unsafe {
            let raw_cm_id = event.as_ref().id;

            assert_ne!(raw_cm_id, null_mut());
            if event.as_ref().event == EventType::ConnectRequest as u32 {
                // For connect requests, create a new CommunicationManager
                Some(new_cm_id_for_raw(self.clone(), raw_cm_id))
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

    /// Set the nonblocking mode of event channel's underlying file descriptor to on (true) or off
    /// (false).
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        // from libstd/sys/unix/fd.rs
        let fd = self.as_raw_fd();

        unsafe {
            let previous = libc::fcntl(fd, libc::F_GETFL);
            if previous < 0 {
                return Err(io::Error::last_os_error());
            }
            let new = if nonblocking {
                previous | libc::O_NONBLOCK
            } else {
                previous & !libc::O_NONBLOCK
            };
            if libc::fcntl(fd, libc::F_SETFL, new) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

impl AsRawFd for EventChannel {
    fn as_raw_fd(&self) -> RawFd {
        unsafe { self.channel.as_ref().fd }
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
    /// Setup the user context for the [`Identifier`], so that you can get it back later. As
    /// [`Identifier`] is thread-safe, so the context should be thread-safe too.
    pub fn setup_context<C: Any + Send + Sync>(&self, ctx: C) {
        let mut user_data = self.user_context.lock().unwrap();
        *user_data = Some(Arc::new(ctx));
    }

    /// Get the user context setting up by [`setup_context`].
    ///
    /// [`setup_context`]: crate::rdmacm::communication_manager::Identifier::setup_context
    ///
    pub fn get_context<C: Any + Send + Sync>(&self) -> Option<Arc<C>> {
        let user_data = self.user_context.lock().unwrap();
        let arc_any = user_data.as_ref()?.clone();
        arc_any.downcast::<C>().ok()
    }

    /// Get the RDMA device's port number of the [`Identifier`]. The port number is only available
    /// after the [`Identifier`] is bound to a specific address by [`bind_addr`] or [`resolve_addr`].
    ///
    /// [`bind_addr`]: crate::rdmacm::communication_manager::Identifier::bind_addr
    /// [`resolve_addr`]: crate::rdmacm::communication_manager::Identifier::resolve_addr
    ///
    pub fn port(&self) -> u8 {
        let cm_id = self.cm_id;

        unsafe { cm_id.as_ref().port_num }
    }

    /// Bind the [`Identifier`] to a specific address. Note that users shouldn't bind to a loopback
    /// address like `127.0.0.1`, or the connection would fail.
    ///
    /// The address could be `0.0.0.0` or `::`, then the specific RDMA device would be chosen on
    /// [`resolve_addr`] or receiving a connection request.
    ///
    /// [`resolve_addr`]: crate::rdmacm::communication_manager::Identifier::resolve_addr
    ///
    pub fn bind_addr(&self, addr: SocketAddr) -> Result<(), BindAddressError> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_bind_addr(cm_id.as_ptr(), OsSocketAddr::from(addr).as_mut_ptr()) };

        if ret < 0 {
            return Err(BindAddressError {
                addr,
                source: BindAddressErrorKind::Rdmacm(io::Error::last_os_error()),
            });
        }

        Ok(())
    }

    /// Resolve the address of the [`Identifier`]. Map a given destination IP address to a usable
    /// RDMA address. The mapping is done by using the local routing table, or via ARP. If a
    /// source address is provided, the [`Identifier`] would be bound to the address, just as if
    /// [`bind_addr`] is called. If no source address is provided, the [`Identifier`] would be
    /// bound to a source address based on the local routing table.
    ///
    /// After this call (user received [`EventType::AddressResolved`] event), the [`Identifier`]
    /// would be bound to an RDMA device.
    ///
    /// This call is typically used for the client side before [`resolve_route`] and [`connect`].
    ///
    /// [`bind_addr`]: crate::rdmacm::communication_manager::Identifier::bind_addr
    /// [`resolve_route`]: crate::rdmacm::communication_manager::Identifier::resolve_route
    /// [`connect`]: crate::rdmacm::communication_manager::Identifier::connect
    ///
    pub fn resolve_addr(
        &self, src_addr: Option<SocketAddr>, dst_addr: SocketAddr, timeout: Duration,
    ) -> Result<(), ResolveAddressError> {
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
            return Err(ResolveAddressError {
                src_addr,
                dst_addr,
                source: ResolveAddressErrorKind::Rdmacm(io::Error::last_os_error()),
            });
        }

        Ok(())
    }

    /// Resolve an RDMA route to the destination address of the [`Identifier`]. The destination
    /// must have already been resolved by [`resolve_addr`].
    ///
    /// This call is typically used for the client side before [`connect`].
    ///
    /// [`resolve_addr`]: crate::rdmacm::communication_manager::Identifier::resolve_addr
    /// [`connect`]: crate::rdmacm::communication_manager::Identifier::connect
    ///
    pub fn resolve_route(&self, timeout: Duration) -> Result<(), ResolveRouteError> {
        let cm_id = self.cm_id;
        let timeout_ms: i32 = timeout.as_millis().try_into().unwrap();

        let ret = unsafe { rdma_resolve_route(cm_id.as_ptr(), timeout_ms) };

        if ret < 0 {
            return Err(ResolveRouteErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        Ok(())
    }

    /// Listen for incoming connections on the [`Identifier`]. The listen will be restricted to the
    /// address bound by [`bind_addr`]. And `backlog` is the maximum number of connections that can
    /// be queued.
    ///
    /// [`bind_addr`]: crate::rdmacm::communication_manager::Identifier::bind_addr
    ///
    pub fn listen(&self, backlog: i32) -> Result<(), ListenError> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_listen(cm_id.as_ptr(), backlog) };

        if ret < 0 {
            return Err(ListenErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        Ok(())
    }

    /// Get the [`DeviceContext`] associated with the [`Identifier`]. The [`DeviceContext`] is only
    /// available after the [`Identifier`] is bound to a specific address by [`bind_addr`] or
    /// [`resolve_addr`].
    ///
    /// [`bind_addr`]: crate::rdmacm::communication_manager::Identifier::bind_addr
    /// [`resolve_addr`]: crate::rdmacm::communication_manager::Identifier::resolve_addr
    ///
    pub fn get_device_context(&self) -> Option<Arc<DeviceContext>> {
        let cm_id = self.cm_id;

        unsafe {
            if (*cm_id.as_ptr()).verbs.is_null() {
                return None;
            }

            let mut guard = DEVICE_LISTS.lock().unwrap();
            let device_ctx = guard.entry((*cm_id.as_ptr()).verbs as usize).or_insert_with(|| {
                Arc::new(DeviceContext {
                    // Safe due to the is_null() check above.
                    context: NonNull::new((*cm_id.as_ptr()).verbs).unwrap(),
                })
            });

            Some(device_ctx.clone())
        }
    }

    /// Connect to a remote [`Identifier`]. The destination must have already been resolved by
    /// [`resolve_addr`] and [`resolve_route`]. The QP must be created before this call.
    ///
    /// [`resolve_addr`]: crate::rdmacm::communication_manager::Identifier::resolve_addr
    /// [`resolve_route`]: crate::rdmacm::communication_manager::Identifier::resolve_route
    ///
    pub fn connect(&self, mut conn_param: ConnectionParameter) -> Result<(), ConnectError> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_connect(cm_id.as_ptr(), &mut conn_param.0) };

        if ret < 0 {
            return Err(ConnectErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        Ok(())
    }

    /// Disconnect the [`Identifier`].
    pub fn disconnect(&self) -> Result<(), DisconnectError> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_disconnect(cm_id.as_ptr()) };

        if ret < 0 {
            return Err(DisconnectErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        Ok(())
    }

    /// Called from the listening side to accept an incoming connection on the [`Identifier`].
    ///
    /// # Note
    ///
    /// This method is only useful for [`EventType::ConnectRequest`] events. A new [`Identifier`]
    /// is automatically created to handle the incoming connection request. This is distinct from
    /// the listener [`Identifier`]. The new [`Identifier`] could be obtained by [`Event::cm_id`].
    ///
    /// To set up an [`ReliableConnection`], you should create a new QP and modify the QP to
    /// [`QueuePairState::ReadyToSend`], then call [`accept`] to complete the connection
    /// establishment.
    ///
    /// [`ReliableConnection`]: crate::ibverbs::queue_pair::QueuePairType::ReliableConnection
    /// [`QueuePairState::ReadyToSend`]: crate::ibverbs::queue_pair::QueuePairState::ReadyToSend
    /// [`accept`]: crate::rdmacm::communication_manager::Identifier::accept
    ///
    pub fn accept(&self, mut conn_param: ConnectionParameter) -> Result<(), AcceptError> {
        let cm_id = self.cm_id;

        let ret = unsafe { rdma_accept(cm_id.as_ptr(), &mut conn_param.0) };

        if ret < 0 {
            return Err(AcceptErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        Ok(())
    }

    /// Acknowledge an incoming connection response event and complete the connection establishment
    /// on the [`Identifier`].
    ///
    /// # Note
    ///
    /// This method is only useful for [`EventType::ConnectResponse`] events. The remote side
    /// accepts the connection request and sends a connection response to the active side. To
    /// complete an [`ReliableConnection`] establishment, you should modify the QP you speficied
    /// in [`connect`] to [`QueuePairState::ReadyToSend`], then call [`establish`] after receiving
    /// the connection response event.
    ///
    /// [`ReliableConnection`]: crate::ibverbs::queue_pair::QueuePairType::ReliableConnection
    /// [`connect`]: crate::rdmacm::communication_manager::Identifier::connect
    /// [`QueuePairState::ReadyToSend`]: crate::ibverbs::queue_pair::QueuePairState::ReadyToSend
    /// [`establish`]: crate::rdmacm::communication_manager::Identifier::establish
    ///
    pub fn establish(&self) -> Result<(), EstablishError> {
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_establish(cm_id.as_ptr()) };

        if ret < 0 {
            return Err(EstablishErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        Ok(())
    }

    /// Get the [`QueuePairAttribute`] of the [`Identifier`].
    pub fn get_qp_attr(&self, state: QueuePairState) -> Result<QueuePairAttribute, GetQueuePairAttributeError> {
        let cm_id = self.cm_id;
        let mut attr = MaybeUninit::<ibv_qp_attr>::uninit();
        let mut mask = 0;

        unsafe { (*attr.as_mut_ptr()).qp_state = state as _ };

        let ret = unsafe { rdma_init_qp_attr(cm_id.as_ptr(), attr.as_mut_ptr(), &mut mask) };

        if ret < 0 {
            return Err(GetQueuePairAttributeErrorKind::Rdmacm(io::Error::last_os_error()).into());
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

    /// Setup the QP number of the [`Identifier`]. You should fill in this field when you are
    /// setting up an [`ReliableConnection`] in [`connect`] and [`accept`].
    ///
    /// [`ReliableConnection`]: crate::ibverbs::queue_pair::QueuePairType::ReliableConnection
    /// [`connect`]: crate::rdmacm::communication_manager::Identifier::connect
    /// [`accept`]: crate::rdmacm::communication_manager::Identifier::accept
    ///
    pub fn setup_qp_number(&mut self, qp_number: u32) -> &mut Self {
        self.0.qp_num = qp_number;
        self
    }

    /// Setup the private data to be sent with connect or accept.
    ///
    /// # Arguments
    /// * `data` - The private data slice. Maximum 56 bytes for RC/UC connections,
    ///            180 bytes for UD. Data exceeding the limit will be truncated.
    ///
    /// # Safety
    /// The caller must ensure the data slice remains valid until the connect/accept
    /// operation completes.
    ///
    /// # Example
    /// ```ignore
    /// let my_data = [1u8, 2, 3, 4];
    /// param.setup_private_data(&my_data);
    /// id.connect(param)?;
    /// ```
    pub fn setup_private_data(&mut self, data: &[u8]) -> &mut Self {
        // Maximum private_data for RC/UC is 56 bytes, for UD is 180 bytes
        // We use 56 as the safe limit for RC connections
        let len = data.len().min(56);
        self.0.private_data = data.as_ptr() as *const _;
        self.0.private_data_len = len as u8;
        self
    }

    /// Setup responder resources for the connection.
    /// This is the maximum number of outstanding RDMA read/atomic operations
    /// the local side will accept from the remote side.
    pub fn setup_responder_resources(&mut self, resources: u8) -> &mut Self {
        self.0.responder_resources = resources;
        self
    }

    /// Setup initiator depth for the connection.
    /// This is the maximum number of outstanding RDMA read/atomic operations
    /// that the local side will have pending to the remote side.
    pub fn setup_initiator_depth(&mut self, depth: u8) -> &mut Self {
        self.0.initiator_depth = depth;
        self
    }

    /// Setup retry count for the connection.
    /// The number of times to retry a connection request or response.
    pub fn setup_retry_count(&mut self, count: u8) -> &mut Self {
        self.0.retry_count = count;
        self
    }

    /// Setup RNR retry count for the connection.
    /// The number of times to retry a receiver-not-ready error.
    pub fn setup_rnr_retry_count(&mut self, count: u8) -> &mut Self {
        self.0.rnr_retry_count = count;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polling::{Event, Events, Poller};
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::thread;

    #[test]
    fn test_cm_id_reference_count() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(channel) => {
                let id = channel.create_id(PortSpace::Tcp).unwrap();

                assert_eq!(Arc::strong_count(&channel), 2);
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
    fn test_channel_event_fd() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(channel) => {
                let id = channel.create_id(PortSpace::Tcp).unwrap();

                assert_eq!(Arc::strong_count(&id), 1);

                channel.set_nonblocking(true).unwrap();

                let dispatcher = thread::spawn(move || {
                    let poller = Poller::new().expect("Failed to create poller");
                    let key = 233;

                    assert_eq!(Arc::strong_count(&channel), 2);
                    unsafe { poller.add(&channel, Event::readable(key)).unwrap() };

                    let mut events = Events::new();
                    events.clear();
                    poller.wait(&mut events, None).unwrap();

                    assert_eq!(events.len(), 1);

                    for ev in events.iter() {
                        assert_eq!(ev.key, key);

                        let event = channel.get_cm_event().unwrap();
                        assert_eq!(event.event_type(), EventType::AddressResolved);
                        assert_eq!(Arc::strong_count(&channel), 2);

                        event.ack().unwrap();
                        assert_eq!(Arc::strong_count(&channel), 2);
                    }
                });

                let _ = id.resolve_addr(
                    None,
                    SocketAddr::from((IpAddr::from_str("127.0.0.1").expect("Invalid IP address"), 0)),
                    Duration::new(0, 200000000),
                );

                dispatcher.join().unwrap();
                assert_eq!(Arc::strong_count(&id), 1);

                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn test_bind_on_the_same_port() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(channel) => {
                let id = channel.create_id(PortSpace::Tcp).unwrap();
                let address = SocketAddr::from((IpAddr::from_str("0.0.0.0").expect("Invalid IP address"), 8080));

                let res = id.bind_addr(address);

                assert!(res.is_ok());

                let new_id = channel.create_id(PortSpace::Tcp).unwrap();

                let err = new_id.bind_addr(address).err().unwrap();

                assert_eq!(err.addr, address);
                match err.source {
                    BindAddressErrorKind::Rdmacm(err) => assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable),
                };

                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn test_conn_param() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(channel) => {
                let _id = channel.create_id(PortSpace::Tcp).unwrap();

                let _param = ConnectionParameter::new();

                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn test_event_channel_outlives_identifier_arc_counts() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(channel) => {
                let id = channel.create_id(PortSpace::Tcp).unwrap();

                assert_eq!(Arc::strong_count(&channel), 2);

                drop(id);

                assert_eq!(Arc::strong_count(&channel), 1);

                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn test_get_device_context_caches_correctly() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(channel) => {
                let id = channel.create_id(PortSpace::Tcp)?;

                let _ = id.resolve_addr(
                    None,
                    SocketAddr::from((IpAddr::from_str("127.0.0.1")?, 0)),
                    Duration::new(0, 200000000),
                );

                let event = channel.get_cm_event()?;
                assert_eq!(event.event_type(), EventType::AddressResolved);

                let ctx1 = id.get_device_context();
                let ctx2 = id.get_device_context();
                let ctx3 = id.get_device_context();

                assert!(ctx1.is_some(), "First get_device_context should return Some");
                assert!(ctx2.is_some(), "Second get_device_context should return Some");
                assert!(ctx3.is_some(), "Third get_device_context should return Some");

                assert!(
                    Arc::ptr_eq(&ctx1.clone().unwrap(), &ctx2.clone().unwrap()),
                    "ctx1 and ctx2 should point to the same DeviceContext"
                );
                assert!(
                    Arc::ptr_eq(&ctx2.clone().unwrap(), &ctx3.clone().unwrap()),
                    "ctx2 and ctx3 should point to the same DeviceContext"
                );

                let ctx = ctx1.unwrap();
                let _pd = ctx.alloc_pd()?;

                Ok(())
            },
            Err(_) => Ok(()),
        }
    }
}
