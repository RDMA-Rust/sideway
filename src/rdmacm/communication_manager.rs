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
    ibv_context, ibv_qp_attr, ibv_qp_type, rdma_accept, rdma_ack_cm_event, rdma_bind_addr, rdma_cm_event,
    rdma_cm_event_type, rdma_cm_id, rdma_conn_param, rdma_connect, rdma_create_event_channel, rdma_create_id,
    rdma_destroy_event_channel, rdma_destroy_id, rdma_disconnect, rdma_establish, rdma_event_channel,
    rdma_free_devices, rdma_get_cm_event, rdma_get_devices, rdma_get_local_addr, rdma_get_peer_addr, rdma_init_qp_attr,
    rdma_listen, rdma_migrate_id, rdma_port_space, rdma_reject, rdma_resolve_addr, rdma_resolve_route,
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
    event_channel: Option<Arc<EventChannel>>,
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
    // Keeps the raw rdma_cm_id's current event channel alive. The mutex is a
    // Rust-side migration guard: it serializes rdma_migrate_id plus the Arc
    // replacement so concurrent migrations cannot leave this lifetime anchor
    // pointing at a different channel than rdma_cm_id::channel. It is not a
    // general RDMA CM operation lock; other operations do not read this field.
    event_channel: Mutex<Arc<EventChannel>>,
    cm_id: NonNull<rdma_cm_id>,
    user_context: Mutex<Option<Arc<dyn Any + Send + Sync>>>,
}

/// A connection paramter used for configure the communication when connecting or establishing
/// datagram communication. Used in [`Identifier::connect`] and [`Identifier::accept`].
pub struct ConnectionParameter {
    conn_param: rdma_conn_param,
    private_data: Vec<u8>,
}

/// The RDMA port space.
#[derive(Debug, Clone, Copy)]
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

/// Error returned by [`Identifier::migrate`] for moving an [`Identifier`] to another
/// [`EventChannel`].
#[derive(Debug, thiserror::Error)]
#[error("failed to migrate rdma cm identifier")]
#[non_exhaustive]
pub struct MigrateError(#[from] pub MigrateErrorKind);

/// The enum type for [`MigrateError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum MigrateErrorKind {
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

/// Error returned by [`Identifier::reject`] for rejecting a connection request.
#[derive(Debug, thiserror::Error)]
#[error("failed to reject")]
#[non_exhaustive]
pub struct RejectError(#[from] pub RejectErrorKind);

/// The enum type for [`RejectError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum RejectErrorKind {
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

/// Error returned by [`get_devices`] for getting RDMA devices opened by RDMA CM.
#[derive(Debug, thiserror::Error)]
#[error("failed to get rdma devices")]
#[non_exhaustive]
pub struct GetDevicesError(#[from] pub GetDevicesErrorKind);

/// The enum type for [`GetDevicesError`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[non_exhaustive]
pub enum GetDevicesErrorKind {
    Rdmacm(#[from] io::Error),
    #[error("rdma_get_devices returned invalid device count: {0}")]
    InvalidDeviceCount(i32),
    #[error("rdma_get_devices returned null context at index {0}")]
    NullDeviceContext(usize),
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
    /// This is available for [`EventType::ConnectRequest`],
    /// [`EventType::ConnectResponse`], and [`EventType::Rejected`] events, where
    /// RDMA CM uses the `rdma_cm_event.param` union to carry connection or
    /// datagram-service private data.
    ///
    /// Note that the actual amount of data transferred is transport dependent
    /// and may be larger than that requested, with trailing zero as padding.
    ///
    /// **For `AF_IB` connected requests, Linux formats RDMA CM's
    /// `struct cma_hdr` at the start of the IB CM REQ private-data area.
    /// The first byte is `cma_version`, currently `0`, so byte 0 of
    /// the [`EventType::ConnectRequest`] private data is overwritten
    /// with `0` and is not the peer's original application byte.**
    ///
    /// # Returns
    /// The private data slice, or an empty slice if the event has no private
    /// data.
    ///
    /// # Example
    /// ```ignore
    /// match event.event_type() {
    ///     EventType::ConnectRequest => {
    ///         let data = event.private_data();
    ///         if !data.is_empty() {
    ///             println!("Received {} bytes of private data", data.len());
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// ```
    pub fn private_data(&self) -> &[u8] {
        unsafe {
            let event = self.event.as_ref();
            match self.event_type() {
                EventType::ConnectRequest | EventType::ConnectResponse | EventType::Rejected => {
                    let Some(id) = NonNull::new(event.id) else {
                        return &[];
                    };

                    if id.as_ref().qp_type == ibv_qp_type::IBV_QPT_UD {
                        let param = &event.param.ud;
                        Self::private_data_slice(event, param.private_data, param.private_data_len)
                    } else {
                        let param = &event.param.conn;
                        Self::private_data_slice(event, param.private_data, param.private_data_len)
                    }
                },
                _ => &[],
            }
        }
    }

    fn private_data_slice(
        _event: &rdma_cm_event, private_data: *const std::ffi::c_void, private_data_len: u8,
    ) -> &[u8] {
        let len = private_data_len as usize;
        if len == 0 || private_data.is_null() {
            &[]
        } else {
            // SAFETY: The caller selected the active RDMA CM event union member
            // for an event type that carries private data. The returned slice is
            // valid until the event is acknowledged.
            unsafe { std::slice::from_raw_parts(private_data.cast(), len) }
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

        self.event_channel.take();
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

struct RdmaDeviceList {
    devices: NonNull<*mut ibv_context>,
}

#[repr(C)]
struct SockAddrIb {
    sib_family: libc::sa_family_t,
    sib_pkey: u16,
    sib_flowinfo: u32,
    sib_addr: [u8; 16],
    sib_sid: u64,
    sib_sid_mask: u64,
    sib_scope_id: u64,
}

impl Drop for RdmaDeviceList {
    fn drop(&mut self) {
        unsafe { rdma_free_devices(self.devices.as_ptr()) };
    }
}

fn cached_device_context(context: NonNull<ibv_context>) -> Arc<DeviceContext> {
    let mut guard = DEVICE_LISTS.lock().unwrap();
    guard
        .entry(context.as_ptr() as usize)
        .or_insert_with(|| Arc::new(DeviceContext { context }))
        .clone()
}

fn socket_addr_from_raw(addr: &libc::sockaddr) -> Option<SocketAddr> {
    let len = match addr.sa_family as i32 {
        libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>(),
        libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
        _ => return None,
    };

    unsafe { OsSocketAddr::copy_from_raw(addr, len as libc::socklen_t).into_addr() }
}

fn port_from_raw_addr(addr: &libc::sockaddr) -> u16 {
    match addr.sa_family as i32 {
        libc::AF_INET => {
            let addr = unsafe { &*(std::ptr::from_ref(addr).cast::<libc::sockaddr_in>()) };
            u16::from_be(addr.sin_port)
        },
        libc::AF_INET6 => {
            let addr = unsafe { &*(std::ptr::from_ref(addr).cast::<libc::sockaddr_in6>()) };
            u16::from_be(addr.sin6_port)
        },
        libc::AF_IB => {
            let addr = unsafe { &*(std::ptr::from_ref(addr).cast::<SockAddrIb>()) };
            u64::from_be(addr.sib_sid) as u16
        },
        _ => 0,
    }
}

/// Get a list of RDMA devices currently available.
///
/// This wraps [`rdma_get_devices`], which returns a temporary array of
/// RDMA-CM-opened device contexts. The temporary array is released with
/// `rdma_free_devices`, while the returned [`DeviceContext`] handles are reused
/// through this module's global context cache.
///
/// The cache is intentionally insertion-only. RDMA CM owns these opened
/// contexts, and dropping a [`DeviceContext`] closes its raw context. Keeping a
/// cached [`Arc`] alive prevents Rust from closing a context that librdmacm may
/// still manage and reuse internally. This mirrors [`Identifier::get_device_context`]
/// and does not attempt hot-unplug invalidation.
///
/// [`rdma_get_devices`]: https://man7.org/linux/man-pages/man3/rdma_get_devices.3.html
pub fn get_devices() -> Result<Vec<Arc<DeviceContext>>, GetDevicesError> {
    let mut num_devices = 0;
    let devices = unsafe { rdma_get_devices(&mut num_devices) };

    if devices.is_null() || num_devices == 0 {
        return Ok(Vec::new());
    }

    let devices = RdmaDeviceList {
        devices: unsafe { NonNull::new_unchecked(devices) },
    };
    let num_devices = usize::try_from(num_devices).map_err(|_| GetDevicesErrorKind::InvalidDeviceCount(num_devices))?;
    let contexts = unsafe { std::slice::from_raw_parts(devices.devices.as_ptr(), num_devices) };
    let mut guard = DEVICE_LISTS.lock().unwrap();

    contexts
        .iter()
        .enumerate()
        .map(|(index, &context)| -> Result<_, GetDevicesError> {
            let context = NonNull::new(context).ok_or(GetDevicesErrorKind::NullDeviceContext(index))?;
            Ok(guard
                .entry(context.as_ptr() as usize)
                .or_insert_with(|| Arc::new(DeviceContext { context }))
                .clone())
        })
        .collect()
}

fn new_cm_id_for_raw(event_channel: Arc<EventChannel>, raw: *mut rdma_cm_id) -> Arc<Identifier> {
    let cm = unsafe {
        Arc::new(Identifier {
            event_channel: Mutex::new(event_channel),
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
            event_channel: Some(self.clone()),
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

    /// Get the local port number of a bound [`Identifier`] in host byte order. If the
    /// [`Identifier`] is not bound to a port, the returned value is 0.
    pub fn get_src_port(&self) -> u16 {
        unsafe { port_from_raw_addr(rdma_get_local_addr(self.cm_id.as_ref())) }
    }

    /// Get the remote port number of a bound [`Identifier`] in host byte order. If the
    /// [`Identifier`] is not connected, the returned value is 0.
    pub fn get_dst_port(&self) -> u16 {
        unsafe { port_from_raw_addr(rdma_get_peer_addr(self.cm_id.as_ref())) }
    }

    /// Get the local IP socket address of a bound [`Identifier`].
    ///
    /// Returns [`None`] when the RDMA CM address is not representable as
    /// [`SocketAddr`], for example when the underlying address family is
    /// `AF_IB`, or when the [`Identifier`] is not bound to an address.
    pub fn get_local_addr(&self) -> Option<SocketAddr> {
        unsafe { socket_addr_from_raw(rdma_get_local_addr(self.cm_id.as_ref())) }
    }

    /// Get the remote IP socket address of the [`Identifier`].
    ///
    /// Returns [`None`] when the RDMA CM address is not representable as
    /// [`SocketAddr`], for example when the underlying address family is
    /// `AF_IB`, or when the [`Identifier`] is not connected.
    pub fn get_peer_addr(&self) -> Option<SocketAddr> {
        unsafe { socket_addr_from_raw(rdma_get_peer_addr(self.cm_id.as_ref())) }
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

    /// Move this [`Identifier`] to another [`EventChannel`].
    ///
    /// After a successful migration, RDMA CM events associated with this
    /// identifier are reported on `channel`. `librdmacm` also moves any pending
    /// events for the identifier to the new channel.
    ///
    /// # Note
    ///
    /// The underlying [`rdma_migrate_id(3)`] call may block while the current
    /// event channel has unacknowledged events. Do not poll the current event
    /// channel or invoke other routines on this identifier while migrating it
    /// between channels.
    ///
    /// The C API accepts a null channel to put the ID into synchronous operation
    /// mode. This safe wrapper intentionally exposes only migration to a live
    /// [`EventChannel`].
    ///
    /// [`rdma_migrate_id(3)`]: https://man7.org/linux/man-pages/man3/rdma_migrate_id.3.html
    pub fn migrate(&self, channel: &Arc<EventChannel>) -> Result<(), MigrateError> {
        let mut event_channel = self.event_channel.lock().unwrap();
        let cm_id = self.cm_id;
        let ret = unsafe { rdma_migrate_id(cm_id.as_ptr(), channel.channel.as_ptr()) };

        if ret < 0 {
            return Err(MigrateErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        *event_channel = channel.clone();

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
            let context = NonNull::new((*cm_id.as_ptr()).verbs)?;
            Some(cached_device_context(context))
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
        let ret = unsafe { rdma_connect(cm_id.as_ptr(), &mut conn_param.conn_param) };

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

        let ret = unsafe { rdma_accept(cm_id.as_ptr(), &mut conn_param.conn_param) };

        if ret < 0 {
            return Err(AcceptErrorKind::Rdmacm(io::Error::last_os_error()).into());
        }

        Ok(())
    }

    /// Called from the listening side to reject an incoming connection on the [`Identifier`].
    ///
    /// # Note
    ///
    /// This method is only useful for [`EventType::ConnectRequest`] events. A new [`Identifier`]
    /// is automatically created to handle the incoming connection request. This is distinct from
    /// the listener [`Identifier`]. The new [`Identifier`] could be obtained by [`Event::cm_id`].
    ///
    /// Use [`ConnectionParameter::setup_private_data`] to attach optional rejection private data.
    ///
    /// [`Event::cm_id`]: crate::rdmacm::communication_manager::Event::cm_id
    ///
    pub fn reject(&self, conn_param: ConnectionParameter) -> Result<(), RejectError> {
        let cm_id = self.cm_id;
        let ret = unsafe {
            rdma_reject(
                cm_id.as_ptr(),
                conn_param.conn_param.private_data,
                conn_param.conn_param.private_data_len,
            )
        };

        if ret < 0 {
            return Err(RejectErrorKind::Rdmacm(io::Error::last_os_error()).into());
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
        Self {
            conn_param: rdma_conn_param {
                private_data: null(),
                private_data_len: 0,
                responder_resources: 1,
                initiator_depth: 1,
                flow_control: 0,
                retry_count: 7,
                rnr_retry_count: 7,
                srq: 0,
                qp_num: 0,
            },
            private_data: Vec::new(),
        }
    }
}

impl ConnectionParameter {
    pub fn new() -> Self {
        Self {
            conn_param: rdma_conn_param {
                private_data: null(),
                private_data_len: 0,
                responder_resources: 0,
                initiator_depth: 0,
                flow_control: 0,
                retry_count: 0,
                rnr_retry_count: 0,
                srq: 0,
                qp_num: 0,
            },
            private_data: Vec::new(),
        }
    }

    /// Setup the QP number of the [`Identifier`]. You should fill in this field when you are
    /// setting up an [`ReliableConnection`] in [`connect`] and [`accept`].
    ///
    /// [`ReliableConnection`]: crate::ibverbs::queue_pair::QueuePairType::ReliableConnection
    /// [`connect`]: crate::rdmacm::communication_manager::Identifier::connect
    /// [`accept`]: crate::rdmacm::communication_manager::Identifier::accept
    ///
    pub fn setup_qp_number(&mut self, qp_number: u32) -> &mut Self {
        self.conn_param.qp_num = qp_number;
        self
    }

    /// Setup the private data to be sent with connect, accept, or reject.
    ///
    /// # Private data size
    ///
    /// This method copies the provided slice into the [`ConnectionParameter`]
    /// and stores that owned buffer's pointer and length in the raw RDMA CM
    /// parameter. It does not cap the length to any specific RDMA CM operation.
    /// Check the operation limit before calling [`Identifier::connect`],
    /// [`Identifier::accept`], or [`Identifier::reject`].
    ///
    /// | Port space | Service type | [`connect`] | [`accept`] | [`reject`] |
    /// | --- | --- | ---: | ---: | ---: |
    /// | [`PortSpace::Tcp`] | connected | 56 | 196 | 148 |
    /// | [`PortSpace::Udp`] | datagram | 180 | 136 | 136 |
    /// | [`PortSpace::InfiniBand`] | connected | 92 | 196 | 148 |
    /// | [`PortSpace::InfiniBand`] | datagram | 216 | 136 | 136 |
    ///
    /// [`PortSpace::Tcp`] and [`PortSpace::Udp`] values are the user-visible
    /// payload sizes documented by the [`rdma_connect`] and
    /// [`rdma_accept`] man pages, plus the [`rdma_reject`] sizes implied
    /// by Linux's IB CM message constants and RDMA CM routing.
    /// [`PortSpace::InfiniBand`] is derived from Linux CMA's
    /// `id->qp_type == IB_QPT_UD` branch: connected QPs use IB CM REQ/REP/REJ
    /// messages, while datagram services use SIDR REQ/REP.
    ///
    /// **For IB connected requests, Linux formats RDMA CM's
    /// `struct cma_hdr` at the start of the IB CM REQ private-data area.
    /// The first byte is `cma_version`, currently `0`, so byte 0 of
    /// the [`EventType::ConnectRequest`] private data is overwritten
    /// with `0`, please offset one byte when setting private data for IB.**
    ///
    /// [`connect`]: Identifier::connect
    /// [`accept`]: Identifier::accept
    /// [`reject`]: Identifier::reject
    /// [`rdma_connect`]: https://man7.org/linux/man-pages/man3/rdma_connect.3.html
    /// [`rdma_accept`]: https://man7.org/linux/man-pages/man3/rdma_accept.3.html
    /// [`rdma_reject`]: https://man7.org/linux/man-pages/man3/rdma_reject.3.html
    ///
    /// [`setup_private_data`]: ConnectionParameter::setup_private_data
    ///
    /// # Panics
    /// Panics if `data.len()` does not fit in `u8`, because
    /// `rdma_conn_param.private_data_len` is an 8-bit field.
    ///
    /// # Example
    /// ```ignore
    /// let my_data = [1u8, 2, 3, 4];
    /// param.setup_private_data(&my_data);
    /// id.connect(param)?;
    /// ```
    pub fn setup_private_data(&mut self, data: &[u8]) -> &mut Self {
        let len =
            u8::try_from(data.len()).expect("ConnectionParameter private_data length is limited to u8::MAX bytes");
        self.private_data.clear();
        self.private_data.extend_from_slice(data);
        self.conn_param.private_data = if self.private_data.is_empty() {
            null()
        } else {
            self.private_data.as_ptr().cast()
        };
        self.conn_param.private_data_len = len;
        self
    }

    /// Setup responder resources for the connection.
    /// This is the maximum number of outstanding RDMA read/atomic operations
    /// the local side will accept from the remote side.
    pub fn setup_responder_resources(&mut self, resources: u8) -> &mut Self {
        self.conn_param.responder_resources = resources;
        self
    }

    /// Setup initiator depth for the connection.
    /// This is the maximum number of outstanding RDMA read/atomic operations
    /// that the local side will have pending to the remote side.
    pub fn setup_initiator_depth(&mut self, depth: u8) -> &mut Self {
        self.conn_param.initiator_depth = depth;
        self
    }

    /// Setup retry count for the connection.
    /// The number of times to retry a connection request or response.
    pub fn setup_retry_count(&mut self, count: u8) -> &mut Self {
        self.conn_param.retry_count = count;
        self
    }

    /// Setup RNR retry count for the connection.
    /// The number of times to retry a receiver-not-ready error.
    pub fn setup_rnr_retry_count(&mut self, count: u8) -> &mut Self {
        self.conn_param.rnr_retry_count = count;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ibverbs::address::{GidEntry, GidType};
    use crate::ibverbs::completion::GenericCompletionQueue;
    use crate::ibverbs::device;
    use crate::ibverbs::queue_pair::{ExtendedQueuePair, QueuePair};
    use polling::{Event as PollingEvent, Events, Poller};
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;
    use std::thread;

    const CM_SETUP_PRIVATE_DATA_SIZE: usize = 54;

    #[derive(Clone, Copy)]
    struct CmGidTestAddr {
        ip: IpAddr,
        scope_id: u32,
    }

    impl CmGidTestAddr {
        fn socket_addr(self, port: u16) -> SocketAddr {
            match self.ip {
                IpAddr::V4(addr) => SocketAddr::from((addr, port)),
                IpAddr::V6(addr) => SocketAddr::V6(std::net::SocketAddrV6::new(addr, port, 0, self.scope_id)),
            }
        }
    }

    fn cm_addr_from_gid_entry(gid_entry: GidEntry) -> Option<CmGidTestAddr> {
        let gid = gid_entry.gid();
        if gid.is_zero() {
            return None;
        }

        match gid_entry.gid_type() {
            GidType::InfiniBand => {},
            GidType::RoceV2 if !gid.is_unicast_link_local() => {},
            _ => return None,
        }

        let ipv6 = Ipv6Addr::from(gid);
        let scope_id = if ipv6.is_unicast_link_local() {
            let scope_id = gid_entry.netdev_index();
            if scope_id == 0 {
                return None;
            }
            scope_id
        } else {
            0
        };

        Some(CmGidTestAddr {
            ip: ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4),
            scope_id,
        })
    }

    fn first_ib_or_roce_v2_gid_addr() -> Option<CmGidTestAddr> {
        let device_list = device::DeviceList::new().ok()?;

        for device in &device_list {
            let Ok(ctx) = device.open() else {
                continue;
            };
            let Ok(gid_entries) = ctx.query_gid_table() else {
                continue;
            };

            if let Some(addr) = gid_entries.into_iter().find_map(cm_addr_from_gid_entry) {
                return Some(addr);
            }
        }

        None
    }

    fn create_test_qp(id: &Identifier) -> Result<ExtendedQueuePair, String> {
        let ctx = id
            .get_device_context()
            .ok_or_else(|| "RDMA CM ID has no verbs device context".to_owned())?;
        let pd = ctx.alloc_pd().map_err(|err| err.to_string())?;
        let cq = GenericCompletionQueue::from(
            ctx.create_cq_builder()
                .setup_cqe(2)
                .build_ex()
                .map_err(|err| err.to_string())?,
        );

        let mut qp = pd
            .create_qp_builder()
            .setup_max_send_wr(1)
            .setup_max_send_sge(1)
            .setup_max_recv_wr(1)
            .setup_max_recv_sge(1)
            .setup_send_cq(cq.clone())
            .setup_recv_cq(cq)
            .build_ex()
            .map_err(|err| err.to_string())?;

        qp.modify(&id.get_qp_attr(QueuePairState::Init).map_err(|err| err.to_string())?)
            .map_err(|err| err.to_string())?;

        Ok(qp)
    }

    fn move_test_qp_to_rts(id: &Identifier, qp: &mut ExtendedQueuePair) -> Result<(), String> {
        qp.modify(
            &id.get_qp_attr(QueuePairState::ReadyToReceive)
                .map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())?;
        qp.modify(
            &id.get_qp_attr(QueuePairState::ReadyToSend)
                .map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())
    }

    fn wait_for_cm_event(
        channel: &Arc<EventChannel>, timeout: Duration, description: &str,
    ) -> Result<Event, Box<dyn std::error::Error>> {
        channel.set_nonblocking(true)?;

        let poller = Poller::new()?;
        unsafe { poller.add(channel, PollingEvent::readable(1))? };

        let mut events = Events::new();
        poller.wait(&mut events, Some(timeout))?;

        assert!(
            !events.is_empty(),
            "expected {description} to receive an RDMA CM event before timeout"
        );

        Ok(channel.get_cm_event()?)
    }

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

                let event = wait_for_cm_event(&channel, Duration::from_secs(2), "reference count test")?;

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
                    unsafe { poller.add(&channel, PollingEvent::readable(key)).unwrap() };

                    let mut events = Events::new();
                    events.clear();
                    poller.wait(&mut events, None).unwrap();

                    assert_eq!(events.len(), 1);

                    for ev in events.iter() {
                        assert_eq!(ev.key, key);

                        let event = channel.get_cm_event().unwrap();
                        assert!(
                            matches!(event.event_type(), EventType::AddressResolved | EventType::AddressError),
                            "unexpected RDMA CM event: {:?}",
                            event.event_type()
                        );
                        assert_eq!(Arc::strong_count(&channel), 3);

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
    fn test_event_keeps_source_channel_alive_after_identifier_migrates() -> Result<(), Box<dyn std::error::Error>> {
        match (EventChannel::new(), EventChannel::new()) {
            (Ok(source_channel), Ok(migrated_channel)) => {
                let id = source_channel.create_id(PortSpace::Tcp)?;
                let source_channel_weak = Arc::downgrade(&source_channel);

                id.resolve_addr(
                    None,
                    SocketAddr::from((IpAddr::from_str("127.0.0.1").expect("Invalid IP address"), 0)),
                    Duration::new(0, 200000000),
                )?;

                let event = wait_for_cm_event(&source_channel, Duration::from_secs(2), "source event channel")?;
                assert!(
                    matches!(event.event_type(), EventType::AddressResolved | EventType::AddressError),
                    "unexpected RDMA CM event: {:?}",
                    event.event_type()
                );
                assert_eq!(Arc::strong_count(&source_channel), 3);

                // Model the Rust-side lifetime state after a successful migration
                // without calling rdma_migrate_id while an event is unacknowledged.
                // The event must keep its retrieval channel alive even after the
                // identifier's current channel anchor moves elsewhere.
                *id.event_channel.lock().unwrap() = migrated_channel;
                assert_eq!(Arc::strong_count(&source_channel), 2);

                drop(source_channel);
                assert_eq!(source_channel_weak.strong_count(), 1);

                event.ack()?;
                assert!(source_channel_weak.upgrade().is_none());

                Ok(())
            },
            _ => Ok(()),
        }
    }

    #[test]
    fn test_migrate_id_to_same_channel_reports_events() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(channel) => {
                let id = channel.create_id(PortSpace::Tcp)?;
                let raw_channel = channel.channel.as_ptr();

                assert_eq!(Arc::strong_count(&channel), 2);
                assert_eq!(unsafe { id.cm_id.as_ref().channel }, raw_channel);

                id.migrate(&channel)?;

                assert_eq!(Arc::strong_count(&channel), 2);
                assert_eq!(unsafe { id.cm_id.as_ref().channel }, raw_channel);

                id.resolve_addr(
                    None,
                    SocketAddr::from((IpAddr::from_str("127.0.0.1").expect("Invalid IP address"), 0)),
                    Duration::new(0, 200000000),
                )?;

                let event = wait_for_cm_event(&channel, Duration::from_secs(2), "self-migrated event channel")?;
                assert!(
                    matches!(event.event_type(), EventType::AddressResolved | EventType::AddressError),
                    "unexpected RDMA CM event: {:?}",
                    event.event_type()
                );
                assert!(Arc::ptr_eq(
                    &event
                        .cm_id()
                        .expect("self-migrated event should carry the migrated identifier"),
                    &id
                ));
                event.ack()?;

                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn test_migrate_id_reports_events_to_new_channel() -> Result<(), Box<dyn std::error::Error>> {
        match (EventChannel::new(), EventChannel::new()) {
            (Ok(source_channel), Ok(migrated_channel)) => {
                let id = source_channel.create_id(PortSpace::Tcp)?;

                assert_eq!(Arc::strong_count(&source_channel), 2);
                assert_eq!(Arc::strong_count(&migrated_channel), 1);

                source_channel.set_nonblocking(true)?;
                id.migrate(&migrated_channel)?;

                assert_eq!(Arc::strong_count(&source_channel), 1);
                assert_eq!(Arc::strong_count(&migrated_channel), 2);
                assert_eq!(unsafe { id.cm_id.as_ref().channel }, migrated_channel.channel.as_ptr());

                id.resolve_addr(
                    None,
                    SocketAddr::from((IpAddr::from_str("127.0.0.1").expect("Invalid IP address"), 0)),
                    Duration::new(0, 200000000),
                )?;

                let event = wait_for_cm_event(&migrated_channel, Duration::from_secs(2), "migrated event channel")?;
                assert!(
                    matches!(event.event_type(), EventType::AddressResolved | EventType::AddressError),
                    "unexpected RDMA CM event: {:?}",
                    event.event_type()
                );
                assert!(Arc::ptr_eq(
                    &event
                        .cm_id()
                        .expect("migrated event should carry the migrated identifier"),
                    &id
                ));
                event.ack()?;

                match source_channel.get_cm_event() {
                    Err(err) => match err.0 {
                        GetEventErrorKind::NoEvent => {},
                        GetEventErrorKind::Rdmacm(err) => return Err(err.into()),
                    },
                    Ok(event) => {
                        let event_type = event.event_type();
                        event.ack()?;
                        panic!("source channel unexpectedly received migrated event {event_type:?}");
                    },
                }

                Ok(())
            },
            _ => Ok(()),
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
                assert_eq!(id.get_src_port(), address.port());

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

                let mut data = [0xa5; 196];
                let mut param = ConnectionParameter::new();
                param.setup_private_data(&data);

                assert_eq!(param.conn_param.private_data, param.private_data.as_ptr().cast());
                assert_eq!(param.conn_param.private_data_len, data.len() as u8);
                assert_ne!(param.conn_param.private_data, data.as_ptr().cast());

                data[0] = 0x5a;
                let stored_data = unsafe {
                    std::slice::from_raw_parts(
                        param.conn_param.private_data as *const u8,
                        param.conn_param.private_data_len as usize,
                    )
                };
                assert_eq!(stored_data, &[0xa5; 196]);
                assert_eq!(data[0], 0x5a);

                param.setup_private_data(&[]);
                assert!(param.conn_param.private_data.is_null());
                assert_eq!(param.conn_param.private_data_len, 0);

                Ok(())
            },
            Err(_) => Ok(()),
        }
    }

    #[test]
    fn test_socket_addr_and_port_from_raw() {
        let ipv4 = SocketAddr::from((std::net::Ipv4Addr::new(192, 0, 2, 1), 18515));
        let raw_ipv4 = OsSocketAddr::from(ipv4);
        assert_eq!(
            unsafe { socket_addr_from_raw(raw_ipv4.as_ptr().as_ref().unwrap()) },
            Some(ipv4)
        );
        assert_eq!(
            unsafe { port_from_raw_addr(raw_ipv4.as_ptr().as_ref().unwrap()) },
            18515
        );

        let ipv6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 18516));
        let raw_ipv6 = OsSocketAddr::from(ipv6);
        assert_eq!(
            unsafe { socket_addr_from_raw(raw_ipv6.as_ptr().as_ref().unwrap()) },
            Some(ipv6)
        );
        assert_eq!(
            unsafe { port_from_raw_addr(raw_ipv6.as_ptr().as_ref().unwrap()) },
            18516
        );

        let ib = SockAddrIb {
            sib_family: libc::AF_IB as _,
            sib_pkey: 0,
            sib_flowinfo: 0,
            sib_addr: [0; 16],
            sib_sid: u64::to_be(18517),
            sib_sid_mask: 0,
            sib_scope_id: 0,
        };
        let ib_addr = unsafe { &*(std::ptr::from_ref(&ib).cast::<libc::sockaddr>()) };
        assert_eq!(socket_addr_from_raw(ib_addr), None);
        assert_eq!(port_from_raw_addr(ib_addr), 18517);

        let unsupported = libc::sockaddr {
            sa_family: libc::AF_UNIX as _,
            sa_data: [0; 14],
        };
        assert_eq!(socket_addr_from_raw(&unsupported), None);
        assert_eq!(port_from_raw_addr(&unsupported), 0);
    }

    #[test]
    fn test_get_devices_smoke_and_cache() {
        let devices = match get_devices() {
            Ok(devices) => devices,
            Err(err) => {
                eprintln!("skipping RDMA CM get_devices smoke test: {err}");
                return;
            },
        };

        let second = get_devices().expect("second rdma_get_devices call should be consistent after first success");
        assert_eq!(devices.len(), second.len());
        for (first, second) in devices.iter().zip(second.iter()) {
            assert!(
                Arc::ptr_eq(first, second),
                "rdma_get_devices contexts should reuse the global DeviceContext cache"
            );
        }
    }

    #[test]
    fn test_connect_request_and_response_private_data() -> Result<(), Box<dyn std::error::Error>> {
        match EventChannel::new() {
            Ok(channel) => {
                let Some(cm_addr) = first_ib_or_roce_v2_gid_addr() else {
                    eprintln!(
                        "skipping RDMA CM private-data test: no usable IB GID or non-link-local RoCEv2 GID found"
                    );
                    return Ok(());
                };

                let listener = channel.create_id(PortSpace::Tcp)?;
                let port = 18515;
                let server_addr = cm_addr.socket_addr(port);
                let client_src_addr = cm_addr.socket_addr(0);
                listener.bind_addr(server_addr)?;
                listener.listen(1)?;

                // Generate some data with different pattern, keep the first byte zero to make IB happy
                let request_payload: [u8; CM_SETUP_PRIVATE_DATA_SIZE] = std::array::from_fn(|index| {
                    if index == 0 {
                        0
                    } else {
                        (index as u8).wrapping_mul(3).wrapping_add(1)
                    }
                });

                let response_payload: [u8; CM_SETUP_PRIVATE_DATA_SIZE] =
                    std::array::from_fn(|index| (index as u8).wrapping_mul(5).wrapping_add(3));

                let server = thread::spawn(move || -> Result<Vec<u8>, String> {
                    let event = channel.get_cm_event().map_err(|err| err.to_string())?;
                    assert_eq!(event.event_type(), EventType::ConnectRequest);

                    let request_private_data = event.private_data().to_vec();
                    let conn_id = event
                        .cm_id()
                        .ok_or_else(|| "CONNECT_REQUEST did not provide a child CM ID".to_owned())?;

                    let mut qp = create_test_qp(&conn_id)?;
                    move_test_qp_to_rts(&conn_id, &mut qp)?;

                    let mut accept_param = ConnectionParameter::default();
                    accept_param.setup_qp_number(qp.qp_number());
                    accept_param.setup_private_data(&response_payload);
                    conn_id.accept(accept_param).map_err(|err| err.to_string())?;
                    event.ack().map_err(|err| err.to_string())?;

                    let established = channel.get_cm_event().map_err(|err| err.to_string())?;
                    assert_eq!(established.event_type(), EventType::Established);
                    established.ack().map_err(|err| err.to_string())?;

                    Ok(request_private_data)
                });

                let client_channel = EventChannel::new()?;
                let client_id = client_channel.create_id(PortSpace::Tcp)?;
                client_id.resolve_addr(Some(client_src_addr), server_addr, Duration::from_secs(2))?;

                let mut client_qp = None;
                let response_private_data = loop {
                    let event = client_channel.get_cm_event()?;
                    match event.event_type() {
                        EventType::AddressResolved => {
                            assert_eq!(client_id.get_dst_port(), server_addr.port());
                            client_id.resolve_route(Duration::from_secs(2))?;
                            event.ack()?;
                        },
                        EventType::RouteResolved => {
                            let qp = create_test_qp(&client_id).map_err(io::Error::other)?;
                            let mut connect_param = ConnectionParameter::default();
                            connect_param.setup_qp_number(qp.qp_number());
                            connect_param.setup_private_data(&request_payload);
                            client_id.connect(connect_param)?;
                            client_qp = Some(qp);
                            event.ack()?;
                        },
                        EventType::ConnectResponse => {
                            let data = event.private_data().to_vec();
                            let qp = client_qp
                                .as_mut()
                                .expect("client QP must exist before CONNECT_RESPONSE");
                            move_test_qp_to_rts(&client_id, qp).map_err(io::Error::other)?;
                            client_id.establish()?;
                            event.ack()?;
                            break data;
                        },
                        event_type => panic!("unexpected client RDMA CM event: {event_type:?}"),
                    }
                };

                let request_private_data = server
                    .join()
                    .map_err(|panic| io::Error::other(format!("server thread panicked: {panic:?}")))?
                    .map_err(io::Error::other)?;

                // Valid field of private data from the RDMA CM event should be exactly the same as original data.
                assert_eq!(
                    &request_private_data[..CM_SETUP_PRIVATE_DATA_SIZE],
                    request_payload.as_slice()
                );
                assert_eq!(
                    &response_private_data[..CM_SETUP_PRIVATE_DATA_SIZE],
                    response_payload.as_slice()
                );

                // The left over should be all zero.
                assert!(request_private_data[CM_SETUP_PRIVATE_DATA_SIZE..]
                    .iter()
                    .all(|&byte| byte == 0));
                assert!(response_private_data[CM_SETUP_PRIVATE_DATA_SIZE..]
                    .iter()
                    .all(|&byte| byte == 0));

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
                let Some(cm_addr) = first_ib_or_roce_v2_gid_addr() else {
                    eprintln!(
                        "skipping RDMA CM device-context test: no usable IB GID or non-link-local RoCEv2 GID found"
                    );
                    return Ok(());
                };

                let id = channel.create_id(PortSpace::Tcp)?;

                if let Err(err) = id.resolve_addr(None, cm_addr.socket_addr(0), Duration::new(0, 200000000)) {
                    eprintln!("skipping RDMA CM device-context test: resolve_addr failed synchronously: {err}");
                    return Ok(());
                }

                let event = wait_for_cm_event(&channel, Duration::from_secs(2), "device context test")?;
                if event.event_type() != EventType::AddressResolved {
                    eprintln!(
                        "skipping RDMA CM device-context test: resolve_addr completed with {:?}",
                        event.event_type()
                    );
                    event.ack()?;
                    return Ok(());
                }

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
