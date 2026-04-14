//! Sideway is a Rust wrapper over [rdma-core]
//!
//! [rdma-core]: https://github.com/linux-rdma/rdma-core

/// The wrapper over [libibverbs](https://github.com/linux-rdma/rdma-core/tree/master/libibverbs),
/// which provides the basic operations for resources creation and data send / receive.
pub mod ibverbs;

/// The wrapper over [librdmacm](https://github.com/linux-rdma/rdma-core/tree/master/librdmacm),
/// which is the in-band (compared to TCP, which is out-of-band) connection manager for RDMA.
pub mod rdmacm;

/// mlx5 vendor-specific extensions (DC transport, etc.).
/// Requires `--features mlx5` and ConnectX-4+ hardware.
#[cfg(feature = "mlx5")]
pub mod mlx5;
