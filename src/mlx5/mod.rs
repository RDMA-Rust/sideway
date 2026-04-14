//! mlx5 vendor-specific extensions for RDMA.
//!
//! Provides DC (Dynamically Connected) transport, which enables scalable RDMA
//! without per-peer QP setup. Requires ConnectX-4+ hardware.
//!
//! # DC Transport
//!
//! - **DCI (DC Initiator)**: Client-side QP that can talk to any DCT on any node
//! - **DCT (DC Target)**: Server-side QP that accepts from any DCI
//! - Per-WR addressing via `wr_set_dc_addr()`
//! - N nodes need 1 DCT + W DCIs per node (vs N×C QPs with RC)

mod context;
pub mod dc;

pub use context::Mlx5Context;
pub use dc::{DcInitiator, DcTarget, DcType};
