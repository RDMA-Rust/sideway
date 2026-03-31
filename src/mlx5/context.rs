use rdma_mummy_sys::mlx5dv;
use std::sync::Arc;

use crate::ibverbs::device_context::DeviceContext;

/// mlx5 device context providing vendor-specific capabilities.
pub struct Mlx5Context {
    dev_ctx: Arc<DeviceContext>,
}

impl Mlx5Context {
    /// Wrap an existing DeviceContext to access mlx5 extensions.
    pub fn new(dev_ctx: Arc<DeviceContext>) -> Self {
        Self { dev_ctx }
    }

    /// Query mlx5 device capabilities including DC support.
    pub fn query_device(&self) -> Result<Mlx5DeviceAttrs, std::io::Error> {
        let mut attrs: mlx5dv::mlx5dv_context = unsafe { std::mem::zeroed() };
        attrs.comp_mask = (mlx5dv::MLX5DV_CONTEXT_MASK_DC_ODP_CAPS
            | mlx5dv::MLX5DV_CONTEXT_MASK_DCI_STREAMS
            | mlx5dv::MLX5DV_CONTEXT_MASK_MAX_DC_RD_ATOM) as u64;

        let ret = unsafe { mlx5dv::mlx5dv_query_device(self.dev_ctx.context.as_ptr().cast(), &mut attrs) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Mlx5DeviceAttrs {
            max_dc_rd_atom: attrs.max_dc_rd_atom,
            flags: attrs.flags,
        })
    }

    pub(crate) fn dev_ctx(&self) -> &Arc<DeviceContext> {
        &self.dev_ctx
    }
}

/// mlx5 device attributes.
pub struct Mlx5DeviceAttrs {
    pub max_dc_rd_atom: u64,
    pub flags: u64,
}
