use std::marker::PhantomData;
use std::ptr::NonNull;

use rdma_mummy_sys::{ibv_comp_channel, ibv_create_comp_channel, ibv_destroy_comp_channel};

use super::device_context::DeviceContext;

#[derive(Debug)]
pub struct CompletionChannel<'ctx> {
    pub(crate) channel: NonNull<ibv_comp_channel>,
    // phantom data for device context
    _phantom: PhantomData<&'ctx DeviceContext>,
}

impl Drop for CompletionChannel<'_> {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_comp_channel(self.channel.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

impl<'ctx> CompletionChannel<'ctx> {
    pub fn new(dev_ctx: &'ctx DeviceContext) -> Result<CompletionChannel<'ctx>, String> {
        let comp_channel = unsafe { ibv_create_comp_channel(dev_ctx.context) };
        Ok(CompletionChannel {
            channel: NonNull::new(comp_channel).ok_or(String::from("ibv_create_comp_channel failed"))?,
            _phantom: PhantomData,
        })
    }
}
