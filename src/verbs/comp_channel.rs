use std::{marker::PhantomData, ptr};

use rdma_mummy_sys::{ibv_comp_channel, ibv_create_comp_channel, ibv_destroy_comp_channel};

use super::rdma_context::RdmaContext;

#[derive(Debug)]
pub struct CompletionChannel<'ctx> {
    pub(crate) channel: ptr::NonNull<ibv_comp_channel>,
    // phantom data for device context
    _dev_ctx: PhantomData<&'ctx RdmaContext>,
}

impl<'ctx> Drop for CompletionChannel<'ctx> {
    fn drop(&mut self) {
        let ret = unsafe { ibv_destroy_comp_channel(self.channel.as_ptr()) };
        assert_eq!(ret, 0);
    }
}

impl<'ctx> CompletionChannel<'ctx> {
    pub fn new<'a>(dev_ctx: &'a RdmaContext) -> Result<CompletionChannel<'a>, String> {
        let comp_channel = unsafe { ibv_create_comp_channel(dev_ctx.context) };
        Ok(CompletionChannel {
            channel: ptr::NonNull::new(comp_channel).ok_or(String::from("ibv_create_comp_channel failed"))?,
            _dev_ctx: PhantomData,
        })
    }
}
