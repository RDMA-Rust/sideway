use super::protection_domain::ProtectionDomain;
use rdma_mummy_sys::{ibv_dereg_mr, ibv_mr};
use std::{
    alloc::{dealloc, handle_alloc_error, Layout},
    marker::PhantomData,
    ptr::NonNull,
};

// This buffer definition is from arrow-buffer
#[derive(Clone, Debug)]
pub struct Buffer {
    pub data: NonNull<u8>,
    pub len: usize,
    layout: Layout,
}

impl Buffer {
    #[inline]
    pub fn from_len_zeroed(len: usize) -> Self {
        let layout = Layout::from_size_align(len, 8).unwrap();
        let data = match layout.size() {
            0 => panic!(),
            _ => {
                let raw_ptr = unsafe { std::alloc::alloc_zeroed(layout) };
                NonNull::new(raw_ptr).unwrap_or_else(|| handle_alloc_error(layout))
            },
        };
        Self { data, len, layout }
    }
}

#[derive(Debug)]
pub struct MemoryRegion<'pd> {
    pub buf: Buffer,
    mr: NonNull<ibv_mr>,
    _pd: PhantomData<&'pd ()>,
}

impl Drop for MemoryRegion<'_> {
    fn drop(&mut self) {
        unsafe {
            ibv_dereg_mr(self.mr.as_mut());
            dealloc(self.buf.data.as_mut(), self.buf.layout);
        }
    }
}

impl MemoryRegion<'_> {
    pub(crate) fn new<'pd>(_pd: &'pd ProtectionDomain<'pd>, buf: Buffer, mr: NonNull<ibv_mr>) -> MemoryRegion<'pd> {
        MemoryRegion {
            buf,
            mr,
            _pd: PhantomData,
        }
    }

    pub fn lkey(&self) -> u32 {
        unsafe { self.mr.as_ref().lkey }
    }

    pub fn rkey(&self) -> u32 {
        unsafe { self.mr.as_ref().rkey }
    }
}
