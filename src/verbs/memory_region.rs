use rdma_mummy_sys::{ibv_dereg_mr, ibv_mr};
use std::{
    alloc::{handle_alloc_error, Layout},
    ptr::NonNull,
};

// This buffer definition is from arrow-buffer
#[derive(Clone, Debug)]
pub struct Buffer {
    pub data: NonNull<u8>,
    pub len: usize,
    _layout: Layout,
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
        Self { data, len, _layout: layout }
    }
}

pub struct MemoryRegion {
    pub buf: Buffer,
    pub mr_ptr: *mut ibv_mr,
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        unsafe {
            ibv_dereg_mr(self.mr_ptr);
        }
    }
}

impl MemoryRegion {
    pub fn get_lkey(&self) -> u32 {
        unsafe { (*self.mr_ptr).lkey }
    }

    pub fn get_rkey(&self) -> u32 {
        unsafe { (*self.mr_ptr).rkey }
    }
}
