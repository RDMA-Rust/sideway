use sideway::ibverbs::{
    address::AddressHandle,
    queue_pair::{PostSendGuard, WorkRequestFlags},
};

fn address_before_send<G: PostSendGuard>(guard: &mut G, ah: &AddressHandle) {
    unsafe {
        guard.construct_wr(1, WorkRequestFlags::Signaled).setup_ud_addr(ah, 1, 1);
    }
}

fn main() {}
