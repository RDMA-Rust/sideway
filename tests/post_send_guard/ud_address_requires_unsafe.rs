use sideway::ibverbs::{
    address::AddressHandle,
    queue_pair::{PostSendGuard, WorkRequestFlags},
};

fn address_without_lifetime_guarantee<G: PostSendGuard>(guard: &mut G, ah: &AddressHandle) {
    guard
        .construct_wr(1, WorkRequestFlags::Signaled)
        .setup_send()
        .setup_ud_addr(ah, 1, 1);
}

fn main() {}
