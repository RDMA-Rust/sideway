#![allow(clippy::while_let_on_iterator)]

use core::time;
use std::thread;

use sideway::ibverbs::completion::GenericCompletionQueue;
use sideway::ibverbs::queue_pair::{GenericQueuePair, SendOperationFlags};
use sideway::ibverbs::{
    address::{AddressHandleAttribute, GidType},
    device,
    device_context::Mtu,
    queue_pair::{
        PostSendGuard, QueuePair, QueuePairAttribute, QueuePairState, SetScatterGatherEntry, WorkRequestFlags,
    },
    AccessFlags,
};

use rstest::rstest;

#[rstest]
#[case(true)]
#[case(false)]
fn main(#[case] use_qp_ex: bool) -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();

        let pd = ctx.alloc_pd().unwrap();

        // Atomic operations work on 8-byte values and require 8-byte alignment.
        let mut remote_val: u64 = 42;
        let mut local_buf: u64 = 0;

        let mr = unsafe {
            pd.reg_mr(
                &mut remote_val as *mut u64 as _,
                std::mem::size_of::<u64>(),
                AccessFlags::LocalWrite
                    | AccessFlags::RemoteWrite
                    | AccessFlags::RemoteRead
                    | AccessFlags::RemoteAtomic,
            )
            .unwrap()
        };
        let local_mr = unsafe {
            pd.reg_mr(
                &mut local_buf as *mut u64 as _,
                std::mem::size_of::<u64>(),
                AccessFlags::LocalWrite,
            )
            .unwrap()
        };

        let mut cq_builder = ctx.create_cq_builder();
        cq_builder.setup_cqe(128);
        let sq = GenericCompletionQueue::from(cq_builder.build_ex().unwrap());
        let rq = GenericCompletionQueue::from(cq_builder.build_ex().unwrap());

        let mut builder = pd.create_qp_builder();
        builder
            .setup_max_inline_data(0)
            .setup_send_cq(sq.clone())
            .setup_recv_cq(rq.clone())
            .setup_send_ops_flags(SendOperationFlags::AtomicCompareAndSwap | SendOperationFlags::AtomicFetchAndAdd);

        let mut qp: GenericQueuePair = if use_qp_ex {
            builder.build_ex().unwrap().into()
        } else {
            builder.build().unwrap().into()
        };

        // modify QP to INIT state
        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::Init)
            .setup_pkey_index(0)
            .setup_port(1)
            .setup_access_flags(
                AccessFlags::LocalWrite
                    | AccessFlags::RemoteWrite
                    | AccessFlags::RemoteRead
                    | AccessFlags::RemoteAtomic,
            );
        qp.modify(&attr).unwrap();
        assert_eq!(QueuePairState::Init, qp.state());

        // modify QP to RTR state, set dest qp as itself (loopback)
        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::ReadyToReceive)
            .setup_path_mtu(Mtu::Mtu1024)
            .setup_dest_qp_num(qp.qp_number())
            .setup_rq_psn(1)
            .setup_max_dest_read_atomic(1)
            .setup_min_rnr_timer(0);

        let mut ah_attr = AddressHandleAttribute::new();
        let gid_entries = ctx.query_gid_table().unwrap();
        let gid = gid_entries
            .iter()
            .find(|&&gid| !gid.gid().is_unicast_link_local() || gid.gid_type() == GidType::RoceV1)
            .unwrap();

        ah_attr
            .setup_dest_lid(1)
            .setup_port(1)
            .setup_service_level(1)
            .setup_grh_src_gid_index(gid.gid_index().try_into().unwrap())
            .setup_grh_dest_gid(&gid.gid())
            .setup_grh_hop_limit(64);
        attr.setup_address_vector(&ah_attr);
        qp.modify(&attr).unwrap();
        assert_eq!(QueuePairState::ReadyToReceive, qp.state());

        // modify QP to RTS state
        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::ReadyToSend)
            .setup_sq_psn(1)
            .setup_timeout(12)
            .setup_retry_cnt(7)
            .setup_rnr_retry(7)
            .setup_max_read_atomic(1);
        qp.modify(&attr).unwrap();
        assert_eq!(QueuePairState::ReadyToSend, qp.state());

        // --- Test 1: Atomic Compare-and-Swap ---
        // remote_val is 42. CAS(compare=42, swap=100) should succeed,
        // setting remote_val to 100 and returning the old value (42) in local_buf.
        {
            let mut guard = qp.start_post_send();
            let wr_handle = guard
                .construct_wr(1, WorkRequestFlags::Signaled)
                .setup_atomic_compare_swap(mr.rkey(), &remote_val as *const u64 as u64, 42, 100);
            unsafe {
                wr_handle.setup_sge(local_mr.lkey(), &local_buf as *const u64 as u64, 8);
            }
            guard.post().unwrap();

            let mut wc_found = false;
            for _ in 0..100 {
                if let Ok(mut poller) = sq.start_poll() {
                    if let Some(wc) = poller.next() {
                        assert_eq!(wc.status(), 0, "CAS failed with status: {}", wc.status());
                        wc_found = true;
                        break;
                    }
                }
                thread::sleep(time::Duration::from_millis(10));
            }
            assert!(wc_found, "Timed out waiting for CAS completion");
            assert_eq!(remote_val, 100);
            assert_eq!(local_buf, 42);
        }

        // --- Test 2: Atomic Fetch-and-Add ---
        // remote_val should now be 100. Fetch-and-add(7) should set it to 107 and
        // return the old value (100) in local_buf.
        {
            let mut guard = qp.start_post_send();
            let wr_handle = guard
                .construct_wr(2, WorkRequestFlags::Signaled)
                .setup_atomic_fetch_add(mr.rkey(), &remote_val as *const u64 as u64, 7);
            unsafe {
                wr_handle.setup_sge(local_mr.lkey(), &local_buf as *const u64 as u64, 8);
            }
            guard.post().unwrap();

            let mut wc_found = false;
            for _ in 0..100 {
                if let Ok(mut poller) = sq.start_poll() {
                    if let Some(wc) = poller.next() {
                        assert_eq!(wc.status(), 0, "FAA failed with status: {}", wc.status());
                        wc_found = true;
                        break;
                    }
                }
                thread::sleep(time::Duration::from_millis(10));
            }
            assert!(wc_found, "Timed out waiting for FAA completion");
            assert_eq!(remote_val, 107);
            assert_eq!(local_buf, 100);
        }
    }

    Ok(())
}
