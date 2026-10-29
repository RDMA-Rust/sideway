#![allow(clippy::while_let_on_iterator)]

use core::time;
use std::thread;

use sideway::ibverbs::completion::{GenericCompletionQueue, WorkCompletionStatus};
use sideway::ibverbs::queue_pair::GenericQueuePair;
use sideway::ibverbs::shared_receive_queue::SharedReceiveQueueAttribute;
use sideway::ibverbs::{
    address::{AddressHandleAttribute, GidType},
    device::{self, DeviceInfo},
    device_context::{DeviceContext, Mtu},
    queue_pair::{
        PostSendGuard, QueuePair, QueuePairAttribute, QueuePairState, SetInlineData, SetScatterGatherEntry,
        WorkRequestFlags,
    },
    AccessFlags,
};

use rstest::rstest;

fn connect(ctx: &DeviceContext, qp: &mut GenericQueuePair, dest_qp_num: u32) {
    let mut attr = QueuePairAttribute::new();
    attr.setup_state(QueuePairState::Init)
        .setup_pkey_index(0)
        .setup_port(1)
        .setup_access_flags(AccessFlags::LocalWrite | AccessFlags::RemoteWrite);
    qp.modify(&attr).unwrap();

    let mut attr = QueuePairAttribute::new();
    attr.setup_state(QueuePairState::ReadyToReceive)
        .setup_path_mtu(Mtu::Mtu1024)
        .setup_dest_qp_num(dest_qp_num)
        .setup_rq_psn(1)
        .setup_max_dest_read_atomic(0)
        .setup_min_rnr_timer(0);
    let mut ah_attr = AddressHandleAttribute::new();
    let port_attr = ctx.query_port(1).unwrap();
    let gid_entries = ctx.query_gid_table().unwrap();
    let gid = gid_entries
        .iter()
        .find(|&&gid| {
            gid.port_num() == 1
                && (!gid.gid().is_unicast_link_local()
                    || gid.gid_type() == GidType::RoceV1
                    || gid.gid_type() == GidType::InfiniBand)
        })
        .unwrap();
    ah_attr
        .setup_dest_lid(port_attr.lid())
        .setup_port(1)
        .setup_service_level(1)
        .setup_grh_src_gid_index(gid.gid_index().try_into().unwrap())
        .setup_grh_dest_gid(&gid.gid())
        .setup_grh_hop_limit(64);
    attr.setup_address_vector(&ah_attr);
    qp.modify(&attr).unwrap();

    let mut attr = QueuePairAttribute::new();
    attr.setup_state(QueuePairState::ReadyToSend)
        .setup_sq_psn(1)
        .setup_timeout(12)
        .setup_retry_cnt(7)
        .setup_rnr_retry(7)
        .setup_max_read_atomic(0);
    qp.modify(&attr).unwrap();

    assert_eq!(QueuePairState::ReadyToSend, qp.state());
}

fn supports_srq(ctx: &DeviceContext) -> bool {
    let supported = ctx.query_device().unwrap().max_srq() > 0;
    if !supported {
        eprintln!("skipping {}: no SRQ support", ctx.name());
    }
    supported
}

#[test]
fn srq_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();
        if !supports_srq(&ctx) {
            continue;
        }
        let pd = ctx.alloc_pd().unwrap();

        let srq = pd
            .create_srq_builder()
            .setup_max_wr(32)
            .setup_max_sge(2)
            .build()
            .unwrap();

        let attr = srq.query().unwrap();
        // the provider is allowed to round the requested values up
        assert!(attr.max_wr() >= 32);
        assert!(attr.max_sge() >= 2);
        assert_eq!(attr.srq_limit(), 0);

        // arming the limit while fewer WRs than the limit are posted fires
        // IBV_EVENT_SRQ_LIMIT_REACHED right away on some devices (e.g. mlx5), which disarms it
        // back to 0, so post more WRs than the limit first
        let mut recv_data: Vec<u8> = vec![0; 64 * 8];
        let recv_mr = unsafe {
            pd.reg_mr(recv_data.as_ptr() as _, recv_data.len(), AccessFlags::LocalWrite)
                .unwrap()
        };
        let mut guard = srq.start_post_recv();
        for i in 0..8 {
            unsafe {
                guard
                    .construct_wr(i)
                    .setup_sge(recv_mr.lkey(), recv_data.as_mut_ptr().add(64 * i as usize) as _, 64);
            }
        }
        guard.post().unwrap();

        let mut attr = SharedReceiveQueueAttribute::new();
        attr.setup_srq_limit(4);
        srq.modify(&attr).unwrap();
        assert_eq!(srq.query().unwrap().srq_limit(), 4);
    }

    Ok(())
}

#[rstest]
#[case(true, true)]
#[case(false, true)]
#[case(true, false)]
#[case(false, false)]
fn srq_shared_by_two_qps(#[case] use_qp_ex: bool, #[case] use_cq_ex: bool) -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();
        if !supports_srq(&ctx) {
            continue;
        }
        let pd = ctx.alloc_pd().unwrap();

        let mut recv_data: Vec<u8> = vec![0; 128];
        let recv_mr = unsafe {
            pd.reg_mr(recv_data.as_ptr() as _, recv_data.len(), AccessFlags::LocalWrite)
                .unwrap()
        };

        let mut cq_builder = ctx.create_cq_builder();
        cq_builder.setup_cqe(128);
        let sq = if use_cq_ex {
            GenericCompletionQueue::from(cq_builder.build_ex().unwrap())
        } else {
            GenericCompletionQueue::from(cq_builder.build().unwrap())
        };
        let rq = if use_cq_ex {
            GenericCompletionQueue::from(cq_builder.build_ex().unwrap())
        } else {
            GenericCompletionQueue::from(cq_builder.build().unwrap())
        };

        let srq = pd
            .create_srq_builder()
            .setup_max_wr(16)
            .setup_max_sge(1)
            .build()
            .unwrap();

        let mut builder = pd.create_qp_builder();
        builder
            .setup_max_inline_data(64)
            .setup_send_cq(sq.clone())
            .setup_recv_cq(rq.clone())
            .setup_shared_receive_queue(&srq);

        let build = |builder: &sideway::ibverbs::queue_pair::QueuePairBuilder| -> GenericQueuePair {
            if use_qp_ex {
                builder.build_ex().unwrap().into()
            } else {
                builder.build().unwrap().into()
            }
        };
        let mut qp_a = build(&builder);
        let mut qp_b = build(&builder);
        drop(builder);

        // both QPs now hold a reference to the SRQ
        assert_eq!(std::sync::Arc::strong_count(&srq), 3);

        let (qp_a_num, qp_b_num) = (qp_a.qp_number(), qp_b.qp_number());
        connect(&ctx, &mut qp_a, qp_b_num);
        connect(&ctx, &mut qp_b, qp_a_num);

        // post two recv buffers into the SRQ, one for each QP's incoming message
        let mut guard = srq.start_post_recv();
        unsafe {
            guard
                .construct_wr(1)
                .setup_sge(recv_mr.lkey(), recv_data.as_mut_ptr() as _, 64);
            guard
                .construct_wr(2)
                .setup_sge(recv_mr.lkey(), recv_data.as_mut_ptr().byte_add(64) as _, 64);
        }
        guard.post().unwrap();

        // A sends to B, then B sends to A, both messages land in the SRQ buffers
        for (qp, msg) in [(&mut qp_a, b"from A"), (&mut qp_b, b"from B")] {
            let mut guard = qp.start_post_send();
            guard
                .construct_wr(100, WorkRequestFlags::Signaled | WorkRequestFlags::Inline)
                .setup_send()
                .setup_inline_data(msg);
            guard.post().unwrap();
            thread::sleep(time::Duration::from_millis(10));
        }

        let mut sent = 0;
        {
            let mut poller = sq.start_poll().unwrap();
            while let Some(wc) = poller.next() {
                assert_eq!(wc.status(), WorkCompletionStatus::Success as u32);
                sent += 1;
            }
        }
        assert_eq!(sent, 2);

        let mut received = Vec::new();
        {
            let mut poller = rq.start_poll().unwrap();
            while let Some(wc) = poller.next() {
                assert_eq!(wc.status(), WorkCompletionStatus::Success as u32);
                assert_eq!(wc.byte_len(), 6);
                received.push(wc.wr_id());
            }
        }
        received.sort();
        assert_eq!(received, vec![1, 2]);

        // which QP consumes which SRQ buffer depends on the order the messages arrive in, so only
        // check that each message landed in one of the buffers
        let mut payloads = [&recv_data[..6], &recv_data[64..70]];
        payloads.sort();
        assert_eq!(payloads, [b"from A", b"from B"]);

        drop(qp_a);
        drop(qp_b);
        assert_eq!(std::sync::Arc::strong_count(&srq), 1);
    }

    Ok(())
}
