#![allow(clippy::while_let_on_iterator)]

use core::time;
use std::{io::IoSlice, thread};

use sideway::ibverbs::completion::GenericCompletionQueue;
use sideway::ibverbs::queue_pair::GenericQueuePair;
use sideway::ibverbs::{
    address::{AddressHandleAttribute, GidType},
    device,
    device_context::Mtu,
    queue_pair::{
        PostSendGuard, QueuePair, QueuePairAttribute, QueuePairState, SetInlineData, SetScatterGatherEntry,
        WorkRequestFlags,
    },
    AccessFlags,
};

use rstest::rstest;

#[rstest]
#[case(true, true)]
#[case(false, true)]
#[case(true, false)]
#[case(false, false)]
fn main(#[case] use_qp_ex: bool, #[case] use_cq_ex: bool) -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();

        let pd = ctx.alloc_pd().unwrap();
        let send_data: Vec<u8> = vec![0; 64];
        let mut recv_data: Vec<u8> = vec![0; 64];
        let mr = unsafe {
            pd.reg_mr(
                send_data.as_ptr() as _,
                send_data.len(),
                AccessFlags::LocalWrite | AccessFlags::RemoteWrite,
            )
            .unwrap()
        };
        let recv_mr = unsafe {
            pd.reg_mr(
                recv_data.as_ptr() as _,
                recv_data.len(),
                AccessFlags::LocalWrite | AccessFlags::RemoteWrite,
            )
            .unwrap()
        };

        let _comp_channel = ctx.create_comp_channel().unwrap();
        let mut cq_builder = ctx.create_cq_builder();
        cq_builder.setup_cqe(128);
        let sq: GenericCompletionQueue = if use_cq_ex {
            cq_builder.build_ex().unwrap().into()
        } else {
            cq_builder.build().unwrap().into()
        };
        let rq: GenericCompletionQueue = if use_cq_ex {
            cq_builder.build_ex().unwrap().into()
        } else {
            cq_builder.build().unwrap().into()
        };

        let mut builder = pd.create_qp_builder();
        builder.setup_max_inline_data(128).setup_send_cq(&sq).setup_recv_cq(&rq);

        let mut qp: GenericQueuePair = if use_qp_ex {
            builder.build_ex().unwrap().into()
        } else {
            builder.build().unwrap().into()
        };

        println!("qp pointer is {qp:?}");
        // modify QP to INIT state
        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::Init)
            .setup_pkey_index(0)
            .setup_port(1)
            .setup_access_flags(AccessFlags::LocalWrite | AccessFlags::RemoteWrite);
        qp.modify(&attr).unwrap();

        assert_eq!(QueuePairState::Init, qp.state());

        // modify QP to RTR state, set dest qp as itself
        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::ReadyToReceive)
            .setup_path_mtu(Mtu::Mtu1024)
            .setup_dest_qp_num(qp.qp_number())
            .setup_rq_psn(1)
            .setup_max_dest_read_atomic(0)
            .setup_min_rnr_timer(0);
        // setup address vector
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
            .setup_max_read_atomic(0);

        qp.modify(&attr).unwrap();

        assert_eq!(QueuePairState::ReadyToSend, qp.state());

        // post one recv buf to the qp
        let mut guard = qp.start_post_recv();
        let recv_handle = guard.construct_wr(114514);
        unsafe { recv_handle.setup_sge(recv_mr.lkey(), recv_data.as_mut_ptr() as _, recv_data.len() as _) };
        guard.post().unwrap();

        let mut guard = qp.start_post_send();
        let buf = vec![0, 1, 2, 3];

        let write_handle = guard
            .construct_wr(233, WorkRequestFlags::Signaled)
            .setup_write(mr.rkey(), send_data.as_ptr() as _);

        write_handle.setup_inline_data(&buf);

        // it's safe for users to drop the inline buffer after they calling setup inline data
        drop(buf);

        let buf = vec![vec![b'H', b'e', b'l', b'l', b'o'], vec![b'R', b'D', b'M', b'A']];

        let write_handle = unsafe {
            guard
                .construct_wr(234, WorkRequestFlags::Signaled)
                .setup_write(mr.rkey(), send_data.as_ptr().byte_add(4) as _)
        };

        write_handle.setup_inline_data_list(&[IoSlice::new(buf[0].as_ref()), IoSlice::new(buf[1].as_ref())]);

        // use SEND to transmit the same data
        let send_handle = guard.construct_wr(567, WorkRequestFlags::Signaled).setup_send();
        send_handle.setup_inline_data_list(&[IoSlice::new(buf[0].as_ref()), IoSlice::new(buf[1].as_ref())]);

        // it's safe for users to drop the inline buffer after they calling setup inline data
        drop(buf);

        guard.post().unwrap();

        thread::sleep(time::Duration::from_millis(10));

        // poll send CQ for the completion
        {
            let mut poller = sq.start_poll().unwrap();
            while let Some(wc) = poller.next() {
                println!("wr_id {}, status: {}, opcode: {}", wc.wr_id(), wc.status(), wc.opcode())
            }
        }

        unsafe {
            let slice = std::slice::from_raw_parts(mr.get_ptr() as *const u8, mr.region_len());
            println!("Buffer contents: {slice:?}");
        }

        // poll recv CQ for the completion
        {
            let mut poller = rq.start_poll().unwrap();
            while let Some(wc) = poller.next() {
                println!("wr_id {}, status: {}, opcode: {}", wc.wr_id(), wc.status(), wc.opcode())
            }
        }

        unsafe {
            let slice = std::slice::from_raw_parts(recv_mr.get_ptr() as *const u8, recv_mr.region_len());
            println!("Recv Buffer contents: {slice:?}");
        }
    }

    Ok(())
}
