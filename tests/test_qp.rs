use sideway::ibverbs::{
    address::{AddressHandleAttribute, GidType},
    device,
    device_context::Mtu,
    queue_pair::{QueuePair, QueuePairAttribute, QueuePairState},
    AccessFlags,
};

#[test]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();

        let pd = ctx.alloc_pd().unwrap();
        let data: Vec<u8> = vec![0; 64];
        let _mr = unsafe {
            pd.reg_mr(
                data.as_ptr() as _,
                data.len(),
                AccessFlags::LocalWrite | AccessFlags::RemoteWrite,
            )
            .unwrap()
        };

        let _comp_channel = ctx.create_comp_channel().unwrap();
        let mut cq_builder = ctx.create_cq_builder();
        let sq = cq_builder.setup_cqe(128).build().unwrap();
        let rq = cq_builder.setup_cqe(128).build().unwrap();

        let mut builder = pd.create_qp_builder();

        let mut qp = builder
            .setup_max_inline_data(128)
            .setup_send_cq(&sq)
            .setup_recv_cq(&rq)
            .build()
            .unwrap();

        println!("qp pointer is {qp:?}");
        // modify QP to INIT state
        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::Init)
            .setup_pkey_index(0)
            .setup_port(1)
            .setup_access_flags(AccessFlags::LocalWrite | AccessFlags::RemoteWrite);
        qp.modify(&attr).unwrap();

        assert_eq!(QueuePairState::Init, qp.state());

        // modify QP to RTR state
        let mut attr = QueuePairAttribute::new();
        attr.setup_state(QueuePairState::ReadyToReceive)
            .setup_path_mtu(Mtu::Mtu1024)
            .setup_dest_qp_num(12345)
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
    }

    Ok(())
}
