use sideway::verbs::device;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();

        let pd = ctx.alloc_pd().unwrap();
        let mr = pd.reg_managed_mr(64).unwrap();

        let comp_channel = ctx.create_comp_channel().unwrap();
        let mut cq_builder = ctx.create_cq_builder();
        let sq = cq_builder.setup_cqe(128).build().unwrap();
        let rq = cq_builder.setup_cqe(128).build().unwrap();

        let mut builder = pd.create_qp_builder();

        let qp = builder
            .setup_max_inline_data(128)
            .setup_send_cq(&sq)
            .setup_recv_cq(&rq)
            .build()
            .unwrap();

        println!("qp pointer is {:?}", qp);
    }

    Ok(())
}
