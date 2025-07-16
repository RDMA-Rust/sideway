use sideway::ibverbs::device;

#[test]
#[allow(clippy::drop_non_drop)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();

        let comp_channel = ctx.create_comp_channel().unwrap();
        let mut builder = ctx.create_cq_builder();
        let cq = builder.setup_cqe(128).build().unwrap();
        let cq_ex = builder.setup_cqe(256).build_ex().unwrap();
        println!("comp_channel pointer is {comp_channel:?}");
        let comp_cq = builder.setup_comp_channel(&comp_channel, 0).build().unwrap();
        // show that the lifetime of CQ is associated with ctx, not builder
        drop(builder);
        println!("comp_cq pointer is {comp_cq:?}");
        println!("cq_ex pointer is {cq_ex:?}");
        drop(cq_ex);
        drop(comp_cq);
        // although cq theoretically does not depend on comp_channel, the rust compiler will still complain if we drop comp_channel here
        // drop(comp_channel);
        println!("cq pointer is {cq:?}");
    }

    Ok(())
}
