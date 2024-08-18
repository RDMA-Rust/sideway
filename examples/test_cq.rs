use sideway::verbs::completion;
use sideway::verbs::device;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();

        let comp_channel = completion::CompletionChannel::new(&ctx).unwrap();
        let mut builder = completion::CompletionQueueBuilder::new(&ctx);
        let cq = builder.setup_cqe(128).build().unwrap();
        let cq_ex = builder.setup_cqe(256).build_ex().unwrap();
        println!("comp_channel pointer is {:?}", comp_channel);
        let comp_cq = builder.setup_comp_channel(&comp_channel, 2).build().unwrap();
        // show that the lifetime of CQ is associated with ctx, not builder
        drop(builder);
        println!("comp_cq pointer is {:?}", comp_cq);
        println!("cq_ex pointer is {:?}", cq_ex);
        drop(cq_ex);
        drop(comp_cq);
        // although cq theoretically does not depend on comp_channel, the rust compiler will still complain if we drop comp_channel here
        // drop(comp_channel);
        println!("cq pointer is {:?}", cq);
    }

    Ok(())
}
