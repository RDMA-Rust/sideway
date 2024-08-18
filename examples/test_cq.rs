use sideway::verbs::completion_queue;
use sideway::verbs::device;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device_ptr in device_list.iter() {
        let dev = device::Device::new(device_ptr);
        let ctx = dev.open().unwrap();

        let mut builder = completion_queue::CompletionQueueBuilder::new(&ctx);
        let cq = builder.setup_cqe(128).build().unwrap();
        let cq_ex = builder.setup_cqe(256).build_ex().unwrap();
        // show that the lifetime of CQ is associated with ctx, not builder
        drop(builder);
        println!("cq_ex pointer is {:?}", cq_ex);
        drop(cq_ex);
        println!("cq pointer is {:?}", cq);
    }

    Ok(())
}
