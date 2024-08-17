use sideway::verbs::completion_queue;
use sideway::verbs::device;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device_ptr in device_list.iter() {
        let dev = device::Device::new(device_ptr);
        let ctx = dev.open().unwrap();

        let mut builder = completion_queue::ExtendedCompletionQueueBuilder::new(&ctx);
        let cq1 = builder.setup_cqe(128).build().unwrap();
        let cq2 = builder.setup_cqe(256).build().unwrap();
        // show that the lifetime of CQ is associated with ctx, not builder
        drop(builder);
        println!("CQ 2 pointer is {:?}", cq2);
        drop(cq2);
        println!("CQ 1 pointer is {:?}", cq1);
    }

    Ok(())
}
