use sideway::verbs::completion;
use sideway::verbs::device;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();

        let mut pd = ctx.alloc_pd().unwrap();
        let mr = pd.reg_managed_mr(64).unwrap();
        let mut builder = completion::CompletionQueueBuilder::new(&ctx);
        let cq = builder.setup_cqe(32).build().unwrap();

        println!("MR is {:?}, lkey is {}, rkey is {}", mr, mr.lkey(), mr.rkey());

        println!("CQ is {:?}", cq,);
    }

    Ok(())
}
