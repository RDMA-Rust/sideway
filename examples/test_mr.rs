use sideway::verbs::device;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device_ptr in device_list.iter() {
        let dev = device::Device::new(device_ptr);
        let ctx = dev.open().unwrap();

        let pd = ctx.alloc_pd().unwrap();
        let mr = pd.reg_managed_mr(64).unwrap();
        let cq = ctx.create_cq(32).unwrap();

        println!(
            "MR pointer is {:?}, lkey is {}, rkey is {}",
            mr.mr_ptr,
            mr.lkey(),
            mr.rkey()
        );

        println!("CQ pointer is {:?}", cq,);
    }

    Ok(())
}
