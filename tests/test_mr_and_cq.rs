use sideway::ibverbs::{device, AccessFlags};
use std::fs::File;
use std::os::fd::AsRawFd;

#[test]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();

        let pd = ctx.alloc_pd().unwrap();
        let data: Vec<u8> = vec![0; 64];
        let mr = unsafe {
            pd.reg_mr(
                data.as_ptr() as _,
                data.len(),
                AccessFlags::LocalWrite | AccessFlags::RemoteWrite,
            )
            .unwrap()
        };
        let dmabuf = File::open("/dev/null")?;
        let dmabuf_result = unsafe {
            pd.reg_dmabuf_mr(
                0,
                data.len(),
                0,
                dmabuf.as_raw_fd(),
                AccessFlags::LocalWrite | AccessFlags::RemoteWrite,
            )
        };
        assert!(dmabuf_result.is_err(), "expected /dev/null registration to fail");
        let mut builder = ctx.create_cq_builder();
        let cq = builder.setup_cqe(32).build().unwrap();

        println!("MR is {:?}, lkey is {}, rkey is {}", mr, mr.lkey(), mr.rkey());

        println!("CQ is {cq:?}");
    }

    Ok(())
}
