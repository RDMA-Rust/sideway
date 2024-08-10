use sideway::verbs::device;
use tabled::{
    settings::{object::Segment, Alignment, Modify},
    Table, Tabled,
};

#[derive(Tabled)]
struct IbDevice {
    #[tabled(rename = "device")]
    name: String,
    #[tabled(rename = "node GUID")]
    guid: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut devices: Vec<IbDevice> = Vec::new();

    let device_list = device::DeviceList::new()?;
    for device_ptr in device_list.iter() {
        let dev = device::Device::new(device_ptr);

        if let Some(name) = dev.name() {
            devices.push(IbDevice { name, guid: dev.guid() });
        } else {
            eprintln!("Found a device without a name, skipping.");
        }
    }

    let table = Table::new(devices)
        .with(Modify::new(Segment::all()).with(Alignment::center()))
        .to_string();

    println!("{}", table);

    Ok(())
}
