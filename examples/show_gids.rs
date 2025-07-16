use std::net::{Ipv4Addr, Ipv6Addr};

use sideway::ibverbs::{
    address::{Gid, GidType},
    device,
    device::DeviceInfo,
};
use tabled::{
    settings::{object::Segment, Alignment, Modify, Style},
    Table, Tabled,
};

#[derive(Tabled)]
struct GidEntries {
    #[tabled(rename = "Dev")]
    dev_name: String,
    #[tabled(rename = "Port")]
    port: u32,
    #[tabled(rename = "Index")]
    index: i32,
    #[tabled(rename = "GID")]
    gid: Gid,
    #[tabled(rename = "IPv4", display = "display_ipv4")]
    ipv4: Option<Ipv4Addr>,
    #[tabled(rename = "Ver")]
    ver: &'static str,
    #[tabled(rename = "Netdev")]
    netdev: String,
}

fn display_ipv4(ipv4: &Option<Ipv4Addr>) -> String {
    match ipv4 {
        Some(addr) => format!("{addr}"),
        None => String::new(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut devices: Vec<GidEntries> = Vec::new();

    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        let ctx = device.open().unwrap();

        let name = device.name();

        let gid_entries = ctx.query_gid_table().unwrap();

        for gid in gid_entries {
            devices.push(GidEntries {
                dev_name: name.clone(),
                port: gid.port_num(),
                index: gid.gid_index() as _,
                gid: gid.gid(),
                ipv4: Ipv6Addr::from(gid.gid()).to_ipv4_mapped(),
                ver: match gid.gid_type() {
                    GidType::InfiniBand => "IB",
                    GidType::RoceV1 => "RoCEv1",
                    GidType::RoceV2 => "RoCEv2",
                },
                netdev: gid.netdev_name().unwrap(),
            });
        }
    }

    let style = Style::psql().remove_verticals();

    let table = Table::new(devices)
        .with(Modify::new(Segment::all()).with(Alignment::center()))
        .with(style)
        .to_string();

    println!("{table}");

    Ok(())
}
