use std::{
    fs,
    net::{Ipv4Addr, Ipv6Addr},
};

use sideway::verbs::{address_handle::Gid, device};
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
    #[tabled(rename = "IPv4", display_with = "display_ipv4")]
    ipv4: Option<Ipv4Addr>,
    #[tabled(rename = "Ver")]
    ver: &'static str,
    #[tabled(rename = "Netdev")]
    netdev: String,
}

fn display_ipv4(ipv4: &Option<Ipv4Addr>) -> String {
    match ipv4 {
        Some(addr) => format!("{addr}"),
        None => format!(""),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut devices: Vec<GidEntries> = Vec::new();

    let device_list = device::DeviceList::new()?;
    for device_ptr in device_list.iter() {
        let dev = device::Device::new(device_ptr);
        let ctx = dev.open().unwrap();

        let dev_attr = ctx.query_device().unwrap();

        for port_num in 1..(dev_attr.phys_port_cnt() + 1) {
            let port_attr = ctx.query_port(port_num).unwrap();

            if let Some(name) = dev.name() {
                for gid_index in 0..port_attr.gid_tbl_len() {
                    let gid = ctx.query_gid(port_num, gid_index).unwrap();

                    if gid.is_zero() {
                        continue;
                    }

                    let gid_type = ctx.query_gid_type(port_num, gid_index as u32).unwrap();

                    let netdev = fs::read_to_string(format!(
                        "/sys/class/infiniband/{}/ports/{}/gid_attrs/ndevs/{}",
                        name, port_num, gid_index
                    ))?
                    .trim_ascii_end()
                    .to_string();

                    devices.push(GidEntries {
                        dev_name: name.clone(),
                        port: port_num.into(),
                        index: gid_index,
                        gid,
                        ipv4: Ipv6Addr::from(gid).to_ipv4_mapped(),
                        ver: match gid_type {
                            0 => "IB/RoCEv1",
                            1 => "RoCEv2",
                            _ => "Unknown",
                        },
                        netdev,
                    });
                }
            } else {
                eprintln!("Found a device without a name, skipping.");
            }
        }
    }

    let style = Style::psql().remove_verticals();

    let table = Table::new(devices)
        .with(Modify::new(Segment::all()).with(Alignment::center()))
        .with(style)
        .to_string();

    println!("{}", table);

    Ok(())
}
