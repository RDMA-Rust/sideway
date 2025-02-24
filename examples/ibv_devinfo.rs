use sideway::ibverbs::device;
use sideway::ibverbs::device::{Device, DeviceInfo};

use termtree::Tree;

const FIELD_ALIGN: usize = 25;

#[macro_export]
macro_rules! aligned_field {
    // For composite values with parentheses
    ($field:expr, $main:expr, paren = $paren:expr) => {{
        format!("{:<width$}{} ({})",
            concat!($field, ":"),
            $main,
            $paren,
            width = FIELD_ALIGN
        )
    }};

    // For composite values with custom formatting
    ($field:expr, fmt = $format:literal, $main:expr, paren = $paren:expr) => {{
        format!("{:<width$}{} ({})",
            concat!($field, ":"),
            format!($format, $main),
            $paren,
            width = FIELD_ALIGN
        )
    }};

    // Basic field-value with optional width
    ($field:expr, $value:expr $(, width = $width:expr)?) => {{
        let width = $($width)?(FIELD_ALIGN);
        format!("{:<width$}{}",
            concat!($field, ":"),
            $value,
            width = width
        )
    }};

    // Formatted value with optional width
    ($field:expr, fmt = $format:literal, $value:expr $(, width = $width:expr)?) => {{
        let width = $($width)?(FIELD_ALIGN);
        format!("{:<width$}{}",
            concat!($field, ":"),
            format!($format, $value),
            width = width
        )
    }};
}

fn device_to_tree(device: &Device) -> Tree<String> {
    // TODO: Adjust tree settings to support different styles
    build_device_tree(device)
}

// Helper to build the actual tree structure
fn build_device_tree(device: &Device) -> Tree<String> {
    let mut device_tree = Tree::new(format!("hca_id: {}", device.name()));

    let ctx = device.open().unwrap();
    let attr = ctx.query_device().unwrap();

    // Add device info
    device_tree.push(aligned_field!(
        "transport_type",
        device.transport_type(),
        paren = device.transport_type() as i32
    ));
    device_tree.push(aligned_field!("fw_ver", attr.firmware_version()));
    device_tree.push(aligned_field!("node_guid", device.guid()));
    device_tree.push(aligned_field!("sys_image_guid", attr.sys_image_guid()));
    device_tree.push(aligned_field!("vendor_id", fmt = "0x{:04x}", attr.vendor_id()));
    device_tree.push(aligned_field!(
        "vendor_part_id",
        fmt = "0x{:04x}",
        attr.vendor_part_id()
    ));
    device_tree.push(aligned_field!("hw_ver", fmt = "0x{:x}", attr.hardware_version()));
    device_tree.push(aligned_field!("phys_port_cnt", attr.phys_port_cnt()));

    // Add ports as subtrees
    for port_num in 1..(attr.phys_port_cnt() + 1) {
        let mut port_tree = Tree::new(format!("port: {}", port_num));

        let port_attr = ctx.query_port(port_num).unwrap();

        port_tree.push(aligned_field!(
            "state",
            fmt = "{:?}",
            port_attr.port_state(),
            paren = port_attr.port_state() as u32
        ));
        port_tree.push(aligned_field!(
            "max_mtu",
            fmt = "{:?}",
            port_attr.max_mtu(),
            paren = port_attr.max_mtu() as u32
        ));
        port_tree.push(aligned_field!(
            "active_mtu",
            fmt = "{:?}",
            port_attr.active_mtu(),
            paren = port_attr.active_mtu() as u32
        ));
        port_tree.push(aligned_field!("link_layer", fmt = "{:?}", port_attr.link_layer()));

        device_tree.push(port_tree);
    }

    device_tree
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = device::DeviceList::new()?;
    for device in &device_list {
        println!("{}", device_to_tree(&device));
    }

    Ok(())
}
