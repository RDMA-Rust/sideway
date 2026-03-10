use sideway::ibverbs::device;
use sideway::ibverbs::device::{Device, DeviceInfo};

use termtree::Tree;

const FIELD_ALIGN: usize = 28;

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
    device_tree.push(aligned_field!("max_mr_size", fmt = "0x{:x}", attr.max_mr_size()));
    device_tree.push(aligned_field!("page_size_cap", fmt = "0x{:x}", attr.page_size_cap()));
    device_tree.push(aligned_field!("max_qp", attr.max_qp()));
    device_tree.push(aligned_field!("max_qp_wr", attr.max_qp_wr()));
    device_tree.push(aligned_field!(
        "device_cap_flags",
        fmt = "0x{:08x}",
        attr.device_cap_flags().bits()
    ));
    device_tree.push(aligned_field!(
        "device_cap_flags_names",
        format!("{:?}", attr.device_cap_flags())
    ));
    device_tree.push(aligned_field!("max_sge", attr.max_sge()));
    device_tree.push(aligned_field!("max_sge_rd", attr.max_sge_rd()));
    device_tree.push(aligned_field!("max_cq", attr.max_cq()));
    device_tree.push(aligned_field!("max_cqe", attr.max_cqe()));
    device_tree.push(aligned_field!("max_mr", attr.max_mr()));
    device_tree.push(aligned_field!("max_pd", attr.max_pd()));
    device_tree.push(aligned_field!("max_qp_rd_atom", attr.max_qp_rd_atom()));
    device_tree.push(aligned_field!("max_ee_rd_atom", attr.max_ee_rd_atom()));
    device_tree.push(aligned_field!("max_res_rd_atom", attr.max_res_rd_atomic()));
    device_tree.push(aligned_field!("max_qp_init_rd_atom", attr.max_qp_init_rd_atom()));
    device_tree.push(aligned_field!("max_ee_init_rd_atom", attr.max_ee_init_rd_atom()));
    device_tree.push(aligned_field!(
        "atomic_cap",
        format!("{:?} ({})", attr.atomic_capability(), attr.atomic_capability() as u32)
    ));
    device_tree.push(aligned_field!("max_ee", attr.max_ee()));
    device_tree.push(aligned_field!("max_rdd", attr.max_rdd()));
    device_tree.push(aligned_field!("max_mw", attr.max_mw()));
    device_tree.push(aligned_field!("max_raw_ipv6_qp", attr.max_raw_ipv6_qp()));
    device_tree.push(aligned_field!("max_raw_ethy_qp", attr.max_raw_ethy_qp()));
    device_tree.push(aligned_field!("max_mcast_grp", attr.max_mcast_grp()));
    device_tree.push(aligned_field!("max_mcast_qp_attach", attr.max_mcast_qp_attach()));
    device_tree.push(aligned_field!(
        "max_total_mcast_qp_attach",
        attr.max_total_mcast_qp_attach()
    ));
    device_tree.push(aligned_field!("max_ah", attr.max_ah()));
    device_tree.push(aligned_field!("max_fmr", attr.max_fmr()));
    device_tree.push(aligned_field!("max_map_per_fmr", attr.max_map_per_fmr()));
    device_tree.push(aligned_field!("max_srq", attr.max_srq()));
    device_tree.push(aligned_field!("max_srq_wr", attr.max_srq_wr()));
    device_tree.push(aligned_field!("max_srq_sge", attr.max_srq_sge()));
    device_tree.push(aligned_field!("max_pkeys", attr.max_pkeys()));
    device_tree.push(aligned_field!("local_ca_ack_delay", attr.local_ca_ack_delay()));
    device_tree.push(aligned_field!(
        "completion_ts_mask",
        if attr.completion_timestamp_mask() == 0 {
            "not supported".to_string()
        } else {
            format!("0x{:016x}", attr.completion_timestamp_mask())
        }
    ));
    device_tree.push(aligned_field!(
        "hca_core_clock",
        if attr.hca_core_clock() == 0 {
            "not supported".to_string()
        } else {
            format!("{} kHz", attr.hca_core_clock())
        }
    ));
    let pci_atomic_caps = attr.pci_atomic_caps();
    device_tree.push(aligned_field!(
        "pci_atomic.fetch_add",
        format!(
            "{:?} (0x{:x})",
            pci_atomic_caps.fetch_add(),
            pci_atomic_caps.fetch_add().bits()
        )
    ));
    device_tree.push(aligned_field!(
        "pci_atomic.swap",
        format!("{:?} (0x{:x})", pci_atomic_caps.swap(), pci_atomic_caps.swap().bits())
    ));
    device_tree.push(aligned_field!(
        "pci_atomic.compare_swap",
        format!(
            "{:?} (0x{:x})",
            pci_atomic_caps.compare_swap(),
            pci_atomic_caps.compare_swap().bits()
        )
    ));
    device_tree.push(aligned_field!("phys_port_cnt", attr.phys_port_cnt()));

    // Add ports as subtrees
    for port_num in 1..(attr.phys_port_cnt() + 1) {
        let mut port_tree = Tree::new(format!("port: {port_num}"));

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
