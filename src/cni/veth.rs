use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use futures::TryStreamExt;
use nix::sched::CloneFlags;
use rtnetlink::Handle;
use super::error::CniError;

pub fn host_veth_name(container_id: &str) -> String {
    format!("veth{}", &container_id[..container_id.len().min(8)])
}

pub fn setup(
    container_id: &str,
    ifname: &str,
    netns: &str,
    pod_ip: IpAddr,
    prefix_len: u8,
    gateway: IpAddr,
) -> Result<(u32, [u8; 6]), CniError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CniError::Netlink(e.to_string()))?;
    rt.block_on(setup_async(container_id, ifname, netns, pod_ip, prefix_len, gateway))
}

pub fn teardown(container_id: &str) -> Result<(), CniError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CniError::Netlink(e.to_string()))?;
    rt.block_on(teardown_async(container_id))
}

async fn setup_async(
    container_id: &str,
    ifname: &str,
    netns: &str,
    pod_ip: IpAddr,
    prefix_len: u8,
    gateway: IpAddr,
) -> Result<(u32, [u8; 6]), CniError> {
    let IpAddr::V4(pod_ipv4) = pod_ip else {
        return Err(CniError::Netlink("IPv6 not supported".into()));
    };
    let IpAddr::V4(gw_ipv4) = gateway else {
        return Err(CniError::Netlink("IPv6 not supported".into()));
    };

    let host_veth = host_veth_name(container_id);
    let peer_veth = format!("peth{}", &container_id[..container_id.len().min(8)]);

    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| CniError::Netlink(e.to_string()))?;
    tokio::spawn(connection);

    handle.link().add()
        .veth(host_veth.clone(), peer_veth.clone())
        .execute()
        .await
        .map_err(|e| CniError::Netlink(format!("create veth: {e}")))?;

    let peer_idx = link_index(&handle, &peer_veth).await?;
    let netns_file = std::fs::File::open(netns)?;
    handle.link().set(peer_idx)
        .setns_by_fd(netns_file.as_raw_fd())
        .execute()
        .await
        .map_err(|e| CniError::Netlink(format!("move peer to pod netns: {e}")))?;

    let host_idx = link_index(&handle, &host_veth).await?;
    handle.link().set(host_idx).up().execute().await
        .map_err(|e| CniError::Netlink(format!("bring up host veth: {e}")))?;
    std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{host_veth}/proxy_arp"),
        "1",
    )?;
    handle.route().add()
        .v4()
        .destination_prefix(pod_ipv4, 32)
        .output_interface(host_idx)
        .execute()
        .await
        .map_err(|e| CniError::Netlink(format!("add host route: {e}")))?;

    let host_ns = std::fs::File::open("/proc/self/ns/net")?;
    nix::sched::setns(&netns_file, CloneFlags::CLONE_NEWNET)
        .map_err(|e| CniError::Netlink(format!("enter pod netns: {e}")))?;

    let result = configure_pod_netns(&peer_veth, ifname, pod_ipv4, prefix_len, gw_ipv4).await;

    nix::sched::setns(&host_ns, CloneFlags::CLONE_NEWNET)
        .map_err(|e| CniError::Netlink(format!("return to host netns: {e}")))?;

    let pod_mac = result?;
    Ok((host_idx, pod_mac))
}

async fn configure_pod_netns(
    peer_veth: &str,
    ifname: &str,
    pod_ip: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
) -> Result<[u8; 6], CniError> {
    let (conn2, handle2, _) = rtnetlink::new_connection()
        .map_err(|e| CniError::Netlink(e.to_string()))?;
    tokio::spawn(conn2);

    let lo_idx = link_index(&handle2, "lo").await?;
    handle2.link().set(lo_idx).up().execute().await
        .map_err(|e| CniError::Netlink(format!("bring up lo: {e}")))?;

    let peer_idx = link_index(&handle2, peer_veth).await?;
    handle2.link().set(peer_idx).name(ifname.to_string()).execute().await
        .map_err(|e| CniError::Netlink(format!("rename veth to {ifname}: {e}")))?;

    let iface_idx = link_index(&handle2, ifname).await?;
    handle2.address().add(iface_idx, IpAddr::V4(pod_ip), prefix_len).execute().await
        .map_err(|e| CniError::Netlink(format!("assign pod IP: {e}")))?;
    handle2.link().set(iface_idx).up().execute().await
        .map_err(|e| CniError::Netlink(format!("bring up {ifname}: {e}")))?;

    handle2.route().add()
        .v4()
        .gateway(gateway)
        .execute()
        .await
        .map_err(|e| CniError::Netlink(format!("add default route: {e}")))?;

    link_mac(&handle2, ifname).await
}

async fn link_mac(handle: &Handle, name: &str) -> Result<[u8; 6], CniError> {
    use netlink_packet_route::link::LinkAttribute;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await
        .map_err(|e| CniError::Netlink(format!("get link {name}: {e}")))?
        .ok_or_else(|| CniError::Netlink(format!("link not found: {name}")))?;
    link.attributes.iter().find_map(|attr| {
        if let LinkAttribute::Address(addr) = attr {
            if addr.len() == 6 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(addr);
                return Some(mac);
            }
        }
        None
    }).ok_or_else(|| CniError::Netlink(format!("no MAC on {name}")))
}

async fn teardown_async(container_id: &str) -> Result<(), CniError> {
    let host_veth = host_veth_name(container_id);

    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| CniError::Netlink(e.to_string()))?;
    tokio::spawn(connection);

    match link_index(&handle, &host_veth).await {
        Ok(idx) => handle.link().del(idx).execute().await
            .map_err(|e| CniError::Netlink(format!("delete host veth: {e}")))?,
        Err(_) => {}
    }
    Ok(())
}

async fn link_index(handle: &Handle, name: &str) -> Result<u32, CniError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await
        .map_err(|e| CniError::Netlink(format!("get link {name}: {e}")))?
        .ok_or_else(|| CniError::Netlink(format!("link not found: {name}")))?;
    Ok(link.header.index)
}
