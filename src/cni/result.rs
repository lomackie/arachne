use std::net::IpAddr;
use serde::Serialize;

#[derive(Serialize)]
pub struct CniResult {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub interfaces: Vec<Interface>,
    pub ips: Vec<IpConfig>,
    pub routes: Vec<Route>,
}

#[derive(Serialize)]
pub struct Interface {
    pub name: String,
    pub mac: String,
    pub sandbox: String,
}

#[derive(Serialize)]
pub struct IpConfig {
    pub address: String,
    pub gateway: IpAddr,
    pub interface: usize,
}

#[derive(Serialize)]
pub struct Route {
    pub dst: String,
    pub gw: IpAddr,
}
