use anyhow::{Context, Result};
use futures::TryStreamExt;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};

use arachne_common::{BackendKey, BackendVal, ServiceKey, ServiceVal, endpoint_key, port_key};

// ── Service/EndpointSlice state ───────────────────────────────────────────────

struct SvcInfo {
    id: u32,
    cluster_ip: Option<Ipv4Addr>,
    ports: Vec<PortInfo>,
}

struct PortInfo {
    svc_port: u16,
    target_port: u16,
    proto: u8,
}

struct BackendEntry {
    pod_ip: Ipv4Addr,
    port: u16,
    proto: u8,
}

struct SvcState {
    next_id: u32,
    // "namespace/name" → SvcInfo
    services: HashMap<String, SvcInfo>,
    // "namespace/name" (service) → "slice_uid" → Vec<BackendEntry>
    slice_backends: HashMap<String, HashMap<String, Vec<BackendEntry>>>,
}

impl SvcState {
    fn new() -> Self {
        Self { next_id: 1, services: HashMap::new(), slice_backends: HashMap::new() }
    }

    fn svc_key(ns: &str, name: &str) -> String {
        format!("{ns}/{name}")
    }

    fn handle_service_apply(&mut self, svc: &Service) -> Result<()> {
        let ns = svc.metadata.namespace.as_deref().unwrap_or("default");
        let name = match svc.metadata.name.as_deref() {
            Some(n) => n,
            None => return Ok(()),
        };
        let key = Self::svc_key(ns, name);

        let cluster_ip = svc.spec.as_ref()
            .and_then(|s| s.cluster_ip.as_deref())
            .filter(|ip| *ip != "None" && !ip.is_empty())
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok());

        let ports = svc.spec.as_ref()
            .and_then(|s| s.ports.as_ref())
            .map(|ps| ps.iter().filter_map(|p| {
                let svc_port = p.port as u16;
                let target_port = match p.target_port.as_ref() {
                    Some(IntOrString::Int(n)) => *n as u16,
                    Some(IntOrString::String(s)) => s.parse::<u16>().ok()?,
                    None => svc_port,
                };
                let proto = proto_byte(p.protocol.as_deref().unwrap_or("TCP"))?;
                Some(PortInfo { svc_port, target_port, proto })
            }).collect())
            .unwrap_or_default();

        let id = self.services.get(&key).map(|s| s.id).unwrap_or_else(|| {
            let id = self.next_id;
            self.next_id += 1;
            id
        });

        self.services.insert(key.clone(), SvcInfo { id, cluster_ip, ports });
        self.reconcile(&key)
    }

    fn handle_service_delete(&mut self, ns: &str, name: &str) -> Result<()> {
        let key = Self::svc_key(ns, name);
        if let Some(svc) = self.services.remove(&key) {
            if let Some(cluster_ip) = svc.cluster_ip {
                for port in &svc.ports {
                    let bpf_key = ServiceKey {
                        vip: endpoint_key(cluster_ip),
                        port: port_key(port.svc_port),
                        proto: port.proto,
                        _pad: 0,
                    };
                    crate::bpf::services_remove(bpf_key)
                        .with_context(|| format!("remove service {key}"))?;
                }
            }
        }
        self.slice_backends.remove(&key);
        Ok(())
    }

    fn handle_slice_apply(&mut self, slice: &EndpointSlice) -> Result<()> {
        let ns = slice.metadata.namespace.as_deref().unwrap_or("default");
        let svc_name = slice.metadata.labels.as_ref()
            .and_then(|l| l.get("kubernetes.io/service-name"))
            .map(String::as_str);
        let Some(svc_name) = svc_name else { return Ok(()) };
        let Some(uid) = slice.metadata.uid.as_deref() else { return Ok(()) };

        let svc_key = Self::svc_key(ns, svc_name);

        let slice_ports = match slice.ports.as_ref() {
            Some(p) => p,
            None => return Ok(()),
        };

        let mut backends = Vec::new();
        for ep in &slice.endpoints {
            let ready = ep.conditions.as_ref()
                .and_then(|c| c.ready)
                .unwrap_or(true);
            if !ready { continue; }

            for addr in &ep.addresses {
                let Ok(pod_ip) = addr.parse::<Ipv4Addr>() else { continue };
                for sp in slice_ports {
                    let Some(port_num) = sp.port else { continue };
                    let Some(proto) = proto_byte(sp.protocol.as_deref().unwrap_or("TCP")) else { continue };
                    backends.push(BackendEntry { pod_ip, port: port_num as u16, proto });
                }
            }
        }

        self.slice_backends
            .entry(svc_key.clone())
            .or_default()
            .insert(uid.to_string(), backends);

        self.reconcile(&svc_key)
    }

    fn handle_slice_delete(&mut self, slice: &EndpointSlice) -> Result<()> {
        let ns = slice.metadata.namespace.as_deref().unwrap_or("default");
        let svc_name = slice.metadata.labels.as_ref()
            .and_then(|l| l.get("kubernetes.io/service-name"))
            .map(String::as_str);
        let Some(svc_name) = svc_name else { return Ok(()) };
        let Some(uid) = slice.metadata.uid.as_deref() else { return Ok(()) };

        let svc_key = Self::svc_key(ns, svc_name);
        if let Some(slices) = self.slice_backends.get_mut(&svc_key) {
            slices.remove(uid);
        }
        self.reconcile(&svc_key)
    }

    /// Recompute and push SERVICES + BACKENDS map entries for one service.
    fn reconcile(&self, svc_key: &str) -> Result<()> {
        let svc = match self.services.get(svc_key) {
            Some(s) => s,
            None => return Ok(()),
        };
        let cluster_ip = match svc.cluster_ip {
            Some(ip) => ip,
            None => return Ok(()),
        };

        // Flatten all backends from every EndpointSlice for this service.
        let all_backends: Vec<&BackendEntry> = self.slice_backends
            .get(svc_key)
            .map(|slices| slices.values().flatten().collect())
            .unwrap_or_default();

        for port in &svc.ports {
            // Match backends by target_port + proto. Prefer name-matching when
            // available, but fall back to port number (handles unnamed ports).
            let port_backends: Vec<&BackendEntry> = all_backends.iter()
                .filter(|b| b.port == port.target_port && b.proto == port.proto)
                .copied()
                .collect();

            let bpf_svc_key = ServiceKey {
                vip: endpoint_key(cluster_ip),
                port: port_key(port.svc_port),
                proto: port.proto,
                _pad: 0,
            };
            let bpf_svc_val = ServiceVal {
                service_id: svc.id,
                backend_count: port_backends.len() as u32,
            };
            crate::bpf::services_upsert(bpf_svc_key, bpf_svc_val)
                .with_context(|| format!("upsert service {svc_key}:{}", port.svc_port))?;

            for (i, b) in port_backends.iter().enumerate() {
                crate::bpf::backends_upsert(
                    BackendKey {
                        service_id: svc.id,
                        index: i as u32,
                        port: port_key(port.svc_port),
                        proto: port.proto,
                        _pad: 0,
                    },
                    BackendVal {
                        pod_ip: endpoint_key(b.pod_ip),
                        pod_port: port_key(b.port),
                        _pad: [0; 2],
                    },
                )
                .with_context(|| format!("upsert backend {svc_key}:{}/{i}", port.svc_port))?;
            }
        }
        Ok(())
    }
}

fn proto_byte(s: &str) -> Option<u8> {
    match s {
        "TCP" => Some(6),
        "UDP" => Some(17),
        _ => None,
    }
}

// ── Watcher helpers ───────────────────────────────────────────────────────────

enum SvcOrSlice {
    Service(Event<Service>),
    Slice(Event<EndpointSlice>),
}

pub async fn watch_services_and_slices(client: &Client) -> Result<()> {
    let mut state = SvcState::new();

    let svc_stream = watcher::watcher(Api::<Service>::all(client.clone()), watcher::Config::default())
        .map_ok(SvcOrSlice::Service)
        .map_err(anyhow::Error::from);
    let slice_stream = watcher::watcher(Api::<EndpointSlice>::all(client.clone()), watcher::Config::default())
        .map_ok(SvcOrSlice::Slice)
        .map_err(anyhow::Error::from);

    let mut merged = futures::stream::select(
        Box::pin(svc_stream),
        Box::pin(slice_stream),
    );

    while let Some(event) = merged.try_next().await.context("service/slice watch error")? {
        match event {
            SvcOrSlice::Service(Event::Apply(s) | Event::InitApply(s)) => {
                state.handle_service_apply(&s)
                    .with_context(|| format!("handle service apply {:?}", s.metadata.name))?;
            }
            SvcOrSlice::Service(Event::Delete(s)) => {
                let ns = s.metadata.namespace.as_deref().unwrap_or("default");
                let name = s.metadata.name.as_deref().unwrap_or("");
                state.handle_service_delete(ns, name)
                    .with_context(|| format!("handle service delete {ns}/{name}"))?;
            }
            SvcOrSlice::Service(Event::Init | Event::InitDone) => {}
            SvcOrSlice::Slice(Event::Apply(s) | Event::InitApply(s)) => {
                state.handle_slice_apply(&s)
                    .with_context(|| format!("handle slice apply {:?}", s.metadata.uid))?;
            }
            SvcOrSlice::Slice(Event::Delete(s)) => {
                state.handle_slice_delete(&s)
                    .with_context(|| format!("handle slice delete {:?}", s.metadata.uid))?;
            }
            SvcOrSlice::Slice(Event::Init | Event::InitDone) => {}
        }
    }
    Ok(())
}
