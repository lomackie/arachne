"""End-to-end tests for the arachne CNI plugin."""
import os
import subprocess
import time

import pytest
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

NAMESPACE = "default"
POD_NAME = "arachne-e2e"
TIMEOUT = 60


@pytest.fixture(scope="session")
def core_v1():
    config.load_kube_config(config_file=os.environ.get("KUBECONFIG"))
    return client.CoreV1Api()


@pytest.fixture(autouse=True)
def delete_pod(core_v1):
    yield
    try:
        core_v1.delete_namespaced_pod(POD_NAME, NAMESPACE)
    except ApiException as e:
        if e.status != 404:
            raise


def _wait(condition, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = condition()
        if result is not None:
            return result
        time.sleep(1)
    raise TimeoutError(f"condition not met after {timeout}s")


def test_pod_lifecycle(core_v1):
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(name=POD_NAME),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name="pause",
                    image="busybox:1.36",
                    command=["sleep", "infinity"],
                )
            ],
            restart_policy="Never",
        ),
    )
    core_v1.create_namespaced_pod(NAMESPACE, pod)

    def has_ip():
        p = core_v1.read_namespaced_pod(POD_NAME, NAMESPACE)
        return p.status.pod_ip or None

    ip = _wait(has_ip)
    assert ip.startswith("10.244."), f"unexpected pod IP: {ip}"

    core_v1.delete_namespaced_pod(
        POD_NAME, NAMESPACE,
        body=client.V1DeleteOptions(grace_period_seconds=0),
    )

    def is_gone():
        try:
            core_v1.read_namespaced_pod(POD_NAME, NAMESPACE)
            return None
        except ApiException as e:
            if e.status == 404:
                return True
            raise

    _wait(is_gone)


def _wait_running_ip(core_v1, name):
    def check():
        p = core_v1.read_namespaced_pod(name, NAMESPACE)
        if p.status.phase == "Running" and p.status.pod_ip:
            return p.status.pod_ip
        return None
    return _wait(check)


def _busybox_pod(name, node_name):
    return client.V1Pod(
        metadata=client.V1ObjectMeta(name=name),
        spec=client.V1PodSpec(
            node_name=node_name,
            containers=[client.V1Container(
                name="pause",
                image="busybox:1.36",
                command=["sleep", "infinity"],
            )],
            restart_policy="Never",
        ),
    )


def _delete_pods(core_v1, *names):
    for name in names:
        try:
            core_v1.delete_namespaced_pod(
                name, NAMESPACE,
                body=client.V1DeleteOptions(grace_period_seconds=0),
            )
        except ApiException as e:
            if e.status != 404:
                raise

    def all_gone():
        for name in names:
            try:
                core_v1.read_namespaced_pod(name, NAMESPACE)
                return None
            except ApiException as e:
                if e.status != 404:
                    raise
        return True

    _wait(all_gone)


def test_same_node_pod_routing(core_v1):
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    node_name = workers[0].metadata.name

    pod_a, pod_b = "arachne-e2e-a", "arachne-e2e-b"
    _delete_pods(core_v1, pod_a, pod_b)
    core_v1.create_namespaced_pod(NAMESPACE, _busybox_pod(pod_a, node_name))
    core_v1.create_namespaced_pod(NAMESPACE, _busybox_pod(pod_b, node_name))

    try:
        ip_a = _wait_running_ip(core_v1, pod_a)
        ip_b = _wait_running_ip(core_v1, pod_b)

        assert ip_a.startswith("10.244."), f"unexpected IP for {pod_a}: {ip_a}"
        assert ip_b.startswith("10.244."), f"unexpected IP for {pod_b}: {ip_b}"

        output = stream(
            core_v1.connect_get_namespaced_pod_exec,
            pod_a, NAMESPACE,
            command=["ping", "-c", "3", "-W", "1", ip_b],
            stderr=True, stdin=False, stdout=True, tty=False,
        )
        assert "3 packets transmitted, 3 packets received, 0% packet loss" in output, f"ping failed:\n{output}"
    finally:
        _delete_pods(core_v1, pod_a, pod_b)


def test_cross_node_routes(core_v1):
    """Each agent pod has a kernel route for every other node's podCIDR."""
    nodes = core_v1.list_node().items
    node_cidrs = {
        n.metadata.name: n.spec.pod_cidr
        for n in nodes
        if n.spec and n.spec.pod_cidr
    }
    assert len(node_cidrs) >= 2, "need at least 2 nodes with podCIDRs"

    agent_pods = core_v1.list_namespaced_pod(
        "kube-system", label_selector="app=arachne"
    ).items

    for pod in agent_pods:
        node = pod.spec.node_name
        expected = {cidr for name, cidr in node_cidrs.items() if name != node}
        if not expected:
            continue

        output = stream(
            core_v1.connect_get_namespaced_pod_exec,
            pod.metadata.name, "kube-system",
            command=["ip", "route"],
            stderr=True, stdin=False, stdout=True, tty=False,
        )
        for cidr in expected:
            assert cidr in output, (
                f"route for {cidr} missing on node {node}:\n{output}"
            )


def test_cross_node_pod_routing(core_v1):
    """A pod on one worker node can ping a pod on a different worker node."""
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    assert len(workers) >= 2, "need at least 2 worker nodes"

    node_a, node_b = workers[0].metadata.name, workers[1].metadata.name
    pod_a, pod_b = "arachne-e2e-xnode-a", "arachne-e2e-xnode-b"

    _delete_pods(core_v1, pod_a, pod_b)
    core_v1.create_namespaced_pod(NAMESPACE, _busybox_pod(pod_a, node_a))
    core_v1.create_namespaced_pod(NAMESPACE, _busybox_pod(pod_b, node_b))

    try:
        ip_a = _wait_running_ip(core_v1, pod_a)
        ip_b = _wait_running_ip(core_v1, pod_b)

        output = stream(
            core_v1.connect_get_namespaced_pod_exec,
            pod_a, NAMESPACE,
            command=["ping", "-c", "3", "-W", "1", ip_b],
            stderr=True, stdin=False, stdout=True, tty=False,
        )
        assert "3 packets transmitted, 3 packets received, 0% packet loss" in output, (
            f"cross-node ping failed:\n{output}"
        )
    finally:
        _delete_pods(core_v1, pod_a, pod_b)


# ── Service load balancing ─────────────────────────────────────────────────────

SVC_APP_LABEL = "arachne-e2e-svc"


def _httpd_pod(name, node_name):
    """A backend pod serving its own hostname over HTTP on :8080."""
    return client.V1Pod(
        metadata=client.V1ObjectMeta(name=name, labels={"app": SVC_APP_LABEL}),
        spec=client.V1PodSpec(
            node_name=node_name,
            containers=[client.V1Container(
                name="httpd",
                image="busybox:1.36",
                command=["sh", "-c",
                         'echo "$HOSTNAME" > /tmp/index.html && httpd -f -p 8080 -h /tmp'],
                ports=[client.V1ContainerPort(container_port=8080)],
                readiness_probe=client.V1Probe(
                    tcp_socket=client.V1TCPSocketAction(port=8080),
                    period_seconds=1,
                ),
            )],
            restart_policy="Never",
        ),
    )


def _service(name, port=80, target_port=8080):
    return client.V1Service(
        metadata=client.V1ObjectMeta(name=name),
        spec=client.V1ServiceSpec(
            selector={"app": SVC_APP_LABEL},
            ports=[client.V1ServicePort(port=port, target_port=target_port, protocol="TCP")],
        ),
    )


def _delete_service(core_v1, name):
    try:
        core_v1.delete_namespaced_service(name, NAMESPACE)
    except ApiException as e:
        if e.status != 404:
            raise


def _curl(core_v1, pod, url):
    """wget the URL from inside a pod; returns stripped stdout (combined w/ stderr)."""
    out = stream(
        core_v1.connect_get_namespaced_pod_exec,
        pod, NAMESPACE,
        command=["wget", "-qO-", "-T", "2", url],
        stderr=True, stdin=False, stdout=True, tty=False,
    )
    return out.strip()


def _wait_response_in(core_v1, client_pod, url, expected):
    """Retry the request until it returns one of the expected backend hostnames.

    The retry naturally waits for the agent to program the BPF SERVICES/BACKENDS
    maps — until then the datapath punts the ClusterIP to the kernel, which has
    no route for it, so the request fails.
    """
    def check():
        out = _curl(core_v1, client_pod, url)
        return out if out in expected else None
    return _wait(check)


def _nslookup(core_v1, pod, name, server):
    """Resolve `name` against `server` over UDP from inside a pod.

    busybox nslookup queries the given server over UDP; `timeout` bounds the wait
    so a dropped/unanswered query fails fast instead of hanging the exec stream.
    Returns the combined stdout/stderr.
    """
    out = stream(
        core_v1.connect_get_namespaced_pod_exec,
        pod, NAMESPACE,
        command=["sh", "-c", f"timeout 5 nslookup {name} {server} 2>&1"],
        stderr=True, stdin=False, stdout=True, tty=False,
    )
    return out.strip()


def test_service_clusterip_dnat(core_v1):
    """A pod can reach a backend through a Service ClusterIP (datapath DNAT)."""
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    node_name = workers[0].metadata.name

    backend, client_pod, svc = "arachne-e2e-svc-be", "arachne-e2e-svc-cli", "arachne-e2e-svc"
    _delete_pods(core_v1, backend, client_pod)
    _delete_service(core_v1, svc)

    core_v1.create_namespaced_pod(NAMESPACE, _httpd_pod(backend, node_name))
    core_v1.create_namespaced_pod(NAMESPACE, _busybox_pod(client_pod, node_name))
    created_svc = core_v1.create_namespaced_service(NAMESPACE, _service(svc))

    try:
        _wait_running_ip(core_v1, backend)
        _wait_running_ip(core_v1, client_pod)

        cluster_ip = created_svc.spec.cluster_ip
        assert cluster_ip.startswith("10.96.") or cluster_ip.startswith("10."), \
            f"unexpected ClusterIP: {cluster_ip}"

        url = f"http://{cluster_ip}:80/"
        resp = _wait_response_in(core_v1, client_pod, url, {backend})
        assert resp == backend, f"expected {backend}, got {resp!r}"
    finally:
        _delete_pods(core_v1, backend, client_pod)
        _delete_service(core_v1, svc)


def test_service_load_balancing(core_v1):
    """Requests across distinct connections spread over multiple backends."""
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    node_name = workers[0].metadata.name

    be_a, be_b = "arachne-e2e-lb-a", "arachne-e2e-lb-b"
    client_pod, svc = "arachne-e2e-lb-cli", "arachne-e2e-lb"
    _delete_pods(core_v1, be_a, be_b, client_pod)
    _delete_service(core_v1, svc)

    core_v1.create_namespaced_pod(NAMESPACE, _httpd_pod(be_a, node_name))
    core_v1.create_namespaced_pod(NAMESPACE, _httpd_pod(be_b, node_name))
    core_v1.create_namespaced_pod(NAMESPACE, _busybox_pod(client_pod, node_name))
    created_svc = core_v1.create_namespaced_service(NAMESPACE, _service(svc))

    backends = {be_a, be_b}
    try:
        _wait_running_ip(core_v1, be_a)
        _wait_running_ip(core_v1, be_b)
        _wait_running_ip(core_v1, client_pod)

        url = f"http://{created_svc.spec.cluster_ip}:80/"
        # Wait until the service routes to *both* backends — the agent programs
        # each EndpointSlice independently, so endpoints land in the map over time.
        seen = set()

        def both_seen():
            seen.add(_curl(core_v1, client_pod, url))
            hit = seen & backends
            return hit if len(hit) >= 2 else None

        # Backend choice is random per flow (bpf_get_prandom_u32 % count); each
        # wget is a fresh connection, so ~30 attempts hits both with near-certainty.
        hits = _wait(both_seen, timeout=90)
        assert hits == backends, f"expected to reach both backends, saw {seen}"
    finally:
        _delete_pods(core_v1, be_a, be_b, client_pod)
        _delete_service(core_v1, svc)


def test_service_clusterip_udp_dns(core_v1):
    """UDP to a Service ClusterIP gets a reply (regression: UDP NAT checksum).

    The issue's repro: resolve an in-cluster name through the kube-dns ClusterIP
    over UDP. The forward query is DNAT'd to a CoreDNS backend and the reply
    SNAT'd back, both of which rewrite the *optional* UDP checksum. The original
    bug patched a 0/absent checksum into a bogus value, so the DNAT'd query was
    silently dropped and the lookup timed out — even though TCP ClusterIP and
    direct UDP-to-pod both worked. A successful resolution proves the reply made
    it back through SNAT intact.
    """
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    node_name = workers[0].metadata.name

    dns_ip = core_v1.read_namespaced_service("kube-dns", "kube-system").spec.cluster_ip
    # The well-known kubernetes API service; its ClusterIP is what DNS returns for
    # the name below, so finding it in the output confirms a real, intact answer.
    expected_ip = core_v1.read_namespaced_service("kubernetes", "default").spec.cluster_ip

    client_pod = "arachne-e2e-dns-cli"
    _delete_pods(core_v1, client_pod)
    core_v1.create_namespaced_pod(NAMESPACE, _busybox_pod(client_pod, node_name))

    try:
        _wait_running_ip(core_v1, client_pod)

        # Retry until the agent has programmed the kube-dns service/backends into
        # the BPF maps; until then the ClusterIP is punted and the lookup fails.
        def resolved():
            out = _nslookup(core_v1, client_pod,
                            "kubernetes.default.svc.cluster.local", dns_ip)
            return out if expected_ip in out else None

        out = _wait(resolved, timeout=60)
        assert expected_ip in out, f"DNS reply missing {expected_ip}:\n{out}"
    finally:
        _delete_pods(core_v1, client_pod)


# ── Conntrack GC ───────────────────────────────────────────────────────────────

DS_NAME = "arachne"
DS_NS = "kube-system"


@pytest.fixture(scope="session")
def apps_v1():
    config.load_kube_config(config_file=os.environ.get("KUBECONFIG"))
    return client.AppsV1Api()


def _patch_agent_env(apps_v1, env):
    """Strategic-merge the agent container's env (list merged by name)."""
    body = {"spec": {"template": {"spec": {"containers": [
        {"name": "agent", "env": env},
    ]}}}}
    apps_v1.patch_namespaced_daemon_set(
        DS_NAME, DS_NS, body,
        _content_type="application/strategic-merge-patch+json",
    )


def _agent_pod_on(core_v1, node_name):
    for p in core_v1.list_namespaced_pod("kube-system", label_selector="app=arachne").items:
        if p.spec.node_name == node_name:
            return p
    return None


def _wait_agent_ready_with_env(core_v1, node_name, env_name, present):
    """Wait until the node's agent pod is Running/Ready and its env contains
    (or lacks) env_name — i.e. the rollout with the new config has landed."""
    def check():
        p = _agent_pod_on(core_v1, node_name)
        if p is None or p.status.phase != "Running":
            return None
        if not all(cs.ready for cs in (p.status.container_statuses or [])):
            return None
        agent = next((c for c in p.spec.containers if c.name == "agent"), None)
        names = {e.name for e in (agent.env or [])}
        return p.metadata.name if (env_name in names) == present else None
    return _wait(check, timeout=120)


def test_conntrack_gc_reaps_idle_flows(core_v1, apps_v1):
    """The idle GC reaps stale conntrack flows.

    Sends one-shot UDP packets at the kube-dns ClusterIP. UDP has no FIN/RST, so
    the datapath never tears the flow down; the forward packet alone creates a
    (forward, reverse) conntrack pair that then sits idle until the sweep reaps
    it. The assertion relies only on the entry being created and aged out, not on
    a reply. The agent is driven with a short idle timeout + sweep interval.
    """
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    node_name = workers[0].metadata.name

    dns_ip = core_v1.read_namespaced_service("kube-dns", "kube-system").spec.cluster_ip
    client_pod = "arachne-e2e-gc-cli"

    # Aggressive timers so the test is fast: reap flows idle > 4s, sweep every 2s.
    # UDP is state-aware "short", so drive the short timeout (not the established
    # ARACHNE_CT_IDLE_SECS, which only applies to established TCP flows).
    _patch_agent_env(apps_v1, [
        {"name": "ARACHNE_CT_SHORT_SECS", "value": "4"},
        {"name": "ARACHNE_CT_GC_SECS", "value": "2"},
    ])
    try:
        _wait_agent_ready_with_env(core_v1, node_name, "ARACHNE_CT_SHORT_SECS", present=True)

        _delete_pods(core_v1, client_pod)
        core_v1.create_namespaced_pod(NAMESPACE, _busybox_pod(client_pod, node_name))
        _wait_running_ip(core_v1, client_pod)

        agent = _agent_pod_on(core_v1, node_name)

        # Each send creates a conntrack pair for a service flow that gets no reply.
        for _ in range(3):
            stream(
                core_v1.connect_get_namespaced_pod_exec,
                client_pod, NAMESPACE,
                command=["sh", "-c", f"echo q | nc -u -w1 {dns_ip} 53"],
                stderr=True, stdin=False, stdout=True, tty=False,
            )

        def gc_evicted():
            # _preload_content=False + decode: the default path returns the str()
            # of a bytes object (literal b'…\n…'), which won't split into lines.
            resp = core_v1.read_namespaced_pod_log(
                agent.metadata.name, "kube-system", container="agent", tail_lines=300,
                _preload_content=False,
            )
            logs = resp.data.decode("utf-8", "replace")
            for line in logs.splitlines():
                if line.startswith("conntrack gc:") and "evicted=" in line:
                    if int(line.split("evicted=")[1].split()[0]) > 0:
                        return line
            return None

        assert _wait(gc_evicted, timeout=40), "GC never reported an eviction"
    finally:
        _patch_agent_env(apps_v1, [
            {"name": "ARACHNE_CT_SHORT_SECS", "$patch": "delete"},
            {"name": "ARACHNE_CT_GC_SECS", "$patch": "delete"},
        ])
        _wait_agent_ready_with_env(core_v1, node_name, "ARACHNE_CT_SHORT_SECS", present=False)
        _delete_pods(core_v1, client_pod)


def _agent_ct_evict(core_v1, agent_name):
    """Latest ct_evict counter value from the agent log, or None if not yet logged.

    The agent prints a `counters: ... ct_evict=N` line every 30s. ct_evict is
    bumped only by datapath teardown (RST/FIN) — the GC sweep never touches it —
    so this is a clean signal that the datapath evicted a flow.
    """
    resp = core_v1.read_namespaced_pod_log(
        agent_name, "kube-system", container="agent", tail_lines=300,
        _preload_content=False,
    )
    logs = resp.data.decode("utf-8", "replace")
    val = None
    for line in logs.splitlines():
        if line.startswith("counters:") and "ct_evict=" in line:
            val = int(line.split("ct_evict=")[1].split()[0])
    return val


def test_conntrack_evicts_on_clean_tcp_close(core_v1):
    """A cleanly closed TCP connection through a ClusterIP is torn down in the
    datapath (the FIN handshake), not left for the idle GC sweep.

    Each wget is a fresh connection the server closes cleanly (HTTP/1.0), so it
    completes the FIN handshake rather than aborting with RST. The agent's
    ct_evict counter is bumped only by datapath teardown, so a climb of one per
    closed connection proves the FIN-eviction path fired without waiting on GC.
    """
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    node_name = workers[0].metadata.name

    backend, client_pod, svc = "arachne-e2e-fin-be", "arachne-e2e-fin-cli", "arachne-e2e-fin"
    _delete_pods(core_v1, backend, client_pod)
    _delete_service(core_v1, svc)

    core_v1.create_namespaced_pod(NAMESPACE, _httpd_pod(backend, node_name))
    core_v1.create_namespaced_pod(NAMESPACE, _busybox_pod(client_pod, node_name))
    created_svc = core_v1.create_namespaced_service(NAMESPACE, _service(svc))

    try:
        _wait_running_ip(core_v1, backend)
        _wait_running_ip(core_v1, client_pod)

        url = f"http://{created_svc.spec.cluster_ip}:80/"
        # Retry until the service is programmed and actually routes to the backend.
        resp = _wait_response_in(core_v1, client_pod, url, {backend})
        assert resp == backend, f"expected {backend}, got {resp!r}"

        agent = _agent_pod_on(core_v1, node_name)
        # Baseline after the warm-up request above is already counted.
        baseline = _wait(lambda: _agent_ct_evict(core_v1, agent.metadata.name), timeout=60)

        bursts = 5
        for _ in range(bursts):
            assert _curl(core_v1, client_pod, url) == backend

        def climbed():
            cur = _agent_ct_evict(core_v1, agent.metadata.name)
            return cur if cur is not None and cur >= baseline + bursts else None

        assert _wait(climbed, timeout=90), \
            f"ct_evict did not climb by {bursts} from baseline {baseline}"
    finally:
        _delete_pods(core_v1, backend, client_pod)
        _delete_service(core_v1, svc)


CLUSTER_NAME = "arachne-dev"


def _spin_up_node(node_name):
    """Start a new kind worker node and join it to the cluster."""
    donor = f"{CLUSTER_NAME}-worker"
    image = subprocess.check_output(
        ["docker", "inspect", "--format", "{{.Config.Image}}", donor]
    ).decode().strip()

    # Copy kubeadm.conf from an existing worker — it already has the cluster
    # CA, API server endpoint, and token baked in.
    subprocess.run(["docker", "cp", f"{donor}:/kind/kubeadm.conf", f"/tmp/{node_name}.conf"], check=True)
    with open(f"/tmp/{node_name}.conf") as f:
        conf = f.read()

    # Run the new node container with the same flags kind uses.
    subprocess.run([
        "docker", "run", "-d", "--privileged", "--tty", "--init=false",
        "--name", node_name, "--hostname", node_name,
        "--network", "kind",
        "--label", f"io.x-k8s.kind.cluster={CLUSTER_NAME}",
        "--label", "io.x-k8s.kind.role=worker",
        "--security-opt", "seccomp=unconfined",
        "--security-opt", "apparmor=unconfined",
        "--tmpfs", "/tmp", "--tmpfs", "/run",
        "--volume", "/var",
        "--volume", "/lib/modules:/lib/modules:ro",
        image,
    ], check=True)

    new_ip = subprocess.check_output([
        "docker", "inspect", "--format",
        "{{(index .NetworkSettings.Networks \"kind\").IPAddress}}", node_name,
    ]).decode().strip()

    # Patch the donor's IP and hostname to match the new node.
    donor_ip = subprocess.check_output([
        "docker", "inspect", "--format",
        "{{(index .NetworkSettings.Networks \"kind\").IPAddress}}", donor,
    ]).decode().strip()
    conf = conf.replace(donor_ip, new_ip).replace(donor, node_name)
    with open(f"/tmp/{node_name}.conf", "w") as f:
        f.write(conf)

    subprocess.run(["docker", "cp", f"/tmp/{node_name}.conf", f"{node_name}:/kind/kubeadm.conf"], check=True)

    # Wait for containerd to be ready before joining.
    _wait(lambda: subprocess.run(
        ["docker", "exec", node_name, "systemctl", "is-active", "--quiet", "containerd"],
        capture_output=True,
    ).returncode == 0 or None)

    # Load the agent image so the DaemonSet pod doesn't hit ErrImageNeverPull.
    save = subprocess.Popen(["docker", "save", "arachne:dev"], stdout=subprocess.PIPE)
    subprocess.run(
        ["docker", "exec", "-i", node_name, "ctr", "-n", "k8s.io", "images", "import", "-"],
        stdin=save.stdout, check=True,
    )
    save.stdout.close()
    save.wait()

    subprocess.run([
        "docker", "exec", node_name,
        "kubeadm", "join", "--config", "/kind/kubeadm.conf", "--skip-phases=preflight",
    ], check=True)


def _tear_down_node(core_v1, node_name):
    """Remove a node from the cluster and delete its container."""
    try:
        core_v1.delete_node(node_name)
    except ApiException as e:
        if e.status != 404:
            raise
    subprocess.run(["docker", "rm", "-f", node_name], check=False)


def test_node_route_lifecycle(core_v1):
    """Routes appear when a node joins and disappear when it leaves."""
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    observer = workers[0]

    observer_agent = next(
        p for p in core_v1.list_namespaced_pod("kube-system", label_selector="app=arachne").items
        if p.spec.node_name == observer.metadata.name
    )

    def route_output():
        return stream(
            core_v1.connect_get_namespaced_pod_exec,
            observer_agent.metadata.name, "kube-system",
            command=["ip", "route"],
            stderr=True, stdin=False, stdout=True, tty=False,
        )

    new_node = "arachne-e2e-lifecycle"
    _spin_up_node(new_node)
    new_cidr = None
    try:
        def node_has_cidr():
            try:
                return core_v1.read_node(new_node).spec.pod_cidr or None
            except ApiException as e:
                if e.status == 404:
                    return None
                raise
        new_cidr = _wait(node_has_cidr)
        _wait(lambda: new_cidr in route_output() or None)
    finally:
        _tear_down_node(core_v1, new_node)
        if new_cidr:
            _wait(lambda: new_cidr not in route_output() or None)
