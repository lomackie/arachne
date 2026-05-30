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
            core_v1.delete_namespaced_pod(name, NAMESPACE)
        except ApiException as e:
            if e.status != 404:
                raise


def test_same_node_pod_routing(core_v1):
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    node_name = workers[0].metadata.name

    pod_a, pod_b = "arachne-e2e-a", "arachne-e2e-b"
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


def test_node_route_lifecycle(core_v1):
    """Routes disappear when a node leaves and reappear when it rejoins."""
    nodes = core_v1.list_node().items
    workers = [n for n in nodes if "node-role.kubernetes.io/control-plane" not in (n.metadata.labels or {})]
    assert len(workers) >= 2, "need at least 2 worker nodes"

    # target: the node we'll remove; observer: the node whose route table we'll check.
    target = workers[-1]
    observer = workers[0]
    target_cidr = target.spec.pod_cidr
    assert target_cidr, f"node {target.metadata.name} has no podCIDR"

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

    def restart_kubelet():
        subprocess.run(
            ["docker", "exec", target.metadata.name, "systemctl", "restart", "kubelet"],
            check=True,
        )

    assert target_cidr in route_output(), f"route for {target_cidr} not present before test"

    core_v1.delete_node(target.metadata.name)

    try:
        _wait(lambda: target_cidr not in route_output() or None)

        restart_kubelet()

        # Wait for the node to re-register and get a CIDR assigned (may differ from
        # the original if the IPAM controller reassigns from the pool).
        def node_rejoined():
            try:
                n = core_v1.read_node(target.metadata.name)
                return n.spec.pod_cidr or None
            except ApiException as e:
                if e.status == 404:
                    return None
                raise

        new_cidr = _wait(node_rejoined)
        _wait(lambda: new_cidr in route_output() or None)

    finally:
        try:
            core_v1.read_node(target.metadata.name)
        except ApiException as e:
            if e.status == 404:
                restart_kubelet()
