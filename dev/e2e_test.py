"""End-to-end tests for the arachne CNI plugin."""
import os
import time

import pytest
from kubernetes import client, config
from kubernetes.client.rest import ApiException

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

    core_v1.delete_namespaced_pod(POD_NAME, NAMESPACE)

    def is_gone():
        try:
            core_v1.read_namespaced_pod(POD_NAME, NAMESPACE)
            return None
        except ApiException as e:
            if e.status == 404:
                return True
            raise

    _wait(is_gone)
