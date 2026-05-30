cluster := "arachne-dev"
kubeconfig := justfile_directory() / "dev/kubeconfig"

default:
    @just --list

check:
    @command -v kind    >/dev/null || { echo "missing: kind";    exit 1; }
    @command -v kubectl >/dev/null || { echo "missing: kubectl"; exit 1; }
    @command -v docker  >/dev/null || { echo "missing: docker";  exit 1; }
    @echo "ok: kind, kubectl, docker present"

up: check
    kind create cluster --config dev/kind-cluster.yaml --kubeconfig {{kubeconfig}}
    @echo "export KUBECONFIG={{kubeconfig}}"

down:
    -kind delete cluster --name {{cluster}}
    -rm -f {{kubeconfig}}

recreate: down up

install:
    KUBECONFIG={{kubeconfig}} kubectl apply -f deploy/arachne-installer.yaml

uninstall:
    -KUBECONFIG={{kubeconfig}} kubectl delete -f deploy/arachne-installer.yaml

reload:
    KUBECONFIG={{kubeconfig}} kubectl rollout restart daemonset/arachne -n kube-system

status:
    KUBECONFIG={{kubeconfig}} kubectl get nodes -o wide
    KUBECONFIG={{kubeconfig}} kubectl -n kube-system get pods -l app=arachne -o wide

logs:
    KUBECONFIG={{kubeconfig}} kubectl -n kube-system logs -l app=arachne --all-containers -f --max-log-requests=10
