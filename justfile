cluster := "arachne-dev"
kubeconfig := justfile_directory() / "dev/kubeconfig"
image := "arachne:dev"

default:
    @just --list

check:
    @command -v kind    >/dev/null || { echo "missing: kind";    exit 1; }
    @command -v kubectl >/dev/null || { echo "missing: kubectl"; exit 1; }
    @command -v docker  >/dev/null || { echo "missing: docker";  exit 1; }
    @echo "ok: kind, kubectl, docker present"

up: check
    kind create cluster --config dev/kind-cluster.yaml --kubeconfig {{kubeconfig}}

down:
    -kind delete cluster --name {{cluster}}
    -rm -f {{kubeconfig}}

recreate: down up

build:
    docker build -t {{image}} .

load: build
    kind load docker-image {{image}} --name {{cluster}}

install: load
    KUBECONFIG={{kubeconfig}} kubectl apply -f deploy/arachne-installer.yaml

uninstall:
    -KUBECONFIG={{kubeconfig}} kubectl delete -f deploy/arachne-installer.yaml

reload: install
    KUBECONFIG={{kubeconfig}} kubectl rollout restart daemonset/arachne -n kube-system

test:
    cargo test

e2e:
    KUBECONFIG={{kubeconfig}} uv run --with-requirements dev/requirements.txt pytest dev/e2e_test.py -v
