# arachne dev cluster

A 3-node [kind](https://kind.sigs.k8s.io) cluster (1 control-plane + 2 workers) with
the default CNI disabled, for developing the arachne CNI and eBPF datapath.

## Prerequisites

```sh
# kind (Go install or pacman/AUR on CachyOS)
go install sigs.k8s.io/kind@latest        # or: yay -S kind-bin
# just
cargo install just                        # or: pacman -S just
# direnv (auto-loads KUBECONFIG in this dir)
pacman -S direnv                          # then hook into fish (see below)
# kubectl + docker are already present
```

## Usage

```sh
just up        # create the cluster (nodes start NotReady -- expected)
just install   # apply the arachne DaemonSet (CNI installer + agent stub)
just status    # node + pod status
just logs      # tail agent logs
just reload    # rebuild + reload + restart (cargo/image steps stubbed for now)
just down      # tear it all down
```

Kubeconfig is written to `dev/kubeconfig` (not your default `~/.kube/config`).
A `.envrc` exports `KUBECONFIG` automatically via [direnv](https://direnv.net)
whenever you're in the project dir, so `kubectl` targets the kind cluster with
no manual export.

One-time setup:

```sh
# hook direnv into fish (add to ~/.config/fish/config.fish)
direnv hook fish | source
# approve this project's .envrc
direnv allow
```

Without direnv, fall back to exporting it yourself:

```sh
export KUBECONFIG="$PWD/dev/kubeconfig"
```
