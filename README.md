# secretbridge

`secretbridge` is a credential proxy that issues **scoped, policy-restricted credentials** instead of handing over your real SSH keys or kubeconfig, so you can mount them into another environment (a Docker container, an AI agent sandbox, etc.) and let it use them safely.

It generates `.ssh` / `.kube` under a given directory and proxies SSH and Kubernetes access while enforcing the policy defined in the config file.

## Getting Started

```
$ tmp=$(mktemp -d)
$ secretbridge $tmp &
$ docker run -it --rm --net host -v $tmp/.ssh:/root/.ssh -v $tmp/.kube:/root/.kube ghcr.io/hrntknr/sh:full
```

## Configuration

By default the config is read from `$XDG_CONFIG_HOME/secretbridge/config.yaml` (typically `~/.config/secretbridge/config.yaml` on Linux). Use `--config` to point at any path.

```yaml
ssh:
  - host: github.com            # omitting commands allows everything, including shell and port forwarding
  - host: "*.hrntknr.net"
  - host: "*"
    commands:                   # restrict to specific commands
      - cat
      - ls
      - kubectl get
k8s:
  - cluster: pear
    mode: rw                    # r (read-only) / rw (read-write)
  - cluster: test
    mode: rw
  - cluster: "*"
    mode: r
    namespace: default          # omit for cluster scope
```

`host`, `cluster`, `namespace`, and `commands` all support glob patterns (`*` matches any string, `?` matches a single character). `commands` is split into tokens and each token is matched.

### Drop-in: `conf.d/`

Additional `*.yaml` (or `*.yml`) files placed in a `conf.d/` directory next to `config.yaml` are merged into the main config. Files are loaded in alphabetical order, so name them with a numeric prefix (e.g. `10-work.yaml`) to control precedence. Targets in later files with the same `host` (SSH) or `cluster` (k8s) override earlier ones; new targets are appended.

```
~/.config/secretbridge/
  config.yaml
  conf.d/
    10-work.yaml
    20-overrides.yaml
```

## Flags

| Flag           | Default                              | Description                                    |
| -------------- | ------------------------------------ | ---------------------------------------------- |
| `--config`     | `~/.config/secretbridge/config.yaml` | Path to the config file                        |
| `--host`       | proxy host                           | Host written into the generated config         |
| `--log-level`  | `silent`                             | `silent` / `debug` / `info` / `warn` / `error` |
| `--ssh-listen` | `:0`                                 | SSH listen address                             |
| `--k8s-listen` | `:0`                                 | k8s listen address                             |

## Build

```
$ make build      # produces ./secretbridge
$ make install    # installs into $PREFIX (default ~/.local/bin)
```
