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
  - context: pear               # kubeconfig context names
    mode: rw                    # r (read-only) / rw (read-write)
  - context: test
    mode: rw
  - context: "*"
    mode: r
    namespace: default          # omit for cluster scope
```

`host`, `context`, `namespace`, and `commands` all support glob patterns (`*` matches any string, `?` matches a single character). `commands` is split into tokens and each token is matched.

k8s policy is keyed by **kubeconfig context name**. Contexts that point at the same cluster are isolated from each other, so granting `rw` to the `dev` context does not grant `rw` to a `prod` context even when both use the same cluster.

### Drop-in: `conf.d/`

Additional `*.yaml` (or `*.yml`) files placed in a `conf.d/` directory next to `config.yaml` are merged into the main config. Files are loaded in alphabetical order, so name them with a numeric prefix (e.g. `10-work.yaml`) to control precedence. Targets in later files with the same `host` (SSH) or `context` (k8s) override earlier ones; new targets are appended.

```
~/.config/secretbridge/
  config.yaml
  conf.d/
    10-work.yaml
    20-overrides.yaml
```

## Following ssh-agent restarts

Upstream SSH connections authenticate with the keys loaded in your ssh-agent. The agent socket path is resolved on every connection, so an agent restarted with the same `SSH_AUTH_SOCK` is picked up automatically.

If the socket path changes across restarts, point `--ssh-agent-env` at a file that sets `SSH_AUTH_SOCK`. The file is parsed as shell source, so the raw output of `ssh-agent` works as-is:

```
$ ssh-agent > ~/.cache/secretbridge-agent.env
$ secretbridge --ssh-agent-env ~/.cache/secretbridge-agent.env $tmp &
```

When the flag is omitted, the `SSH_AUTH_SOCK` environment variable of the secretbridge process is used.

## Transport verification

Upstream SSH connections verify host keys against your known_hosts, honoring the `StrictHostKeyChecking` of your ssh config. `no` disables verification; `accept-new` trusts unknown keys on first use and records them; anything else (including the default `ask`, which cannot prompt here) requires the host key to be already known — connect once directly (`ssh <host>`) to record it. `HostKeyAlias` is honored like ssh; `KnownHostsCommand` is not supported and fails closed.

The generated kubeconfig embeds the proxy's TLS certificate (`certificate-authority-data`), so downstream kubectl verifies the proxy's TLS connection instead of skipping verification. The certificate covers `localhost`, `127.0.0.1`, `::1`, and the `--host` value.

## Flags

| Flag               | Default                              | Description                                             |
| ------------------ | ------------------------------------ | ------------------------------------------------------- |
| `--config`         | `~/.config/secretbridge/config.yaml` | Path to the config file                                 |
| `--host`           | `localhost`                          | Host written into the generated config                  |
| `--log-level`      | `silent`                             | `silent` / `debug` / `info` / `warn` / `error`           |
| `--ssh-listen`     | `:0`                                 | SSH listen address                                      |
| `--k8s-listen`     | `:0`                                 | k8s listen address                                      |
| `--ssh-agent-env`  | (none)                               | Env file exporting `SSH_AUTH_SOCK`, re-read per connection |

## Build

```
$ make build      # produces ./secretbridge
$ make install    # installs into $PREFIX (default ~/.local/bin)
```
