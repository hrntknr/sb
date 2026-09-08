# sb

`sb` is a credential proxy that issues **scoped, policy-restricted credentials** instead of handing over your real SSH keys or kubeconfig, so you can mount them into another environment (a Docker container, an AI agent sandbox, etc.) and let it use them safely.

It generates `.ssh` / `.kube` under a given directory and proxies SSH and Kubernetes access while enforcing the policy defined in the config file.

## Getting Started

```
$ sb run -- -it ghcr.io/hrntknr/sh:full
```

Or run the proxy manually and mount the generated credentials yourself:

```
$ tmp=$(mktemp -d)
$ sb proxy $tmp &
$ docker run -it --rm --net host -v $tmp/.ssh:/root/.ssh -v $tmp/.kube:/root/.kube ghcr.io/hrntknr/sh:full
```

## Running containers: `sb run`

`sb run` wraps the whole flow: it starts the proxy in the background, picks a runtime, and runs your container with the scoped credentials mounted at `/root/.ssh` and `/root/.kube`. The container's exit code becomes sb's.

The runtime — docker, podman, or the apple container CLI (macOS) — is auto-detected in that order; select one with `container.runtime` in the config. Everything after `--` (or plain arguments, when they don't start with `-`) is passed to the runtime's `run` command unchanged, so native options like `-v` and `-p` work as usual:

```
$ sb run alpine sh
$ sb run -- -v $PWD:/work -p 8080:80 -it node npm run dev
```

The proxy listens on all interfaces and is reached through the runtime's host gateway, so the default bridged networking just works; with `--network host` (docker/podman) it falls back to `localhost`. Runtime compatibility is checked at startup, with hints for what to fix.

The shared flags (`--config`, `--log-level`, `--ssh-agent-env`) also apply; see [Flags](#flags).

Notes:

- `-d`/`--detach` is rejected: the credentials live in a temp dir owned by the `run` process, so the container cannot outlive it.
- The credentials are mounted under `/root`; with `--user`, make sure that user can read `/root`.
- Rootless docker is supported: since its `host-gateway` points inside the daemon's network namespace, the proxy is reached through the host's outbound IP instead.
- A host firewall (firewalld, ufw) can block container-to-host traffic; if `kubectl`/`ssh` inside the container fail with "connection refused" or time out, pass `--network host` (docker/podman).
- apple container needs a one-time setup so containers can reach the Mac: `sudo container system dns create host.container.internal --localhost 203.0.113.113`.
- Rootless podman needs 5.3+ for `host.containers.internal` with the default pasta network; otherwise pass `--network host`.


## Configuration

By default the config is read from `$XDG_CONFIG_HOME/sb/config.yaml` (typically `~/.config/sb/config.yaml` on Linux). Use `--config` to point at any path.

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

### Container: `container`

The `container` section configures how `sb run` launches the container.

```yaml
container:
  runtime: docker               # docker, podman, apple; default is auto-detect
  image: ghcr.io/hrntknr/sh:full
  mounts:
    - ~/.claude:/root/.claude
    - ~/.config/opencode:/root/.config/opencode
    - ~/.cache/opencode:/root/.cache/opencode
```

`runtime` selects docker, podman, or apple (or `auto`, the default) for `sb run`.
`mounts` entries are `<source>:<target>` in docker `-v` syntax; `~` in the source is expanded. The source must be an absolute path (after `~` expansion) and must exist — `run` fails early instead of letting the runtime create it as root.

With `image` set, the arguments form the container command and no arguments at all runs the image's default command; use `--` when the command starts with `-`:

```
$ sb run claude
$ sb run -- claude --settings '{"sandbox":{"enabled":false}}'
```

Without `image`, `run` behaves as before: all arguments are passed to the runtime's run command unchanged, so the first plain argument is the image.

Entries from `conf.d/` are merged: `runtime` and `image` are overridden by later files, and `mounts` are appended with exact duplicates removed.

k8s policy is keyed by **kubeconfig context name**. Contexts that point at the same cluster are isolated from each other, so granting `rw` to the `dev` context does not grant `rw` to a `prod` context even when both use the same cluster.

### Drop-in: `conf.d/`

Additional `*.yaml` (or `*.yml`) files placed in a `conf.d/` directory next to `config.yaml` are merged into the main config. Files are loaded in alphabetical order, so name them with a numeric prefix (e.g. `10-work.yaml`) to control precedence. Targets in later files with the same `host` (SSH) or `context` (k8s) override earlier ones; new targets are appended.

```
~/.config/sb/
  config.yaml
  conf.d/
    10-work.yaml
    20-overrides.yaml
```

### Reloading

The config (including `conf.d/`) is watched and reloaded automatically; policy changes take effect without restarting sb. A reload that fails (e.g. invalid yaml) keeps the previous config and retries on the next change.

## Following ssh-agent restarts

Upstream SSH connections authenticate with the keys loaded in your ssh-agent. The agent socket path is resolved on every connection, so an agent restarted with the same `SSH_AUTH_SOCK` is picked up automatically.

If the socket path changes across restarts, point `--ssh-agent-env` at a file that sets `SSH_AUTH_SOCK`. The file is parsed as shell source, so the raw output of `ssh-agent` works as-is:

```
$ ssh-agent > ~/.cache/sb-agent.env
$ sb proxy --ssh-agent-env ~/.cache/sb-agent.env $tmp &
```

When the flag is omitted, the `SSH_AUTH_SOCK` environment variable of the sb process is used.

## Transport verification

Upstream SSH connections verify host keys against your known_hosts, honoring the `StrictHostKeyChecking` of your ssh config. `no` disables verification; `accept-new` trusts unknown keys on first use and records them; anything else (including the default `ask`, which cannot prompt here) requires the host key to be already known — connect once directly (`ssh <host>`) to record it. `HostKeyAlias` is honored like ssh; `KnownHostsCommand` is not supported and fails closed.

The generated kubeconfig embeds the proxy's TLS certificate (`certificate-authority-data`), so downstream kubectl verifies the proxy's TLS connection instead of skipping verification. The certificate covers `localhost`, `127.0.0.1`, `::1`, and the `--host` value.

## Flags

Shared flags (available on every subcommand): `--config`, `--log-level`, and `--ssh-agent-env` (see the [ssh-agent section](#following-ssh-agent-restarts) for the latter). `sb proxy` adds:

| Flag               | Default                              | Description                                             |
| ------------------ | ------------------------------------ | ------------------------------------------------------- |
| `--host`           | `localhost`                          | Host written into the generated config                  |
| `--ssh-listen`     | `:0`                                 | SSH listen address                                      |
| `--k8s-listen`     | `:0`                                 | k8s listen address                                      |

## Build

```
$ make build      # produces ./sb
$ make install    # installs into $PREFIX (default ~/.local/bin)
```
