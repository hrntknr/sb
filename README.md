# sb

`sb` is a credential proxy that issues **scoped, policy-restricted credentials** instead of handing over your real SSH keys, kubeconfig, or AWS credentials, so you can mount them into another environment (a Docker container, an AI agent sandbox, etc.) and let it use them safely.

It generates `.ssh` / `.kube` / `.aws` under a given directory and proxies SSH, Kubernetes, and supported AWS access while enforcing the policy defined in the config file.

## Getting Started

Set `container.image` in the config (see [Configuration](#configuration)), then:

```
$ sb run
```

Or run the proxy manually and mount the generated credentials yourself:

```
$ tmp=$(mktemp -d)
$ sb proxy $tmp &
$ docker run -it --rm --net host -v $tmp/.ssh:/root/.ssh -v $tmp/.kube:/root/.kube -v $tmp/.aws:/root/.aws ghcr.io/hrntknr/sh:full
```

## Running containers: `sb run`

`sb run` wraps the whole flow: it starts the proxy in the background, picks a runtime, and runs the image set as `container.image` in the config with the scoped credentials mounted at `/root/.ssh`, `/root/.kube`, and `/root/.aws`. The container's exit code becomes sb's. The container is named with `--name` (default `default`), so that [`sb exec`](#running-commands-inside-sb-exec) can target it.

The runtime — docker, podman, or the apple container CLI (macOS) — is auto-detected in that order; select one with `container.runtime` in the config. The arguments form the container command; no arguments at all runs the image's default command. Use `--` when the command starts with `-`:

```
$ sb run
$ sb run zsh -l
$ sb run -- claude --settings '{"sandbox":{"enabled":false}}'
```

`sb run` also accepts `--network <n>`, passed to the runtime:

```
$ sb run --network host zsh -l
```

The proxy listens on all interfaces and is reached through the runtime's host gateway, so the default bridged networking just works; with `--network host` (docker/podman) it falls back to `localhost`. Runtime compatibility is checked at startup, with hints for what to fix.

The shared flags (`--config`, `--log-level`) also apply; see [Flags](#flags).

Notes:

- If the proxy fails while the container is running, the container is force-removed (`rm -f` via a `--cidfile`) so it cannot outlive its credentials.
- The credentials are mounted under `/root`; with `--user`, make sure that user can read `/root`.
- Rootless docker is supported: since its `host-gateway` points inside the daemon's network namespace, the proxy is reached through the host's outbound IP instead.
- A host firewall (firewalld, ufw) can block container-to-host traffic; if `kubectl`/`ssh` inside the container fail with "connection refused" or time out, pass `--network host` (docker/podman).
- apple container needs a one-time setup so containers can reach the Mac: `sudo container system dns create host.container.internal --localhost 203.0.113.113`.
- The container runs without an init process by default; pass `--init` to run the command under an init process as PID 1 that forwards signals and reaps zombie processes.
- Rootless podman needs 5.3+ for `host.containers.internal` with the default pasta network; otherwise pass `--network host`.


## Running commands inside: `sb exec`

While `sb run` is running, `sb exec` runs a command inside its container from another terminal. It targets the run's `--name` (`default` when not given):

```
$ sb exec zsh -l
$ sb exec --name dev -- kubectl get pods
$ sb exec -w /work -- pwd
```

The runtime is selected like `sb run` (`container.runtime` or auto-detection); the command's exit code becomes sb's.


## Configuration

By default the config is read from `$XDG_CONFIG_HOME/sb/config.yaml` (typically `~/.config/sb/config.yaml` on Linux). Use `--config` to point at any path.

```yaml
ssh:
  - host: github.com
  - host: "*.hrntknr.net"
k8s:
  - context: pear               # kubeconfig context names
    mode: rw                    # r (read-only) / rw (read-write)
    secret: false               # allow Secret access; default false
  - context: test
    mode: rw
  - context: "*"
    mode: r
    namespace: default          # omit for every namespace (and cluster scope)
aws:
  - profile: dev                 # source AWS profile name
    roleArn: arn:aws:iam::123456789012:role/sb-dev
    regions: [eu-west-1]        # optional; defaults to all regions
    mode: r                     # default for services without their own mode
    services:
      - name: dynamodb        # inherits the default r
      - name: ec2
        mode: rw               # overrides the default
  - profile: default            # no services: mode applies to every service
    mode: rw
proxy:
  sshAgentEnv: ~/.cache/sb-agent.env
```

`host`, `context`, and `namespace` support glob patterns (`*` matches any string, `?` matches a single character).

SSH `host` rules match the `HostName` resolved by `ssh -G` on the machine running sb, not the alias typed by the client. For example, `Host gw` with `HostName g.hrntknr.net` matches a policy for `*.hrntknr.net`. Connections to hosts that no longer match any target are closed when the config reloads.

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
  environments:
    - FOO=bar                   # KEY=VALUE, or just KEY to inherit from sb's environment
    - LANG
```

`runtime` selects docker, podman, or apple (or `auto`, the default) for `sb run`.
`mounts` entries are `<source>:<target>` in docker `-v` syntax; `~` in the source is expanded. The source must be an absolute path (after `~` expansion) and must exist — `run` fails early instead of letting the runtime create it as root.
`environments` entries are `KEY=VALUE`, or just `KEY` to inherit the variable from the sb process's environment.

`image` is required for `sb run`; the arguments form the container command and no arguments at all runs the image's default command. Use `--` when the command starts with `-`:

```
$ sb run claude
$ sb run -- claude --settings '{"sandbox":{"enabled":false}}'
```

Entries from `conf.d/` are merged: `runtime` and `image` are overridden by later files, and `mounts` and `environments` are appended with exact duplicates removed.

k8s policy is keyed by **kubeconfig context name**. Contexts that point at the same cluster are isolated from each other, so granting `rw` to the `dev` context does not grant `rw` to a `prod` context even when both use the same cluster. A `namespace` restricts the target to that namespace and disables cluster scope (non-namespaced resources and non-resource requests like API discovery); omitting it grants every namespace and cluster scope. `secret: true` additionally allows Secret access (get/list Secret resources); without it, requests that access Secret resources are denied.

### AWS profiles

AWS policy is keyed by **source profile name**. Each allowed profile is written to the generated `.aws/config` and `.aws/credentials` with a new proxy-only key and an HTTPS `endpoint_url` (and `ca_bundle`). The proxy verifies SigV4, checks the profile, region, service, and operation, then signs upstream requests with the assumed role's credentials — without a session policy: the proxy filter alone enforces the policy, and the role's own IAM permissions are the only AWS-side upper bound. `roleArn` may be omitted: without it the proxy signs upstream requests with the source profile's own credentials and no role is assumed; `roleArn` must otherwise match `arn:aws:iam::<account>:role/<name>`. When set, the source profile must be able to call `sts:AssumeRole` on that role and the role must trust that source principal, and matching targets must agree on the role. Long-running sessions are refreshed automatically. The source credentials never enter the container. A `mode` on the target (`r` = ReadOnlyAccess actions only, `rw` = all operations) is the default for its `services`; each service's own `mode` overrides it. `services` may be omitted: the mode then applies to every supported service. Source profiles using login sessions (`aws login`, `login_session`) resolve natively through the SDK, which reads and refreshes the token cache `aws login` wrote under `~/.aws/login/cache`.

`services` supports JSON (`X-Amz-Target`), Query (form-encoded `Action`), and EC2 POST APIs covered by the embedded [AWS Service Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html) — currently 128 services, including `sts`, `ec2`, `dynamodb`, `logs`, `kinesis`, `iam`, `ses`, `budgets`, and Cost Explorer. REST (`route53`, `s3` itself), CBOR, SigV2, multi-endpoint services that cannot be represented by one fixed or regional host template, and console-only services (`a2c`) are rejected when loading the config. For `r`, an operation is permitted only when every action exercising it matches the [AWS ReadOnlyAccess policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html). Operations with any non-read-only action or without an operation-to-action mapping fail closed for `r`. A supported service without any read operation has an empty `read` list.

AWS ReadOnlyAccess includes operations that return credentials, authentication tokens, client secrets, or remote-access endpoints. These operations are allowed in `r`. A returned credential or capability may remain usable outside sb, bypassing its service, region, request-shape, logging, and lifecycle controls; some can lead to a different principal whose permissions are not bounded by the assumed role. The assumed role's IAM permissions are the AWS-side upper bound only where the returned capability represents that same principal. Use a dedicated role with AWS ReadOnlyAccess or a stricter policy when this risk is unacceptable.

sb validates the wire shape before authorizing it: JSON requests must use the model's exact `application/x-amz-json-*` media type and `targetPrefix` with a JSON object body, while Query and EC2 requests must use `application/x-www-form-urlencoded`, provide exactly one form-encoded `Action`, and omit `X-Amz-Target`. Upstream hosts and signing-region overrides are not inferred from endpoint-rule text. `cd tools/gen_aws_policy && uv run python main.py` runs the uv-pinned botocore endpoint provider (`pyproject.toml`, `uv.lock`) for every commercial AWS region and keeps only results that mechanically reduce to one fixed host or one `{region}` host template. It also fetches the current default ReadOnlyAccess policy and AWS Service Reference mappings, then updates the committed `services.json` only when its content changes. Regeneration requires `uv`; bump the botocore pin in `pyproject.toml` to refresh endpoint data.

`regions` restricts requests in sb (the IAM policy of the role is not region-scoped). The generated profile and upstream STS use the source region, falling back to `us-east-1`. If the source has no `default` profile, sb uses the host's environment or container/instance credentials for it; unset `AWS_PROFILE`/`AWS_DEFAULT_PROFILE` in that case. Profile names may use letters, digits, `_`, `-`, `.`, `@`, and `+`. An AWS client must honor the shared-config `endpoint_url` and `ca_bundle` settings; clients that ignore them cannot use these proxy-only keys. Presigned URLs, streaming requests, and custom AWS endpoints are not supported. Supported requests are SigV4 POST with signed payloads. When using `sb proxy` manually, mount `.aws` at `/root/.aws` so the generated CA path remains valid.

### Drop-in: `conf.d/`

Additional `*.yaml` (or `*.yml`) files placed in a `conf.d/` directory next to `config.yaml` are merged into the main config. Files are loaded in alphabetical order, so name them with a numeric prefix (e.g. `10-work.yaml`) to control precedence. Targets in later files with the same `host` (SSH), `context` (k8s), or `profile` (AWS) override earlier ones; new targets are appended.

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

If the socket path changes across restarts, set `proxy.sshAgentEnv` in the config to a file that sets `SSH_AUTH_SOCK`. The file is parsed as shell source, so the raw output of `ssh-agent` works as-is:

```
$ ssh-agent > ~/.cache/sb-agent.env
```

with `proxy.sshAgentEnv: ~/.cache/sb-agent.env` in the config. When unset, the `SSH_AUTH_SOCK` environment variable of the sb process is used.

## Transport verification

Upstream SSH connections verify host keys against your known_hosts, honoring the `StrictHostKeyChecking` of your ssh config. `no` disables verification; `accept-new` trusts unknown keys on first use and records them; anything else (including the default `ask`, which cannot prompt here) requires the host key to be already known — connect once directly (`ssh <host>`) to record it. `HostKeyAlias` is honored like ssh; `KnownHostsCommand` is not supported and fails closed.

The generated kubeconfig embeds the proxy's TLS certificate (`certificate-authority-data`), so downstream kubectl verifies the proxy's TLS connection instead of skipping verification. The certificate covers `localhost`, `127.0.0.1`, `::1`, and the `--host` value.

SSH host key negotiation prioritizes key types already registered for the target in user and global known_hosts files, including hashed entries and `HostKeyAlias`. RSA keys support SHA-2 signatures, and trusted host CAs can sign host certificates of any supported key type. The negotiated key is still verified against known_hosts.

## Flags

Shared flags (available on every subcommand): `--config` and `--log-level`. `sb proxy` adds:

| Flag           | Default     | Description                            |
| -------------- | ----------- | -------------------------------------- |
| `--host`       | `localhost` | Host written into the generated config |
| `--ssh-listen` | `:0`        | SSH listen address                     |
| `--k8s-listen` | `:0`        | k8s listen address                     |
| `--aws-listen` | `:0`        | AWS listen address                     |

## Build

```
$ make build      # produces ./sb
$ make install    # installs into $PREFIX (default ~/.local/bin)
```
