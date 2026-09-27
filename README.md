# sb

`sb` is a credential proxy that issues **scoped, policy-restricted credentials** instead of handing over your real SSH keys, kubeconfig, or AWS credentials, so you can mount them into another environment (a Docker container, an AI agent sandbox, etc.) and let it use them safely.

It generates `.ssh` / `.kube` / `.aws` under a given directory and proxies SSH, Kubernetes, and supported AWS access while enforcing the policy defined in the config file. A request the policy does not allow is never sent upstream.

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

The config must be the v3 form (`version: 3`); converting a v2 config is manual — see [Migrating from v2 to v3](docs/migration.md).

## Running containers: `sb run`

`sb run` wraps the whole flow: it starts the proxy in the background, picks a runtime, and runs the image set as `container.image` in the config with the scoped credentials mounted read-only at `/root/.ssh`, `/root/.kube`, and `/root/.aws`. The container's exit code becomes sb's.

The session is named with `--name`: the same name identifies it to `sb exec`, and starting a second live session with that name is refused. Omitting `--name` generates a fresh name, printed on stderr, so a second run never collides with the first.

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

Whatever ends the run — the container's exit, a signal, or a proxy failure — goes through the same stop flow. sb stops accepting new requests and cancels what the running requests started upstream (SSH forwarding, k8s watch and `logs -f` streams), waiting for their cleanup within the deadline. Then it stops and removes the session's containers by their session label, deletes the issued credentials, and drops the session record. Whatever could not be reclaimed — a runtime that does not answer, or a write still in flight — is reported with the steps to reclaim it by hand; the next `sb run` retries with what stayed.

A killed sb reclaims nothing synchronously. The next startup sweeps the sessions whose locks no longer protect them — orphaned by a kill or a crash — and reclaims what they left: their containers are stopped and removed by the session label, the issued credentials deleted, the records dropped. A live session is never touched.

Notes:

- The credentials are mounted under `/root`; a container that runs as a non-root user must be able to read `/root`.
- Rootless docker is supported: since its `host-gateway` points inside the daemon's network namespace, the proxy is reached through the host's outbound IP instead.
- A host firewall (firewalld, ufw) can block container-to-host traffic; if `kubectl`/`ssh` inside the container fail with "connection refused" or time out, pass `--network host` (docker/podman).
- apple container needs a one-time setup so containers can reach the Mac: `sudo container system dns create host.container.internal --localhost 203.0.113.113`.
- The container runs without an init process by default; pass `--init` to run the command under an init process as PID 1 that forwards signals and reaps zombie processes.
- Rootless podman needs 5.3+ for `host.containers.internal` with the default pasta network; otherwise pass `--network host`.


## Running commands inside: `sb exec`

While `sb run` is running, `sb exec` runs a command inside its container from another terminal. It targets the session by the name the run used: the runtime, the container ID, and the session label come from that session's record, cross-checked against the runtime's own records, so a session that is not alive, or a container that took over the name, connects to nothing. The current config is not consulted. The command's exit code becomes sb's.

```
$ sb exec zsh -l
$ sb exec --name dev -- kubectl get pods
$ sb exec -w /work -- pwd
```


## Configuration

The config is the v3 form: it starts with `version: 3`, and everything in it is checked — unknown fields, invalid permissions, and empty required values are rejected at load, and the same binary does not silently accept a v2 config. Converting from v2 is manual; see [Migrating from v2 to v3](docs/migration.md).

By default the config is read from `$XDG_CONFIG_HOME/sb/config.yaml` (typically `~/.config/sb/config.yaml` on Linux). Use `--config` to point at any path.

```yaml
version: 3
container:
  runtime: docker
  image: ghcr.io/hrntknr/sh:full
  mounts:
    - source: ~/work
      target: /work
      readOnly: false
  environment:
    LANG: {inherit: true}
    FOO: {value: bar}
ssh:
  - host: github.com
    user: git                 # optional: restricts the upstream user
    port: 22                  # optional: restricts the upstream port
    access: full
k8s:
  - context: dev
    resources:
      - group: ""             # "" is the core API group
        resource: pods
        namespace: default
        verbs: [get, list, watch]
      - group: ""
        resource: pods/log
        namespace: default
        verbs: [get]          # kubectl logs, including -f
aws:
  - profile: dev
    roleArn: arn:aws:iam::123456789012:role/sb-dev    # optional
    regions: [eu-west-1]
    services:
      - name: dynamodb
        mode: ro
```

`host` (ssh) and `profile` and `regions` (aws) support glob patterns (`*` matches any string, `?` matches a single character). aws `profile` patterns are expanded at startup to the profiles that exist in the source credentials; a pattern that matches no profile is a startup error. k8s `context` names are exact.

### Container: `container`

The `container` section configures how `sb run` launches the container.

`runtime` selects docker, podman, or apple (or `auto`, the default) for `sb run`. `mounts` entries have `source`, `target`, and `readOnly`: `~` in the source is expanded, the source must be an absolute path that exists — `run` fails early instead of letting the runtime create it as root — the target must be an absolute container path, and two targets may not overlap. `environment` entries are `KEY: {inherit: true}` or `KEY: {value: bar}`: an inherited variable comes from the sb process's environment.

`image` is required for `sb run`; the arguments form the container command and no arguments at all runs the image's default command. Use `--` when the command starts with `-`:

```
$ sb run claude
$ sb run -- claude --settings '{"sandbox":{"enabled":false}}'
```

### ssh: hosts and access

SSH `host` rules match the `HostName` resolved by `ssh -G` on the machine running sb, not the alias typed by the client. For example, `Host gw` with `HostName g.hrntknr.net` matches a policy for `*.hrntknr.net` — and two aliases that resolve to the same hostname are the same permission. `user` and `port` are optional additional restrictions on the upstream connection: when set, the connection must use exactly that user or port; when omitted, whatever the upstream ssh config resolves is accepted.

`access: full` is the whole upstream account on the matched host: the shell, any exec, subsystem, and TCP forwarding, reverse forwarding included. sb cannot prove any restriction from a free-form shell string, so the initial version has no other access mode.

### k8s: contexts and resources

k8s policy is keyed by **kubeconfig context name**. The context is both the selection in the source kubeconfig and the partition of the permission: only the contexts named in the policy go into the generated kubeconfig, and the rules of one context never apply to another — granting `get` on the `dev` context does not grant it on a `prod` context even when both point at the same cluster. A context the policy names that does not resolve from the source kubeconfig is a startup error.

What a context resolves to — the server URL, TLS verification, and auth settings — is fixed for the session: requests reuse it without reloading the kubeconfig, and a downstream token works only on its own context's URL. The issued kubeconfig is read-only by design: `kubectl config use-context` cannot write to it. Pass `--context` or `-n` per command, or copy the kubeconfig somewhere writable and edit the copy — the `context` key stays the switch.

`resources` enumerate every grant: `group` (required; `""` is the core API group), `resource`, `namespace` (required; `*` is an explicit all-namespaces grant, distinct from a single name) or `scope: cluster` for cluster-scoped resources, and `verbs`. The initial version supports `get`, `list`, `watch` for regular resources and `get` for `pods/log` (`kubectl logs`, including `-f` as a `follow=true` GET). A `pods` grant does not inherit to `pods/log`.

Requests are classified as the Kubernetes API server classifies them: the group, resource, subresource, verb, and namespace are matched against the rules, and what no rule covers — unknown paths, other subresources, impersonation headers, upgrade — is rejected before the upstream. Non-resource requests are limited to the fixed discovery paths (`/api`, `/apis`, core `/api/v1`, group discovery, openapi, and the version endpoint) as GET.

RBAC is the final upper bound, and `get`/`list`/`watch` and log reads can still return Secrets and log-carried credentials — choose the resources you grant carefully.

### AWS profiles

AWS policy is keyed by **source profile name**. Each allowed profile is written to the generated `.aws/config` and `.aws/credentials` with a new proxy-only key and an HTTPS `endpoint_url` (and `ca_bundle`). The proxy verifies SigV4, checks the profile, region, service, and operation, then signs upstream requests with the assumed role's credentials — without a session policy: the proxy filter alone enforces the policy, and the role's own IAM permissions are the only AWS-side upper bound. `roleArn` may be omitted: without it the proxy signs upstream requests with the source profile's own credentials and no role is assumed; `roleArn` must otherwise match `arn:aws:iam::<account>:role/<name>`. When set, the source profile must be able to call `sts:AssumeRole` on that role and the role must trust that source principal, and matching targets must agree on the role. Long-running sessions are refreshed automatically. The source credentials never enter the container.

`services` supports JSON (`X-Amz-Target`), Query (form-encoded `Action`), and EC2 POST APIs covered by the embedded [AWS Service Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html) — currently 128 services, including `sts`, `ec2`, `dynamodb`, `logs`, `kinesis`, `iam`, `ses`, `budgets`, and Cost Explorer. REST (`route53`, `s3` itself), CBOR, SigV2, multi-endpoint services that cannot be represented by one fixed or regional host template, and console-only services (`a2c`) are rejected when loading the config. For `ro`, an operation is permitted only when every action exercising it matches the [AWS ReadOnlyAccess policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html). Operations with any non-read-only action or without an operation-to-action mapping fail closed for `ro`. A supported service without any read operation has an empty `read` list.

sb validates the wire shape before authorizing it: JSON requests must use the model's exact `application/x-amz-json-*` media type and `targetPrefix` with a JSON object body, while Query and EC2 requests must use `application/x-www-form-urlencoded`, provide exactly one form-encoded `Action`, and omit `X-Amz-Target`. Upstream hosts and signing-region overrides are not inferred from endpoint-rule text. `cd tools/gen_aws_policy && uv run python main.py` runs the uv-pinned botocore endpoint provider (`pyproject.toml`, `uv.lock`) for every commercial AWS region and keeps only results that mechanically reduce to one fixed host or one `{region}` host template. It also fetches the current default ReadOnlyAccess policy and AWS Service Reference mappings, then updates the committed `services.json` only when its content changes. Regeneration requires `uv`; bump the botocore pin in `pyproject.toml` to refresh endpoint data.

AWS ReadOnlyAccess includes operations that return credentials, authentication tokens, client secrets, or remote-access endpoints. These operations are allowed in `ro`. A returned credential or capability may remain usable outside sb, bypassing its service, region, request-shape, logging, and lifecycle controls; some can lead to a different principal whose permissions are not bounded by the assumed role. The assumed role's IAM permissions are the AWS-side upper bound only where the returned capability represents that same principal. Use a dedicated role with AWS ReadOnlyAccess or a stricter policy when this risk is unacceptable.

`regions` restricts requests in sb (the IAM policy of the role is not region-scoped). The generated profile and upstream STS use the source region, falling back to `us-east-1`. If the source has no `default` profile, sb uses the host's environment or container/instance credentials for it; unset `AWS_PROFILE`/`AWS_DEFAULT_PROFILE` in that case. Profile names may use letters, digits, `_`, `-`, `.`, `@`, and `+`. An AWS client must honor the shared-config `endpoint_url` and `ca_bundle` settings; clients that ignore them cannot use these proxy-only keys. Presigned URLs, streaming requests, and custom AWS endpoints are not supported. Supported requests are SigV4 POST with signed payloads. When using `sb proxy` manually, mount `.aws` at `/root/.aws` so the generated CA path remains valid.

### Drop-in: `conf.d/`

Additional `*.yaml` (or `*.yml`) files placed in a `conf.d/` directory next to `config.yaml` are loaded in alphabetical order, so name them with a numeric prefix (e.g. `10-work.yaml`) for a stable order. Every target must be defined exactly once: the same ssh `host`, k8s `context`, or aws `profile` in two files, the same mount `target` or environment key twice, or `container.image`/`container.runtime` in two files is an error. To remove or replace a definition, edit the file that defines it.

```
~/.config/sb/
  config.yaml
  conf.d/
    10-work.yaml
    20-other.yaml
```

### Applying changes

The config (including `conf.d/`) is read once per session: the running session's permission set is fixed, and a change — the sb policy config, or the source kubeconfig a k8s context resolves from — lands at the next `sb run` or `sb proxy`. The host-side ssh config is still resolved per SSH connection (`ssh -G`), so a change there shows up on the next connection; the host, user, and port conditions stay fixed for the session.

## Following ssh-agent restarts

Upstream SSH connections authenticate with the keys loaded in your ssh-agent. The agent socket path is read from the sb process's `SSH_AUTH_SOCK` on every upstream dial, so an agent restarted with the same socket path is picked up automatically. When the socket path changes across restarts, restart sb with the new `SSH_AUTH_SOCK` in its environment.

## Transport verification

Upstream SSH connections verify host keys against your known_hosts, honoring the `StrictHostKeyChecking` of your ssh config. `no` disables verification; `accept-new` trusts unknown keys on first use and records them; anything else (including the default `ask`, which cannot prompt here) requires the host key to be already known — connect once directly (`ssh <host>`) to record it. `HostKeyAlias` is honored like ssh; `KnownHostsCommand` is not supported and fails closed.

The generated kubeconfig embeds the proxy's TLS certificate (`certificate-authority-data`), so downstream kubectl verifies the proxy's TLS connection instead of skipping verification. The certificate covers `localhost`, `127.0.0.1`, `::1`, and the `--host` value.

SSH host key negotiation prioritizes key types already registered for the target in user and global known_hosts files, including hashed entries and `HostKeyAlias`. RSA keys support SHA-2 signatures, and trusted host CAs can sign host certificates of any supported key type. The negotiated key is still verified against known_hosts.

## Limits

What sb revokes is bounded by the proxy's lifetime: the credentials it issues work only while it is running, and stopping sb is their revocation — a copy taken to the destination with `sb proxy` is dead once sb stops. Anything else that got out — a credential or URL an upstream returns inside a response (an AWS `ro` operation, a Secret read through k8s) — cannot be revoked by sb. Restrict it upstream — IAM for AWS, RBAC for k8s — where that matters.

## Flags

Shared flags (available on every subcommand): `--config`, which accepts the v3 form only (`version: 3`; a v2 config is rejected), and `--log-level`. `sb proxy` adds:

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
