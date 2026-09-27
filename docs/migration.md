# Migrating from v2 to v3

sb v3 reads a new config format. A v3 config starts with `version: 3`:

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
    user: git
    port: 22
    access: full
k8s:
  - context: dev
    resources:
      - group: ""
        resource: pods
        namespace: default
        verbs: [get, list, watch]
      - group: ""
        resource: pods/log
        namespace: default
        verbs: [get]
aws:
  - profile: dev
    roleArn: arn:aws:iam::123456789012:role/sb-dev
    regions: [eu-west-1]
    services:
      - name: dynamodb
        mode: ro
```

## Config scope

sb reads the v3 config everywhere: `sb config check`, `sb run`, and `sb proxy` all reject the v2 config (`version` absent or the old structure) and read the v3 config (`version: 3`). Convert the v2 config manually (below); `sb config check` confirms the result.

## v2 config is rejected, not converted

`--config` accepts v3 only. A v2 config (no `version` key, or the old structure) fails with an error that points here, for example:

```
$ sb config check
config.yaml: version is required: sb reads v3 config only (version: 3);
v2 config is not accepted (see docs/migration.md)
```

This is deliberate. v2's restrictions cannot be converted automatically without changing what they mean:

- An **ssh** `commands` list cannot become a v3 restriction: sb cannot prove any restriction from a free-form shell string, so any conversion would silently grant more than v2 did.
- A **k8s** `mode` cannot become a v3 rule: `rw` cannot be expressed at all, and silently turning `rw` into read-only would change the grant without notice.

Because sb refuses to guess, the conversion is manual: convert each entry below, decide what it should mean in v3, and let `sb config check` confirm the result.

## Top-level changes

| v2 | v3 |
| --- | --- |
| `version` absent | `version: 3` required |
| `proxy:` section (`sshAgentEnv`) | not part of the v3 config; the agent socket is read from the sb process's `SSH_AUTH_SOCK` on every upstream dial |
| `container.mounts`: `"source:target"` strings | `mounts`: entries with `source`, `target`, `readOnly` |
| `container.environments`: `KEY=VALUE` list, bare `KEY` inherits | `container.environment`: a map of `KEY: {inherit: true}` or `KEY: {value: bar}` |
| `ssh`: `host` + `commands` | `host`, `user`, `port`, `access` |
| `k8s`: `context` + `mode` + `namespace` | `context` + `resources` (`group`, `resource`, `namespace` or `scope`, `verbs`) |
| `aws`: unchanged except `mode` values | same as v2, with `mode: r` renamed to `mode: ro` |

Unknown fields are rejected: every key must be a v3 key. Names, permissions, support ranges, and conflicts are checked when the config loads.

## SSH: `commands` → `access: full`

v2 restricted an ssh rule by matching the first words of the executed command against a pattern list, and omitted `commands` granted everything. Both forms are gone:

- v2 matched the command *tokens*, so `commands: [git]` allowed every git subcommand (`git push`, `git clone` of anything reachable by that host), and `commands: [cat]` allowed reading any file the upstream user can read. The restriction never proved the purpose of the command, and sb cannot prove anything about a free-form shell string.
- v3 therefore states the truth: an ssh rule is a grant of the *whole* upstream account on the matched host, shown as `access: full`. `access: full` includes the shell, any exec, subsystem, and TCP forwarding — the same set v2 granted when `commands` was omitted.

To convert, decide per host:

| v2 rule | v3 conversion |
| --- | --- |
| `- host: github.com` with `commands: [cat]` | `- host: github.com` + `access: full`, if you accept the broader grant |
| `- host: github.com` with `commands` omitted (shell + forward + any exec) | `- host: github.com` + `access: full` (same meaning) |
| any rule you do not want to grant in full | drop the entry |

```yaml
# v2                        # v3
ssh:                        ssh:
  - host: github.com          - host: github.com
    commands:                     access: full
      - cat
      - ls
```

Review each host: a v2 `commands` rule that felt limited now becomes an explicit full grant. If that is not what you want, remove the host from the config and reach it directly instead.

`user` and `port` are optional additional restrictions on the upstream connection (`user: git`, `port: 22`); when omitted, the values resolved from the upstream ssh config are used. `ssh.host` is still a pattern matched against the hostname resolved on the host running sb (`*.example.net`, `*`).

## k8s: `mode` → enumerated `resources`

v2 granted `r`/`rw` on a context. With `namespace: default` set, the grants applied to namespaced requests in `default` only; with `namespace` omitted, they applied to namespaced requests in *every* namespace *and* to cluster-scoped requests. v3 enumerates every grant explicitly, so the conversion is manual:

| v2 | v3 |
| --- | --- |
| `mode: r`, `namespace: default` | `resources` with the verbs you want in `default` (below) |
| `mode: rw` | **no v3 equivalent in the initial version** — no write verbs exist; drop the entry or keep only the read you intended |
| `namespace` omitted | v2 granted both every-namespace namespaced operations *and* cluster-scoped operations. In v3 these are separate grants: pick per resource — `namespace: "*"` for namespaced resources, `scope: cluster` for cluster-scoped resources (like `namespaces` or `nodes`). Converting only to `scope: cluster` silently drops every namespaced grant. |
| read of `pods` | does *not* inherit to `pods/log`; add a separate `pods/log` rule if you use `kubectl logs` |

`mode: r` granted all resources read access in the namespace; v3 requires listing each resource you actually use:

```yaml
# v2                          # v3
k8s:                          k8s:
  - context: dev                - context: dev
    mode: r                       resources:
    namespace: default              - group: ""
        resource: pods
        namespace: default
        verbs: [get, list, watch]
```

For an omitted `namespace`, convert the resources you used — namespaced resources keep working with `namespace: "*"`, and cluster-scoped resources (like `namespaces`) need `scope: cluster`:

```yaml
# v2                                # v3
k8s:                                k8s:
  - context: dev                      - context: dev
    mode: r                             resources:
    # namespace omitted                    - group: ""
                                            resource: pods
                                            namespace: "*"
                                            verbs: [get, list, watch]
                                          - group: ""
                                            resource: namespaces
                                            scope: cluster
                                            verbs: [get, list, watch]
```

Rules:

- `group` is required; `group: ""` is the core API group and is written explicitly.
- `namespace` is required per rule, or the rule is cluster-scoped with `scope: cluster`. `namespace: "*"` is an explicit all-namespaces grant (distinct from omission).
- `verbs` are enumerated. The initial v3 version supports `get`, `list`, `watch` for regular resources and `get` for `pods/log` (`kubectl logs` including `-f`).
- Unknown verbs, unknown subresources, and anything beyond that set are rejected at load.

## k8s: the issued kubeconfig is read-only

The kubeconfig sb issues is read-only by design: `kubectl config use-context` cannot write to it (and a written context would change what the grants were issued for). Pass `--context` or `-n` per command instead, or copy the kubeconfig somewhere writable and edit the copy — the `context` key stays the switch.

What changes when differs per side: the host-side source's connection and auth settings are fixed for the session, so a change there lands at the next session, while the working copy's own client-side selections — the context it points at, the default namespace — apply with the next request that uses the copy, within the issued contexts and the fixed policy.

## AWS: rename `mode: r` to `mode: ro`

AWS is the mechanical conversion:

```yaml
# v2                          # v3
aws:                           aws:
  - profile: dev                - profile: dev
    roleArn: arn:...             # roleArn: arn:... (unchanged, optional)
    regions: [eu-west-1]         regions: [eu-west-1]
    services:                    services:
      - name: dynamodb             - name: dynamodb
        mode: r                      mode: ro
      - name: sts                   - name: sts
        mode: rw                      mode: rw
```

- `mode: r` → `mode: ro`. `ro` has the same judgment as v2's `r`: an operation passes only when every action exercising it is allowed by the AWS ReadOnlyAccess policy.
- `mode: rw` is unchanged: the whole service passes.
- `roleArn` is unchanged and still optional; omit it to sign upstream with the source profile's own credentials.
- v3 does not accept the old `r`: it fails with `invalid mode "r" (want ro or rw)`.

## Container: `environments` list → `environment` map

```yaml
# v2                          # v3
container:                     container:
  runtime: docker                runtime: docker
  image: ghcr.io/hrntknr/sh:full  image: ghcr.io/hrntknr/sh:full
  mounts:                        mounts:
    - ~/.claude:/root/.claude      - source: ~/.claude
    - /srv/work:/work                target: /root/.claude
  environments:                       readOnly: false
    - FOO=bar                      - source: /srv/work
    - LANG                           target: /work
  environment:
    FOO: {value: bar}
    LANG: {inherit: true}
```

`image` is required when the container section is set. `readOnly` is new: v2 mounts were always writable.

## conf.d: duplicates are errors

`conf.d/` drop-ins next to the config still load, but the last-wins override is gone. After the files are read, these duplicates fail:

- the same ssh `host`, k8s `context`, or aws `profile` in two files
- the same mount `target` or the same environment variable key
- `container.image` or `container.runtime` set in two files

To remove or replace a definition, edit the file that defines it. Overlapping mount targets (one target nested under another) are ambiguous and also fail.

## Check the result

```
$ sb config check [--config path]
```

It validates the form, names, supported ranges, and conflicts statically, then lists every issuance target (ssh hosts, k8s contexts, aws profiles) and the permissions granted to each. It reads no credentials and contacts no cluster; connecting to the upstreams is done by running sb itself.

What the config grants is what the proxies enforce: a request outside it is never sent upstream, so the listing is the whole permission set the session runs with.
