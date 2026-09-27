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
- A **k8s** `mode` rule converts by hand: v2 applied the mode inside the `namespace` (or, omitted, to every namespace *and* cluster-scoped requests), while a v3 mode covers every resource of the stable API in every namespace and at the cluster's root — a mechanical conversion would change what the rule grants, and the same name means a different grant.

Because sb refuses to guess, the conversion is manual: convert each entry below, decide what it should mean in v3, and let `sb config check` confirm the result.

## Top-level changes

| v2 | v3 |
| --- | --- |
| `version` absent | `version: 3` required |
| `proxy:` section (`sshAgentEnv`) | not part of the v3 config; the agent socket is read from the sb process's `SSH_AUTH_SOCK` on every upstream dial |
| `container.mounts`: `"source:target"` strings | `mounts`: entries with `source`, `target`, `readOnly` |
| `container.environments`: `KEY=VALUE` list, bare `KEY` inherits | `container.environment`: a map of `KEY: {inherit: true}` or `KEY: {value: bar}` |
| `ssh`: `host` + `commands` | `host`, `user`, `port`, `access` |
| `k8s`: `context` + `mode` + `namespace` | `context` + `mode` (`ro`/`rw`) or `resources` (`group`, `resource`, `namespace` or `scope`, `verbs`) |
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

v2:

```yaml
ssh:
  - host: github.com
    commands:
      - cat
      - ls
```

becomes:

v3:

```yaml
ssh:
  - host: github.com
    access: full
```

Review each host: a v2 `commands` rule that felt limited now becomes an explicit full grant. If that is not what you want, remove the host from the config and reach it directly instead.

`user` and `port` are optional additional restrictions on the upstream connection (`user: git`, `port: 22`); when omitted, the values resolved from the upstream ssh config are used. `ssh.host` is still a pattern matched against the hostname resolved on the host running sb (`*.example.net`, `*`).

## k8s: `mode` → `mode`, or enumerated `resources`

v2 granted `r`/`rw` on a context. v3 keeps the form as `mode: ro` (read) and `mode: rw` (every verb) — granted on every resource of the stable API, in every namespace and at the cluster's root alike — and adds the explicit form: `resources` enumerates the verbs on each resource you name. `mode` and `resources` are mutually exclusive in one context.

With `namespace: default` set, v2 granted only the namespaced requests in `default`; with `namespace` omitted, it granted namespaced requests in *every* namespace *and* cluster-scoped requests — exactly what the v3 modes grant. The conversion is manual because the grant sits differently in v3: the namespace moves from one field on the rule to a field on each resource, and the resources, subresources, and verbs differ — a v3 rule names its resource, takes `namespace: "*"` or `scope: cluster` for the scope, and its verbs are enumerated, while a v3 mode covers every resource at once and no subresource at all:

| v2 | v3 |
| --- | --- |
| `mode: r`, `namespace: default` | `resources` with the verbs you want in `default` (below) — or `mode: ro`, which also grants read on every other resource: check that is what you mean |
| `mode: rw` | `mode: rw`: every resource of the stable API, every verb. v2 granted read-write on the resources in the namespace; check that read-write everywhere is what you mean |
| `namespace` omitted | v2 granted both every-namespace namespaced operations *and* cluster-scoped operations — the v3 modes grant exactly that. The `resources` form picks per resource — `namespace: "*"` for namespaced resources, `scope: cluster` for cluster-scoped resources (like `namespaces` or `nodes`) — and converting only to `scope: cluster` silently drops every namespaced grant. |
| read of `pods` | does *not* inherit to `pods/log`; add a separate `pods/log` rule if you use `kubectl logs`. No mode covers `pods/log` — a `pods/log` rule in `resources` is the only way to grant it |

`mode: r` granted all resources read access in the namespace; v3 requires listing each resource you actually use:

v2:

```yaml
k8s:
  - context: dev
    mode: r
    namespace: default
```

becomes:

v3:

```yaml
k8s:
  - context: dev
    resources:
      - group: ""
        resource: pods
        namespace: default
        verbs: [get, list, watch]
```

For an omitted `namespace`, convert the resources you used — namespaced resources keep working with `namespace: "*"`, and cluster-scoped resources (like `namespaces`) need `scope: cluster`:

v2:

```yaml
k8s:
  - context: dev
    mode: r
    # namespace omitted
```

becomes:

v3:

```yaml
k8s:
  - context: dev
    resources:
      - group: ""
        resource: pods
        namespace: "*"
        verbs: [get, list, watch]
      - group: ""
        resource: namespaces
        scope: cluster
        verbs: [get, list, watch]
```

`mode: rw` keeps its form; the grant widens from the resources in the namespace to every resource of the stable API:

v2:

```yaml
k8s:
  - context: dev
    mode: rw
    namespace: default
```

becomes:

v3:

```yaml
k8s:
  - context: dev
    mode: rw
```

Rules:

- `group` is required; `group: ""` is the core API group and is written explicitly.
- `namespace` or `scope: cluster` (cluster-scoped resources): `namespace: "*"` and an omitted `namespace` are the same all-namespaces grant. An omitted `verbs` is every verb the resource supports — `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` for regular resources, `get` for `pods/log` (`kubectl logs` including `-f`).
- `mode: ro` reads and `mode: rw` grants every verb on every resource of the stable API; `verbs` at the context level — with `resources` omitted, or omitted entirely: the `mode: rw` grant — grants those verbs on each of them. `mode`, `verbs`, and `resources` never mix in one context; a null or absent key is the same omission, and an empty `resources: []` list is rejected.
- Unknown verbs, unknown subresources, and anything beyond that set are rejected at load.

## k8s: the issued kubeconfig is read-only

The kubeconfig sb issues is read-only by design: `kubectl config use-context` cannot write to it (and a written context would change what the grants were issued for). Pass `--context` or `-n` per command instead, or copy the kubeconfig somewhere writable and edit the copy — the `context` key stays the switch.

What changes when differs per side: the host-side source's connection and auth settings are fixed for the session, so a change there lands at the next session, while the working copy's own client-side selections — the context it points at, the default namespace — apply with the next request that uses the copy, within the issued contexts and the fixed policy.

## AWS: rename `mode: r` to `mode: ro`

AWS is the mechanical conversion:

v2:

```yaml
aws:
  - profile: dev
    roleArn: arn:...
    regions: [eu-west-1]
    services:
      - name: dynamodb
        mode: r
      - name: sts
        mode: rw
```

becomes:

v3:

```yaml
aws:
  - profile: dev
    # roleArn: arn:... (unchanged, optional)
    regions: [eu-west-1]
    services:
      - name: dynamodb
        mode: ro
      - name: sts
        mode: rw
```

- `mode: r` → `mode: ro`. `ro` has the same judgment as v2's `r`: an operation passes only when every action exercising it is allowed by the AWS ReadOnlyAccess policy.
- `mode: rw` is unchanged: the whole service passes.
- `roleArn` is unchanged and still optional; omit it to sign upstream with the source profile's own credentials.
- v3 does not accept the old `r`: it fails with `invalid mode "r" (want ro or rw)`.

## Container: `environments` list → `environment` map

v2:

```yaml
container:
  runtime: docker
  image: ghcr.io/hrntknr/sh:full
  mounts:
    - ~/.claude:/root/.claude
    - /srv/work:/work
  environments:
    - FOO=bar
    - LANG
```

becomes:

v3:

```yaml
container:
  runtime: docker
  image: ghcr.io/hrntknr/sh:full
  mounts:
    - source: ~/.claude
      target: /root/.claude
      readOnly: false
    - source: /srv/work
      target: /work
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
