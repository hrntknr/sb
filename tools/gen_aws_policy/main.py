"""Regenerate internal/awsproxy/services.json from current AWS sources."""

import concurrent.futures
import fnmatch
import json
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlparse

from botocore.endpoint_provider import EndpointProvider
from botocore.loaders import Loader

ROA_URL = "https://raw.githubusercontent.com/zoph-io/IAMTrail/main/policies/ReadOnlyAccess"
REFS_BASE = "https://servicereference.us-east-1.amazonaws.com"
SERVICES_PATH = Path(__file__).resolve().parents[2] / "internal/awsproxy/services.json"


def collect():
    """Resolve every forwardable service endpoint in every commercial region."""
    loader = Loader()
    partitions = loader.load_data("partitions")
    aws = next(p for p in partitions["partitions"] if p["id"] == "aws")
    # aws-global is a pseudo-region for global endpoints, not a commercial region.
    regions = sorted(k for k in aws["regions"] if k != "aws-global")
    result = {}
    for client in loader.list_available_services("service-2"):
        model = loader.load_service_model(client, "service-2")
        metadata = model.get("metadata", {})
        protocol = metadata.get("protocol") or (metadata.get("protocols") or [None])[0]
        if protocol not in {"json", "query", "ec2"}:
            continue
        if metadata.get("signatureVersion") != "v4":
            continue
        try:
            ruleset = loader.load_service_model(client, "endpoint-rule-set-1")
        except Exception:
            continue

        common = {"UseFIPS": False, "UseDualStack": False, "Endpoint": None}
        for name, spec in ruleset.get("parameters", {}).items():
            if not spec.get("required") or name == "Region" or name in common:
                continue
            if "default" in spec:
                common[name] = spec["default"]
                continue
            values = {
                operation.get("staticContextParams", {}).get(name, {}).get("value")
                for operation in model.get("operations", {}).values()
            }
            values.discard(None)
            if len(values) != 1:
                break
            common[name] = values.pop()
        else:
            provider = EndpointProvider(ruleset_data=ruleset, partition_data=partitions)
            resolved = {}
            try:
                for region in regions:
                    endpoint = provider.resolve_endpoint(Region=region, **common)
                    resolved[region] = {
                        "url": endpoint.url,
                        "authSchemes": (endpoint.properties or {}).get("authSchemes", []),
                    }
            except Exception:
                continue
            result[client] = {
                "signing": metadata.get("signingName") or client,
                "protocol": protocol,
                "contentType": (
                    "application/x-amz-json-" + metadata["jsonVersion"]
                    if protocol == "json"
                    else "application/x-www-form-urlencoded"
                ),
                "targetPrefix": metadata.get("targetPrefix", ""),
                "resolved": resolved,
            }

    return result


def fetch_json(url):
    """Return the JSON document at url."""
    with urllib.request.urlopen(url) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} fetching {url}")
        return json.load(response)


def fetch_policy():
    """Return the current default ReadOnlyAccess policy."""
    policy = fetch_json(ROA_URL)
    version = policy["PolicyVersion"]
    document = version["Document"]
    if (
        not version.get("IsDefaultVersion")
        or not version.get("VersionId")
        or document.get("Version") != "2012-10-17"
    ):
        raise RuntimeError("invalid ReadOnlyAccess policy")
    return policy


def fetch_references():
    """Return the AWS Service Reference data of every service, keyed by service name."""
    services = [entry["service"] for entry in fetch_json(REFS_BASE + "/")]
    if len(services) < 400:
        raise RuntimeError("AWS service reference list is incomplete")

    def fetch_reference(service):
        slug = quote(service, safe="")
        reference = fetch_json(f"{REFS_BASE}/v1/{slug}/{slug}.json")
        if reference.get("Name") != service:
            raise RuntimeError(f"invalid service reference for {service}")
        return service, reference

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        return dict(executor.map(fetch_reference, services))


def load_endpoints():
    """Return one derived endpoint per SigV4 signing name."""
    services = collect()
    if len(services) < 100:
        raise RuntimeError("botocore endpoint list is incomplete")
    groups = {}
    for client, service in services.items():
        groups.setdefault(service["signing"], []).append(client)

    endpoints = {}
    for signing, clients in groups.items():
        clients.sort()
        client = signing if signing in clients else clients[0]
        endpoint = derive_endpoint(signing, services[client])
        if endpoint:
            endpoints[signing] = endpoint
    return endpoints


def derive_endpoint(signing, service):
    """Reduce a service's resolved endpoints to one endpoint, or None if it cannot."""
    hosts = {}
    signing_regions = {}
    for region, resolved in service["resolved"].items():
        parsed = urlparse(resolved["url"])
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.path not in ("", "/")
            or parsed.query
        ):
            return None
        hosts[region] = parsed.netloc
        auth_regions = set()
        for auth in resolved.get("authSchemes", []):
            if auth.get("name") != "sigv4":
                return None
            if auth.get("signingName") not in (None, "", signing):
                return None
            if auth.get("signingRegion"):
                auth_regions.add(auth["signingRegion"])
        if len(auth_regions) > 1:
            return None
        signing_regions[region] = next(iter(auth_regions), region)

    if not hosts or not service.get("contentType"):
        return None
    if service["protocol"] == "json" and not service.get("targetPrefix"):
        return None

    endpoint = {
        "host": "",
        "protocol": service["protocol"],
        "contentType": service["contentType"],
    }
    if service.get("targetPrefix"):
        endpoint["targetPrefix"] = service["targetPrefix"]

    regions = sorted(hosts)
    if len(set(hosts.values())) == 1:
        endpoint["host"] = hosts[regions[0]]
        if all(signing_regions[region] == region for region in regions):
            return endpoint
        fixed_region = signing_regions[regions[0]]
        if not all(signing_regions[region] == fixed_region for region in regions):
            return None
        endpoint["signingRegion"] = fixed_region
        return endpoint

    first_region = regions[0]
    first_host = hosts[first_region]
    start = 0
    while (index := first_host.find(first_region, start)) != -1:
        prefix = first_host[:index]
        suffix = first_host[index + len(first_region):]
        if all(
            hosts[region] == prefix + region + suffix
            and signing_regions[region] == region
            for region in regions
        ):
            endpoint["host"] = prefix + "{region}" + suffix
            return endpoint
        start = index + 1
    return None


def allows_operation(patterns, service, actions):
    """Return whether every action exercising the operation is read-only."""
    allowed = False
    for action in actions:
        if action.get("Service") != service:
            continue
        value = (service + ":" + action["Name"]).lower()
        if not any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns):
            return False
        allowed = True
    return allowed


def generate():
    """Fetch current AWS sources and rewrite services.json."""
    policy = fetch_policy()
    references = fetch_references()
    endpoints = load_endpoints()
    patterns = {}
    for statement in policy["PolicyVersion"]["Document"]["Statement"]:
        if (
            statement.get("Effect") != "Allow"
            or statement.get("Resource") != "*"
            or statement.get("Condition")
        ):
            continue
        for action in statement.get("Action", []):
            if ":" in action:
                service = action.split(":", 1)[0].lower()
                patterns.setdefault(service, []).append(action.lower())

    services = {}
    for service, reference in references.items():
        endpoint = endpoints.get(service)
        if not endpoint:
            continue
        read = sorted(
            operation["Name"]
            for operation in reference.get("Operations", [])
            if allows_operation(
                patterns.get(service.lower(), []),
                service,
                operation.get("AuthorizedActions", []),
            )
        )
        services[service] = {**endpoint, **({"read": read} if read else {})}

    content = json.dumps(dict(sorted(services.items())), indent=2) + "\n"
    if not SERVICES_PATH.exists() or SERVICES_PATH.read_text() != content:
        SERVICES_PATH.write_text(content)
    version = policy["PolicyVersion"]["VersionId"]
    print(f"AWS services updated (ReadOnlyAccess {version})")


if __name__ == "__main__":
    try:
        generate()
    except Exception as error:
        raise SystemExit(f"gen_aws_policy: {error}") from error
