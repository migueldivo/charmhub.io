#!/usr/bin/env python3
"""Generate the dependency and vulnerability snapshot used by a charm's
"Dependencies" and "Security" tabs.

The snapshot is written to webapp/store/security_data/<charm>.json and is
built from real data wherever possible:

- Charmhub API: metadata (interfaces), resources and charm library versions.
- The charm source repository: vendored charm libraries and uv.lock.
- The OCI image pinned by the charm: Ubuntu packages (dpkg manifest), and the
  workload's Go build info (Go toolchain and embedded Go modules).
- OSV.dev: vulnerabilities for all of the above.

Charm interfaces and charm libraries are not covered by any public
vulnerability database, so a small set of clearly-marked illustrative
advisories is added for them. Maintenance statuses are derived from the data
(fix availability, severity, age) to demonstrate the triage workflow.

Usage:
    pip install cvss packaging pyyaml
    python3 scripts/generate_security_report.py grafana-k8s

Requires network access, git and docker.
"""

import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml
from cvss import CVSS3, CVSS4
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "webapp" / "store" / "security_data"
CHARMHUB_API = "https://api.charmhub.io"
OSV_API = "https://api.osv.dev/v1"

# Per-charm knowledge that cannot be derived generically: which binary in an
# OCI resource is the workload, and where its newer upstream build lives.
WORKLOADS = {
    "grafana-k8s": {
        "grafana-image": {
            "name": "Grafana",
            "binary": "/usr/bin/grafana",
            "go_module": "github.com/grafana/grafana",
            "url": "https://github.com/grafana/grafana",
            "rock_repo": "canonical/grafana-rock",
        }
    }
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def report_severity(severity):
    """Collapse vendor ratings into critical/high/medium/low. Unrated
    advisories are treated as medium until assessed."""
    if severity == "negligible":
        return "low"
    if severity not in SEVERITY_ORDER:
        return "medium"
    return severity


def http_json(url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def http_text(url):
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read().decode()


def parse_version(value):
    if value is None:
        return None
    try:
        return Version(str(value).lstrip("v"))
    except InvalidVersion:
        return None


# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------


def get_charm_info(charm):
    fields = ",".join(
        [
            "default-release.revision.metadata-yaml",
            "default-release.revision.revision",
            "default-release.channel",
            "default-release.resources",
        ]
    )
    info = http_json(f"{CHARMHUB_API}/v2/charms/info/{charm}?fields={fields}")
    release = info["default-release"]
    return {
        "metadata": yaml.safe_load(release["revision"]["metadata-yaml"]),
        "revision": release["revision"]["revision"],
        "channel": release["channel"]["name"],
        "base": release["channel"]["base"],
        "resources": release["resources"],
    }


def clone(repo_url):
    target = tempfile.mkdtemp(prefix="secreport-")
    subprocess.run(
        ["git", "clone", "--quiet", "--depth", "1", repo_url, target],
        check=True,
    )
    return pathlib.Path(target)


def interface_dependencies(metadata):
    interfaces = {}
    roles = {"requires": "requires", "provides": "provides", "peers": "peer"}
    for section, role in roles.items():
        for endpoint, spec in (metadata.get(section) or {}).items():
            name = spec["interface"]
            dep = interfaces.setdefault(
                name,
                {
                    "id": f"interface:{name}",
                    "name": name,
                    "type": "interface",
                    "version": None,
                    "relationship": "direct",
                    "parent": None,
                    "url": f"https://charmhub.io/integrations/{name}",
                    "endpoints": [],
                },
            )
            dep["endpoints"].append(
                {
                    "name": endpoint,
                    "role": role,
                    "optional": spec.get("optional", section != "requires"),
                }
            )
    return list(interfaces.values())


def library_dependencies(repo):
    libs = []
    for path in sorted((repo / "lib" / "charms").rglob("*.py")):
        source = path.read_text()
        values = dict(
            re.findall(
                r'^(LIBID|LIBAPI|LIBPATCH)\s*=\s*"?(\w+)"?', source, re.M
            )
        )
        if "LIBID" not in values:
            continue
        module = ".".join(path.relative_to(repo / "lib").with_suffix("").parts)
        libs.append(
            {
                "module": module,
                "library_id": values["LIBID"],
                "api": int(values["LIBAPI"]),
                "patch": int(values["LIBPATCH"]),
            }
        )

    published = http_json(
        f"{CHARMHUB_API}/v1/charm/libraries/bulk",
        [{"library-id": lib["library_id"], "api": lib["api"]} for lib in libs],
    )["libraries"]
    by_id = {(p["library-id"], p["api"]): p for p in published}

    deps = []
    for lib in libs:
        latest = by_id.get((lib["library_id"], lib["api"]), {})
        owner = latest.get("charm-name")
        name = lib["module"].split(".")[-1]
        deps.append(
            {
                "id": f"library:{lib['module']}",
                "name": lib["module"],
                "type": "charm-library",
                "version": f"{lib['api']}.{lib['patch']}",
                "latest_version": (
                    f"{lib['api']}.{latest['patch']}" if latest else None
                ),
                "outdated": bool(latest and latest["patch"] > lib["patch"]),
                "relationship": "direct",
                "parent": None,
                "owner": owner,
                "url": (
                    f"https://charmhub.io/{owner}/libraries/{name}"
                    if owner
                    else None
                ),
            }
        )
    return deps


def python_dependencies(repo):
    lock = tomllib.loads((repo / "uv.lock").read_text())
    pyproject = tomllib.loads((repo / "pyproject.toml").read_text())
    packages = {p["name"]: p for p in lock["package"]}
    root = packages[pyproject["project"]["name"]]

    constraints = {}
    for requirement in pyproject["project"]["dependencies"]:
        match = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)", requirement)
        name = match.group(1).lower().replace("_", "-")
        constraints[name] = match.group(3).strip() or None

    root_extras = {
        dep["name"]: dep.get("extra", []) for dep in root["dependencies"]
    }
    via = {}

    def walk(name, parent):
        if name in via:
            return
        via[name] = parent
        package = packages[name]
        for dep in package.get("dependencies", []):
            walk(dep["name"], name)
        if parent is None:
            optional = package.get("optional-dependencies", {})
            for extra in root_extras.get(name, []):
                for sub in optional.get(extra, []):
                    walk(sub["name"], name)

    for dep in root["dependencies"]:
        walk(dep["name"], None)

    return [
        {
            "id": f"pypi:{name}",
            "name": name,
            "type": "python-package",
            "version": packages[name]["version"],
            "relationship": "direct" if parent is None else "transitive",
            "parent": f"pypi:{parent}" if parent else None,
            "constraint": constraints.get(name),
            "url": f"https://pypi.org/project/{name}/",
        }
        for name, parent in sorted(via.items())
    ]


def read_go_buildinfo(data):
    start = data.find(b"\xff Go buildinf:")
    if start < 0:
        raise RuntimeError("No Go build info found")
    pos = start + 32

    def varint(pos):
        value = shift = 0
        while True:
            byte = data[pos]
            pos += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                return value, pos

    length, pos = varint(pos)
    go_version = data[pos : pos + length].decode()
    pos += length
    length, pos = varint(pos)
    modinfo = data[pos : pos + length][16:-16].decode()

    modules, ldflags = [], ""
    for line in modinfo.splitlines():
        parts = line.split("\t")
        if parts[0] == "dep":
            modules.append((parts[1], parts[2]))
        elif parts[0] == "=>" and modules:
            modules[-1] = (parts[1], parts[2])
        elif parts[0] == "build" and parts[1].startswith("-ldflags="):
            ldflags = parts[1]
    version = re.search(r"main\.version=([\w.\-]+)", ldflags)
    return {
        "go": go_version.removeprefix("go"),
        "modules": modules,
        "version": version.group(1) if version else None,
    }


def docker_read(image, path):
    # Captured through a pipe: snap-confined docker cannot write to /tmp.
    return subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "", image, "cat", path],
        stdout=subprocess.PIPE,
        check=True,
    ).stdout


def newer_rock(workload, charmcraft):
    """Read the newest upstream rock for the track the charm pins, using the
    renovate comment next to the resource's upstream-source."""
    tag = re.search(r"oci-image tag:\s*([\d.]+)-", charmcraft)
    if not tag:
        return None
    base = f"https://raw.githubusercontent.com/{workload['rock_repo']}/main"
    try:
        rock = yaml.safe_load(http_text(f"{base}/{tag.group(1)}/rockcraft.yaml"))
    except urllib.error.HTTPError:
        return None
    version = str(rock["version"])
    repo = workload["url"].removeprefix("https://github.com/")
    go_mod = http_text(
        f"https://raw.githubusercontent.com/{repo}/v{version}/go.mod"
    )
    go = re.search(r"^go\s+([\d.]+)", go_mod, re.M).group(1)
    modules = dict(re.findall(r"^\s+(\S+)\s+(v\S+)", go_mod, re.M))
    return {"version": version, "go": go, "modules": modules}


def image_dependencies(charm, metadata, resources, repo):
    deps, newer = [], None
    workloads = WORKLOADS.get(charm, {})
    for resource in resources:
        if resource["type"] != "oci-image":
            continue
        name = resource["name"]
        spec = metadata["resources"][name]
        upstream = spec.get("upstream-source")
        resource_id = f"resource:{name}"
        deps.append(
            {
                "id": resource_id,
                "name": name,
                "type": "resource",
                "version": f"rev {resource['revision']}",
                "relationship": "direct",
                "parent": None,
                "image": upstream,
                "url": f"https://charmhub.io/{charm}/resources/{name}",
            }
        )
        if not upstream:
            continue

        subprocess.run(["docker", "pull", "-q", upstream], check=True)
        manifest = docker_read(upstream, "/usr/share/rocks/dpkg.query")
        os_release, sources = {}, {}
        for line in manifest.decode().splitlines():
            if line.startswith("ii "):
                _, _binary, _, source, source_version = line.split(",")
                sources[source] = source_version
            elif "=" in line:
                key, _, value = line.partition("=")
                os_release[key] = value.strip('"')
        ecosystem = f"Ubuntu:{os_release['VERSION_ID']}"
        if "LTS" in os_release.get("VERSION", ""):
            ecosystem += ":LTS"
        deps[-1]["os"] = os_release.get("PRETTY_NAME")
        for source, version in sorted(sources.items()):
            deps.append(
                {
                    "id": f"deb:{source}",
                    "name": source,
                    "type": "os-package",
                    "version": version,
                    "relationship": "transitive",
                    "parent": resource_id,
                    "ecosystem": ecosystem,
                    "url": f"https://launchpad.net/ubuntu/+source/{source}",
                }
            )

        workload = workloads.get(name)
        if not workload:
            continue
        info = read_go_buildinfo(docker_read(upstream, workload["binary"]))
        app_id = f"app:{workload['go_module']}"
        deps.append(
            {
                "id": app_id,
                "name": workload["name"],
                "type": "application",
                "version": info["version"],
                "relationship": "transitive",
                "parent": resource_id,
                "module": workload["go_module"],
                "url": workload["url"],
            }
        )
        deps.append(
            {
                "id": "go:stdlib",
                "name": "Go standard library",
                "type": "runtime",
                "version": info["go"],
                "relationship": "transitive",
                "parent": app_id,
                "url": "https://go.dev/doc/devel/release",
            }
        )
        for module, version in info["modules"]:
            deps.append(
                {
                    "id": f"go:{module}",
                    "name": module,
                    "type": "go-module",
                    "version": version,
                    "relationship": "transitive",
                    "parent": app_id,
                    "url": f"https://pkg.go.dev/{module}@{version}",
                }
            )
        newer = newer_rock(workload, (repo / "charmcraft.yaml").read_text())
    return deps, newer


# --------------------------------------------------------------------------
# Vulnerabilities
# --------------------------------------------------------------------------

_vuln_cache = {}


def osv_vuln(vuln_id):
    if vuln_id not in _vuln_cache:
        try:
            _vuln_cache[vuln_id] = http_json(f"{OSV_API}/vulns/{vuln_id}")
        except urllib.error.HTTPError:
            _vuln_cache[vuln_id] = None
    return _vuln_cache[vuln_id]


def osv_batch(queries):
    results = []
    for i in range(0, len(queries), 1000):
        response = http_json(
            f"{OSV_API}/querybatch", {"queries": queries[i : i + 1000]}
        )
        results += [r.get("vulns", []) for r in response["results"]]
    return [[v["id"] for v in vulns] for vulns in results]


def osv_query_all(name, ecosystem):
    ids, token = [], None
    while True:
        body = {"package": {"name": name, "ecosystem": ecosystem}}
        if token:
            body["page_token"] = token
        response = http_json(f"{OSV_API}/query", body)
        ids += [v["id"] for v in response.get("vulns", [])]
        token = response.get("next_page_token")
        if not token:
            return ids


def osv_package(dep):
    """(package name, ecosystem, version) as OSV expects them."""
    if dep["type"] == "python-package":
        return dep["name"], "PyPI", dep["version"]
    if dep["type"] == "go-module":
        return dep["name"], "Go", dep["version"].removeprefix("v")
    if dep["type"] == "runtime":
        return "stdlib", "Go", dep["version"]
    if dep["type"] == "os-package":
        return dep["name"], dep["ecosystem"], dep["version"]
    return None


def normalise(value):
    value = value.lower()
    return {"moderate": "medium", "important": "high"}.get(value, value)


def rating(score):
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def severity_of(vuln, seen=None):
    """Return (severity, CVSS base score) for an OSV record."""
    seen = seen or set()
    seen.add(vuln["id"])
    score, ubuntu = None, None
    for entry in vuln.get("severity") or []:
        vector = entry.get("score", "")
        if entry["type"] == "Ubuntu":
            ubuntu = normalise(vector)
            continue
        try:
            if vector.startswith("CVSS:4"):
                score = float(CVSS4(vector).base_score)
            elif vector.startswith("CVSS:3") and score is None:
                score = float(CVSS3(vector).scores()[0])
        except Exception:
            continue
    db_severity = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db_severity, str):
        return normalise(db_severity), score
    if ubuntu and ubuntu not in ("unknown", "untriaged"):
        return ubuntu, score
    if score is not None:
        return rating(score), score
    # Go stdlib advisories carry no severity; Ubuntu's per-CVE records do.
    aliases = vuln.get("aliases", [])
    aliases += [f"UBUNTU-{a}" for a in aliases if a.startswith("CVE-")]
    for alias in aliases:
        if alias in seen or not alias.startswith(("GHSA-", "CVE-", "UBUNTU-")):
            continue
        record = osv_vuln(alias)
        if record:
            result = severity_of(record, seen)
            if result[0] != "unknown":
                return result
    return "unknown", None


def fixed_version(vuln, package, installed):
    """First fixed version after the installed one for a package."""
    installed_v = parse_version(installed)
    fixes = [
        event["fixed"]
        for affected in vuln.get("affected", [])
        if affected["package"]["name"] == package
        for rng in affected.get("ranges", [])
        for event in rng["events"]
        if "fixed" in event
    ]
    if installed_v is None:
        # Debian-style versions: OSV returns the matching range's fix.
        return fixes[-1] if fixes else None
    newer = [
        (parse_version(f), f)
        for f in fixes
        if parse_version(f) and parse_version(f) > installed_v
    ]
    return min(newer)[1] if newer else None


def fixed_in_line(vuln, package, installed, line_start):
    """The fix version if the vuln was fixed after line_start, up to and
    including the installed version."""
    installed_v, start_v = parse_version(installed), parse_version(line_start)
    for affected in vuln.get("affected", []):
        if affected["package"]["name"] != package:
            continue
        for rng in affected.get("ranges", []):
            for event in rng["events"]:
                fixed = parse_version(event.get("fixed"))
                if fixed and start_v < fixed <= installed_v:
                    return event["fixed"]
    return None


def ghsa_line_status(vuln, package, version):
    """Evaluate GHSA per-release-line ranges for an exact workload version.

    The Go vulnerability database marks every github.com/grafana/grafana
    version as affected (the module has no /v12 suffix), so GitHub's reviewed
    ranges ("introduced 12.4.0, < 12.4.2") are used instead.
    """
    installed = parse_version(version)
    for affected in vuln.get("affected", []):
        if affected["package"]["name"] != package:
            continue
        bound = (affected.get("database_specific") or {}).get(
            "last_known_affected_version_range", ""
        )
        for rng in affected.get("ranges", []):
            events = rng["events"]
            values = [v for event in events for v in event.values()]
            if any("-" in v for v in values):
                # Go pseudo-versions, not release versions.
                continue
            introduced = parse_version(events[0].get("introduced"))
            if not introduced or introduced > installed:
                continue
            fixed = next((e["fixed"] for e in events if "fixed" in e), None)
            last = next(
                (e["last_affected"] for e in events if "last_affected" in e),
                None,
            )
            upper, inclusive = parse_version(fixed), False
            if upper is None and last:
                upper, inclusive = parse_version(last), True
            elif upper is None and bound:
                inclusive = bound.startswith("<=")
                upper = parse_version(bound.lstrip("<= "))
                fixed = None if inclusive else str(upper)
            if upper is None or installed < upper or (
                inclusive and installed == upper
            ):
                return "affected", fixed
            if upper.release[:2] == installed.release[:2]:
                return "fixed", fixed or f"> {upper}"
    return None, None


ID_RANK = ("GHSA-", "PYSEC-", "GO-", "UBUNTU-", "USN-")


def id_rank(vuln_id):
    return next(
        (i for i, p in enumerate(ID_RANK) if vuln_id.startswith(p)),
        len(ID_RANK),
    )


def canonical_ids(vuln):
    ids = [vuln["id"]] + vuln.get("aliases", [])
    cve = next((i for i in ids if i.startswith("CVE-")), None)
    ranked = sorted(
        (i for i in ids if not i.startswith(("CVE-", "BIT-"))), key=id_rank
    )
    return (ranked[0] if ranked else vuln["id"]), cve


def summarise(vuln):
    summary = vuln.get("summary") or ""
    if not summary:
        summary = (vuln.get("details") or "").strip().split("\n")[0]
    summary = re.sub(r"\s+in (github\.com|golang\.org)/\S+$", "", summary)
    return summary[:240]


def build_vulnerability(vuln, dep, state, fixed):
    primary, cve = canonical_ids(vuln)
    severity, score = severity_of(vuln)
    url_id = primary if primary.startswith(ID_RANK) else vuln["id"]
    return {
        "id": primary,
        "cve": cve,
        "summary": summarise(vuln),
        "severity": report_severity(severity),
        "cvss": score,
        "dependency": dep["id"],
        "installed_version": dep["version"],
        "fixed_version": fixed,
        "state": state,
        "published": (vuln.get("published") or "")[:10],
        "source": "OSV.dev",
        "url": f"https://osv.dev/vulnerability/{url_id}",
    }


def collect_vulnerabilities(deps, snapshot_date):
    by_id = {d["id"]: d for d in deps}
    scannable = [d for d in deps if osv_package(d)]
    queries = []
    for dep in scannable:
        name, ecosystem, version = osv_package(dep)
        queries.append(
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        )
    affected_ids = osv_batch(queries)

    # Full advisory history: used to show vulnerabilities that were already
    # resolved by the versions currently shipped.
    history = {
        dep["id"]: osv_query_all(*osv_package(dep)[:2])
        for dep in scannable
        if dep["type"] in ("python-package", "runtime")
    }
    app = next((d for d in deps if d["type"] == "application"), None)
    app_ids = osv_query_all(app["module"], "Go") if app else []

    wanted = {i for ids in affected_ids for i in ids}
    wanted |= {i for ids in history.values() for i in ids}
    wanted |= set(app_ids)
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(osv_vuln, wanted))
    ghsa_aliases = {
        alias
        for vuln_id in app_ids
        for alias in (osv_vuln(vuln_id) or {}).get("aliases", [])
        if alias.startswith("GHSA-")
    }
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(osv_vuln, ghsa_aliases))

    results = {}

    def add(record):
        key = (record["dependency"], record["cve"] or record["id"])
        existing = results.get(key)
        if existing and id_rank(existing["id"]) <= id_rank(record["id"]):
            return
        results[key] = record

    for dep, ids in zip(scannable, affected_ids):
        name, _, version = osv_package(dep)
        cves_listed = {
            alias
            for vuln_id in ids
            if vuln_id.startswith("UBUNTU-")
            for alias in (osv_vuln(vuln_id) or {}).get("aliases", [])
        } | {i.removeprefix("UBUNTU-") for i in ids}
        for vuln_id in ids:
            vuln = osv_vuln(vuln_id)
            if not vuln or vuln.get("withdrawn"):
                continue
            if vuln_id.startswith("USN-"):
                # USNs group per-CVE Ubuntu records already listed.
                cves = [a for a in vuln.get("aliases", []) if a.startswith("CVE")]
                if cves and all(c in cves_listed for c in cves):
                    continue
            fixed = fixed_version(vuln, name, version)
            add(build_vulnerability(vuln, dep, "affected", fixed))

    one_year_ago = (snapshot_date - datetime.timedelta(days=365)).isoformat()
    for dep_id, ids in history.items():
        dep = by_id[dep_id]
        name, _, version = osv_package(dep)
        line_start = "0"
        if dep["type"] == "runtime":
            line_start = ".".join(version.split(".")[:2]) + ".0"
        for vuln_id in ids:
            vuln = osv_vuln(vuln_id)
            if not vuln or vuln.get("withdrawn"):
                continue
            if (vuln.get("published") or "")[:10] < one_year_ago:
                continue
            fixed = fixed_in_line(vuln, name, version, line_start)
            if fixed:
                add(build_vulnerability(vuln, dep, "fixed", fixed))

    if app:
        ghsa_ids = set()
        for vuln_id in app_ids:
            vuln = osv_vuln(vuln_id) or {}
            ids = [vuln_id] + vuln.get("aliases", [])
            ghsa_ids |= {i for i in ids if i.startswith("GHSA-")}
        for ghsa in sorted(ghsa_ids):
            vuln = osv_vuln(ghsa)
            if not vuln or vuln.get("withdrawn"):
                continue
            state, fixed = ghsa_line_status(vuln, app["module"], app["version"])
            if state:
                add(build_vulnerability(vuln, app, state, fixed))

    return list(results.values())


# Interfaces and charm libraries are not tracked by any public vulnerability
# database. These advisories are illustrative and flagged as such in the UI.
ILLUSTRATIVE = [
    (
        "library:charms.grafana_k8s.v0.grafana_dashboard",
        "high",
        7.6,
        "in-progress",
        "Dashboards received over the grafana_dashboard relation are"
        " provisioned without sanitising HTML text panels, allowing stored"
        " XSS from a compromised related charm.",
        "2026-08-19",
    ),
    (
        "interface:grafana_datasource",
        "medium",
        6.4,
        "in-progress",
        "Datasource URLs published over grafana_datasource are not validated,"
        " enabling SSRF through the Grafana datasource proxy.",
        "2026-07-30",
    ),
    (
        "library:charms.hydra.v0.oauth",
        "high",
        7.1,
        "ready-for-release",
        "The OAuth client secret ID is logged at DEBUG level when the relation"
        " changes, exposing a secret reference in Juju logs.",
        "2026-06-11",
    ),
    (
        "interface:tls-certificates",
        "medium",
        5.9,
        "triaged",
        "Certificate requests are accepted without checking that the CSR"
        " common name matches the requesting unit.",
        "2026-09-02",
    ),
    (
        "library:charms.istio_beacon_k8s.v0.service_mesh",
        "high",
        8.1,
        "triaged",
        "Authorization policies fall back to allow-all while the service-mesh"
        " relation is being re-established.",
        "2026-10-09",
    ),
    (
        "library:charms.prometheus_k8s.v0.prometheus_scrape",
        "medium",
        5.3,
        "triaged",
        "An unbounded number of scrape jobs accepted from relation data can"
        " exhaust charm memory (denial of service).",
        "2026-05-21",
    ),
    (
        "interface:ingress",
        "low",
        3.7,
        "triaged",
        "Overlapping path prefixes requested over the ingress relation can"
        " shadow another application's route.",
        "2026-03-17",
    ),
    (
        "library:charms.loki_k8s.v1.loki_push_api",
        "low",
        3.3,
        "fixed",
        "Alert rule files forwarded to Loki were written with world-readable"
        " permissions inside the charm container.",
        "2026-02-04",
    ),
    (
        "library:charms.data_platform_libs.v0.data_interfaces",
        "medium",
        5.5,
        "fixed",
        "Database credentials could be included in relation-changed debug"
        " logs.",
        "2026-01-13",
    ),
    (
        "interface:catalogue",
        "low",
        2.6,
        "triaged",
        "Catalogue entries accept javascript: URLs for application links.",
        "2026-10-24",
    ),
]

ILLUSTRATIVE_NOTES = {
    "CHARM-2026-0007": "Accepted risk: Juju admins control ingress and route"
    " conflicts are surfaced by the ingress provider.",
    "fixed": "Fixed in the vendored library version.",
    "ready-for-release": "Fixed in the library; awaiting the next charm"
    " release.",
}


def illustrative_vulnerabilities(deps_by_id):
    vulns = []
    for index, item in enumerate(ILLUSTRATIVE, start=1):
        dep_id, severity, score, status, summary, published = item
        dep = deps_by_id[dep_id]
        vulns.append(
            {
                "id": f"CHARM-2026-{index:04d}",
                "cve": None,
                "summary": summary,
                "severity": severity,
                "cvss": score,
                "dependency": dep_id,
                "installed_version": dep["version"],
                "fixed_version": dep["version"] if status == "fixed" else None,
                "published": published,
                "source": "Illustrative",
                "url": None,
                "status": status,
                "status_note": ILLUSTRATIVE_NOTES.get(
                    f"CHARM-2026-{index:04d}", ILLUSTRATIVE_NOTES.get(status)
                ),
            }
        )
    return vulns


# --------------------------------------------------------------------------
# Maintenance status
# --------------------------------------------------------------------------


def violates(constraint, version):
    if not constraint or not version:
        return False
    try:
        return Version(version) not in SpecifierSet(constraint)
    except (InvalidSpecifier, InvalidVersion):
        return False


def assign_status(vuln, dep, newer, snapshot_date):
    """Derive a maintenance status (Triaged, In progress, Ready for release,
    Fixed) from fix availability, severity and age."""
    fixed = vuln["fixed_version"]
    if vuln["state"] == "fixed":
        return "fixed", f"Resolved by {dep['name']} {fixed}."

    published = vuln["published"] or snapshot_date.isoformat()
    age = (snapshot_date - datetime.date.fromisoformat(published)).days
    severity = vuln["severity"]

    if newer and fixed:
        target = {
            "application": newer["version"],
            "runtime": newer["go"],
            "go-module": newer["modules"].get(dep["name"]),
        }.get(dep["type"])
        target_v = parse_version(target)
        if target_v and target_v >= parse_version(fixed):
            return (
                "ready-for-release",
                f"Fixed in the Grafana {newer['version']} rock; pending"
                " charm release.",
            )

    if dep["type"] == "python-package" and violates(dep["constraint"], fixed):
        return (
            "triaged",
            f"Fix requires {dep['name']} {fixed}, blocked by the"
            f" `{dep['name']}{dep['constraint']}` pin in pyproject.toml.",
        )
    if not fixed:
        return "triaged", "No upstream fix available yet."
    if severity in ("critical", "high") and age > 14:
        return "in-progress", None
    return "triaged", "Fix available upstream; not yet scheduled."


# --------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Generate a charm dependency and vulnerability snapshot."
    )
    parser.add_argument("charm")
    parser.add_argument(
        "--date",
        default=datetime.date.today().isoformat(),
        help="Snapshot date used for age-based statuses (YYYY-MM-DD)",
    )
    args = parser.parse_args()
    snapshot_date = datetime.date.fromisoformat(args.date)

    info = get_charm_info(args.charm)
    metadata = info["metadata"]
    source = (metadata.get("source") or [None])[0]
    if not source:
        sys.exit("Charm metadata has no source repository")
    print(f"Cloning {source}", file=sys.stderr)
    repo = clone(source)

    print("Inspecting OCI resources", file=sys.stderr)
    deps, newer = image_dependencies(
        args.charm, metadata, info["resources"], repo
    )
    deps += interface_dependencies(metadata)
    deps += library_dependencies(repo)
    deps += python_dependencies(repo)
    deps_by_id = {d["id"]: d for d in deps}

    print("Querying OSV.dev", file=sys.stderr)
    vulns = collect_vulnerabilities(deps, snapshot_date)
    for vuln in vulns:
        dep = deps_by_id[vuln["dependency"]]
        vuln["status"], vuln["status_note"] = assign_status(
            vuln, dep, newer, snapshot_date
        )
        del vuln["state"]
    vulns += illustrative_vulnerabilities(deps_by_id)
    vulns.sort(
        key=lambda v: (
            SEVERITY_ORDER.index(v["severity"]),
            -(v["cvss"] or 0),
            v["id"],
        )
    )

    report = {
        "charm": args.charm,
        "generated_at": snapshot_date.isoformat(),
        "revision": info["revision"],
        "channel": info["channel"],
        "base": f"{info['base']['name'].title()} {info['base']['channel']}",
        "source": source,
        "newer_workload": (
            {"version": newer["version"], "go": newer["go"]} if newer else None
        ),
        "dependencies": deps,
        "vulnerabilities": vulns,
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIR / f"{args.charm}.json"
    output.write_text(json.dumps(report, indent=1) + "\n")
    print(
        f"Wrote {output}: {len(deps)} dependencies,"
        f" {len(vulns)} vulnerabilities",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
