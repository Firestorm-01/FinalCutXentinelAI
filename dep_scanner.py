"""
XentinelAI — Dependency Vulnerability Scanner (4th Domain: DEPS)

Parses package manifests and checks against the OSV (Open Source Vulnerabilities)
database. OSV is free, no API key required: https://osv.dev/

Supported manifests:
  requirements.txt · package.json · Pipfile · composer.json · go.mod

Endpoint : POST /scan/deps  (accepts repo ZIP or scan_id with repo_path)
Standalone: scan_dependencies(repo_path) -> Dict with findings + summary
"""

import os
import re
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Manifest parsers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_requirements_txt(content: str) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split("#")[0].split(";")[0].strip()
        line_no_extras = re.sub(r"\[.*?\]", "", line)
        m = re.match(
            r"^([A-Za-z0-9_\-\.]+)\s*(?:[=~><!\^]{1,2}=?\s*([0-9][^\s,#]*))?",
            line_no_extras.strip(),
        )
        if m:
            name    = m.group(1).lower()
            version = (m.group(2) or "").strip() if m.group(2) else ""
            deps.append((name, version))
    return deps


def _parse_package_json(content: str) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, AttributeError, TypeError):
        return deps

    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, raw_ver in (data.get(section) or {}).items():
            if not isinstance(raw_ver, str):
                continue
            ver = raw_ver.strip()
            if ver in ("*", "", "x", "latest"):
                deps.append((name.lower(), ""))
                continue
            ver = ver.split("||")[0].strip()
            ver = re.sub(r"^[>=<~^v\s]+", "", ver)
            ver = ver.split()[0]
            ver = re.sub(r"\.x\b", ".0", ver, flags=re.IGNORECASE)
            deps.append((name.lower(), ver))
    return deps


def _parse_pipfile(content: str) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    in_section = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line in ("[packages]", "[dev-packages]"):
            in_section = True
            continue
        if line.startswith("[") and line.endswith("]"):
            in_section = False
            continue
        if not in_section or "=" not in line:
            continue
        name_raw, _, val_raw = line.partition("=")
        name = name_raw.strip().strip('"').lower()
        val  = val_raw.strip().strip('"').strip("'")
        if not name:
            continue
        if val.startswith("{"):
            vm = re.search(r'version\s*=\s*["\']([^"\']+)["\']', val)
            val = vm.group(1) if vm else "*"
        if val in ("*", ""):
            deps.append((name, ""))
            continue
        clean = re.sub(r"^[>=<~^v\s]+", "", val)
        deps.append((name, clean))
    return deps


def _parse_composer_json(content: str) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, AttributeError, TypeError):
        return deps

    for name, raw_ver in (data.get("require") or {}).items():
        if name.lower().startswith(("php", "ext-", "lib-")):
            continue
        if "/" not in name:
            continue
        ver = re.sub(r"^[>=<~^v\*\s]+", "", (raw_ver or "").strip())
        ver = re.split(r"[\|,]", ver)[0].strip()
        deps.append((name.lower(), ver))
    return deps


def _parse_go_mod(content: str) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    in_require = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if re.match(r"^require\s*\($", line):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        single = re.match(r"^require\s+([A-Za-z0-9\./\-_]+)\s+(v[0-9][^\s]*)", line)
        if single:
            deps.append((single.group(1).lower(), single.group(2).lstrip("v")))
            continue
        if in_require:
            m = re.match(r"^([A-Za-z0-9\./\-_]+)\s+(v[0-9][^\s]*)", line)
            if m:
                deps.append((m.group(1).lower(), m.group(2).lstrip("v")))
    return deps


MANIFEST_PARSERS: Dict[str, Tuple[str, Any]] = {
    "requirements.txt": ("pypi",      _parse_requirements_txt),
    "package.json":     ("npm",       _parse_package_json),
    "Pipfile":          ("pypi",      _parse_pipfile),
    "composer.json":    ("packagist", _parse_composer_json),
    "go.mod":           ("go",        _parse_go_mod),
}


# ─────────────────────────────────────────────────────────────────────────────
# OSV API
# ─────────────────────────────────────────────────────────────────────────────

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT   = 20
OSV_CHUNK     = 100


def _query_osv_batch(queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not queries:
        return []

    empty = [{} for _ in queries]
    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data    = payload,
        method  = "POST",
        headers = {"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            body    = resp.read().decode()
            results = json.loads(body).get("results", [])
            if len(results) < len(queries):
                results.extend([{}] * (len(queries) - len(results)))
            return results
    except urllib.error.HTTPError as e:
        print(f"[DEPS] OSV HTTP error {e.code}: {e.reason}")
        return empty
    except Exception as e:
        print(f"[DEPS] OSV unexpected error: {e}")
        return empty


def _query_osv_all(queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for start in range(0, len(queries), OSV_CHUNK):
        chunk   = queries[start : start + OSV_CHUNK]
        partial = _query_osv_batch(chunk)
        results.extend(partial)
    return results


def _fetch_full_vuln(vuln_id: str) -> Dict[str, Any]:
    """Fetches the complete vulnerability definition directly using its ID."""
    url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"[DEPS] OSV fetch error for full vuln {vuln_id}: {e}")
        return {}


_OSV_ECOSYSTEM: Dict[str, str] = {
    "pypi":      "PyPI",
    "npm":       "npm",
    "packagist": "Packagist",
    "go":        "Go",
}


# ─────────────────────────────────────────────────────────────────────────────
# CVSS severity extraction
# ─────────────────────────────────────────────────────────────────────────────

def _cvss_score_from_vector(vector: str) -> Optional[float]:
    m = re.match(r"([0-9]+\.[0-9]+)", vector.strip())
    if m:
        return float(m.group(1))
    return None


def _extract_cvss(vuln: Dict[str, Any]) -> Tuple[Optional[float], str]:
    for s in vuln.get("severity", []):
        score_str = s.get("score", "")
        try:
            score = float(score_str)
            return score, _score_to_severity(score)
        except ValueError:
            pass
        leading = _cvss_score_from_vector(score_str)
        if leading is not None:
            return leading, _score_to_severity(leading)

    db  = vuln.get("database_specific") or {}
    sev = db.get("severity", "")
    if sev.upper() in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        mapped = "MEDIUM" if sev.upper() == "MODERATE" else sev.upper()
        synthetic = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}
        return synthetic.get(mapped, 5.0), mapped

    for key in ("cvss_v3", "cvss_v2", "cvss"):
        raw = db.get(key)
        if not raw:
            continue
        if isinstance(raw, dict):
            score = raw.get("baseScore") or raw.get("base_score")
            if score is not None:
                try:
                    f = float(score)
                    return f, _score_to_severity(f)
                except (ValueError, TypeError):
                    pass
        if isinstance(raw, str):
            leading = _cvss_score_from_vector(raw)
            if leading is not None:
                return leading, _score_to_severity(leading)

    return None, "HIGH"


def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Fixed-version extraction
# ─────────────────────────────────────────────────────────────────────────────

def _semver_key(version_str: str) -> Tuple[int, ...]:
    """Extract numeric components for standard library safe semver sorting."""
    return tuple(int(x) for x in re.split(r'[^\d]+', version_str) if x.isdigit())


def _find_fixed_version(
    vuln:      Dict[str, Any],
    pkg:       str,
    ecosystem: str,
) -> Tuple[Optional[str], str]:
    
    semver_fixed:    List[str] = []
    ecosystem_fixed: List[str] = []
    last_affected:   List[str] = []
    has_git_range                = False
    has_any_range                = False

    pkg_lower = pkg.lower()
    eco_lower = ecosystem.lower()

    for affected in vuln.get("affected", []):
        pkg_info = affected.get("package", {})
        
        # Guard against identically named packages across different ecosystems
        if pkg_info.get("name", "").lower() != pkg_lower:
            continue
        affected_eco = pkg_info.get("ecosystem", "").lower()
        if affected_eco and affected_eco != eco_lower:
            continue

        for rng in affected.get("ranges", []):
            rng_type = rng.get("type", "").upper()
            has_any_range = True

            if rng_type == "GIT":
                has_git_range = True
                continue

            for event in rng.get("events", []):
                fixed = event.get("fixed")
                last  = event.get("last_affected")

                if fixed:
                    if rng_type == "SEMVER":
                        semver_fixed.append(fixed)
                    else:
                        ecosystem_fixed.append(fixed)

                if last:
                    last_affected.append(last)

        # Database_specific fallbacks
        db_spec = affected.get("database_specific") or {}
        lkav = db_spec.get("last_known_affected_version")
        if lkav:
            last_affected.append(lkav)

    top_db = vuln.get("database_specific") or {}
    lkav_top = top_db.get("last_known_affected_version")
    if lkav_top:
        last_affected.append(lkav_top)

    # ── Decision tree ──────────────────────────────────────────────────────
    all_fixed = semver_fixed or ecosystem_fixed
    if all_fixed:
        all_fixed.sort(key=_semver_key)
        return all_fixed[0], "fixed"

    if last_affected:
        last_affected.sort(key=_semver_key)
        return ">" + last_affected[-1], "last_affected"

    if has_git_range and not has_any_range:
        return None, "git_only"

    return None, "unpatched"


# ─────────────────────────────────────────────────────────────────────────────
# Finding builder
# ─────────────────────────────────────────────────────────────────────────────

def _truncate(text: str, max_chars: int = 400) -> str:
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars].rsplit(" ", 1)[0]
    return truncated.rstrip(".,;:") + "…"


def _vuln_to_finding(
    pkg_name:    str,
    pkg_version: str,
    vuln:        Dict[str, Any],
    manifest:    str,
    ecosystem:   str,
) -> Dict[str, Any]:
    vuln_id  = vuln.get("id", "UNKNOWN")
    aliases  = vuln.get("aliases") or []
    cve_ids  = [a for a in aliases if a.startswith("CVE-")]
    cve      = cve_ids[0] if cve_ids else ""
    summary  = vuln.get("summary") or "Vulnerability in dependency"
    details  = _truncate(vuln.get("details") or summary)

    cvss_score, severity = _extract_cvss(vuln)

    fixed_ver, fix_reason = _find_fixed_version(vuln, pkg_name, ecosystem)

    fixed_ver_display = fixed_ver
    if fixed_ver and fixed_ver.startswith(">"):
        fixed_ver_display = None   

    published = (vuln.get("published") or "")[:10]
    modified  = (vuln.get("modified")  or "")[:10]

    cve_label = f" [{cve}]" if cve else f" [{vuln_id}]"
    title = f"Vulnerable dependency: {pkg_name}{cve_label}"

    if fix_reason == "fixed" and fixed_ver:
        fix_hint = (
            f"Update {pkg_name} from {pkg_version or 'unknown'} to "
            f"{fixed_ver} or later to remediate {cve or vuln_id}."
        )
    elif fix_reason == "last_affected" and fixed_ver:
        bare = fixed_ver.lstrip(">")
        fix_hint = (
            f"Upgrade {pkg_name} beyond version {bare}. "
            f"Version {bare} is the last known affected release for {cve or vuln_id}."
        )
    elif fix_reason == "git_only":
        fix_hint = (
            f"No versioned fix available for {pkg_name} ({cve or vuln_id}). "
            f"The advisory only references Git commit hashes. "
            f"Check the repository for a tagged release that includes the patch."
        )
    else:
        fix_hint = (
            f"No fixed version is currently available for {pkg_name} "
            f"({cve or vuln_id}). The vulnerability is unpatched upstream. "
            f"Monitor https://osv.dev/vulnerability/{vuln_id} for updates."
        )

    fixed_code = _build_fix_snippet(pkg_name, pkg_version, fixed_ver_display, manifest)

    refs = [r.get("url") for r in (vuln.get("references") or []) if r.get("url")]

    return {
        "id":              f"dep-{vuln_id}",
        "domain":          "DEPS",
        "severity":        severity,
        "title":           title,
        "description":     details,
        "file":            manifest,
        "line":            None,
        "rule_id":         f"dep-{vuln_id.lower()}",
        "cwe":             "CWE-1035",
        "cwe_name":        "Using Components with Known Vulnerabilities",
        "fix_hint":        fix_hint,
        "fixed_code":      fixed_code,
        "package":         pkg_name,
        "version":         pkg_version or "unpinned",
        "fixed_version":   fixed_ver_display,  
        "fix_reason":      fix_reason,           
        "last_affected":   fixed_ver.lstrip(">") if fix_reason == "last_affected" and fixed_ver else None,
        "ecosystem":       ecosystem,
        "vuln_id":         vuln_id,
        "cve":             cve,
        "cvss_score":      round(cvss_score, 1) if cvss_score is not None else None,
        "summary":         summary,
        "published":       published,
        "modified":        modified,
        "references":      refs[:5],
        "aliases":         aliases,
    }


def _build_fix_snippet(
    pkg:       str,
    current:   str,
    fixed:     Optional[str],
    manifest:  str,
) -> Optional[str]:
    if not fixed:
        return None
    fname = os.path.basename(manifest)
    if fname == "requirements.txt":
        return f"{pkg}>={fixed}"
    if fname == "package.json":
        return f'"{pkg}": "^{fixed}"'
    if fname == "Pipfile":
        return f'{pkg} = ">={fixed}"'
    if fname == "composer.json":
        return f'"{pkg}": "^{fixed}"'
    if fname == "go.mod":
        return f"require {pkg} v{fixed}"
    return f"{pkg} >= {fixed}"


# ─────────────────────────────────────────────────────────────────────────────
# File walker
# ─────────────────────────────────────────────────────────────────────────────

_SKIP_DIRS = frozenset({
    "node_modules", "vendor", "__pycache__", ".git", "venv", ".venv",
    "dist", "build", ".tox", ".pytest_cache", ".mypy_cache",
    "bower_components", ".yarn",
})


def _find_manifests(repo_path: str) -> List[Tuple[str, str, str]]:
    found: List[Tuple[str, str, str]] = []
    for root, dirs, files in os.walk(repo_path, topdown=True):
        dirs[:] = [
            d for d in dirs
            if d not in _SKIP_DIRS and not d.startswith(".")
        ]
        for filename in files:
            if filename in MANIFEST_PARSERS:
                abs_path = os.path.join(root, filename)
                rel_path = os.path.relpath(abs_path, repo_path)
                found.append((abs_path, rel_path, filename))
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def scan_dependencies(repo_path: str) -> Dict[str, Any]:
    empty_result: Dict[str, Any] = {
        "findings":          [],
        "total":             0,
        "critical":          0,
        "high":              0,
        "medium":            0,
        "low":               0,
        "with_fix":          0,
        "without_fix":       0,
        "git_only":          0,
        "manifests_scanned": [],
        "packages_checked":  0,
        "error":             None,
    }

    if not repo_path or not os.path.isdir(repo_path):
        empty_result["error"] = f"repo_path is not a valid directory: {repo_path!r}"
        return empty_result

    manifests = _find_manifests(repo_path)
    if not manifests:
        print("[DEPS] No supported manifest files found")
        return empty_result

    all_findings:      List[Dict[str, Any]] = []
    manifests_scanned: List[str]            = []
    total_packages_checked                  = 0
    full_vuln_cache: Dict[str, Dict[str, Any]] = {}

    for abs_path, rel_path, manifest_name in manifests:
        ecosystem_key, parser = MANIFEST_PARSERS[manifest_name]
        ecosystem             = _OSV_ECOSYSTEM.get(ecosystem_key, "PyPI")

        try:
            with open(abs_path, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError as e:
            print(f"[DEPS] Cannot read {rel_path}: {e}")
            continue

        packages = parser(content)
        if not packages:
            print(f"[DEPS] No packages parsed from {rel_path}")
            continue

        manifests_scanned.append(rel_path)
        total_packages_checked += len(packages)
        print(f"[DEPS] {rel_path}: checking {len(packages)} packages against OSV")

        osv_queries: List[Dict[str, Any]] = []
        for name, version in packages:
            query: Dict[str, Any] = {
                "package": {"name": name, "ecosystem": ecosystem},
            }
            if version:
                query["version"] = version
            osv_queries.append(query)

        results = _query_osv_all(osv_queries)

        # ── Fetch Full Vulnerability Definitions ───────────────────────
        # Isolate all unique vulnerability IDs discovered in this batch
        unique_ids = {
            v["id"] for res in results 
            for v in (res.get("vulns") or []) 
            if "id" in v
        }
        
        for vid in unique_ids:
            if vid not in full_vuln_cache:
                full_vuln_cache[vid] = _fetch_full_vuln(vid)
        # ───────────────────────────────────────────────────────────────

        for idx, result in enumerate(results):
            if idx >= len(packages):
                break
            pkg_name, pkg_version = packages[idx]
            vulns = result.get("vulns") or []
            
            for sparse_vuln in vulns:
                vid = sparse_vuln.get("id")
                if not vid:
                    continue
                
                # Replace the sparse batch vuln with our fully-fetched JSON
                vuln = full_vuln_cache.get(vid, {})
                if not vuln:
                    continue  

                finding = _vuln_to_finding(
                    pkg_name, pkg_version, vuln, rel_path, ecosystem
                )
                all_findings.append(finding)

    # Deduplicate by (package, vuln_id)
    seen:   set               = set()
    deduped: List[Dict[str, Any]] = []
    for f in all_findings:
        key = (f.get("package", ""), f.get("vuln_id", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort: CRITICAL → HIGH → MEDIUM → LOW
    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 9))

    # Build summary counters
    counters: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    with_fix    = 0
    without_fix = 0
    git_only    = 0
    for f in deduped:
        sev = f.get("severity", "LOW")
        counters[sev] = counters.get(sev, 0) + 1
        reason = f.get("fix_reason", "unpatched")
        if reason == "fixed":
            with_fix += 1
        elif reason == "git_only":
            git_only += 1
        else:
            without_fix += 1

    total = len(deduped)
    print(
        f"[DEPS] Done — {total} findings "
        f"(CRIT:{counters['CRITICAL']} HIGH:{counters['HIGH']} "
        f"MED:{counters['MEDIUM']} LOW:{counters['LOW']}) "
        f"fixed:{with_fix} unpatched:{without_fix} git_only:{git_only} "
        f"across {len(manifests_scanned)} manifest(s)"
    )

    return {
        "findings":          deduped,
        "total":             total,
        "critical":          counters["CRITICAL"],
        "high":              counters["HIGH"],
        "medium":            counters["MEDIUM"],
        "low":               counters["LOW"],
        "with_fix":          with_fix,
        "without_fix":       without_fix,
        "git_only":          git_only,
        "manifests_scanned": manifests_scanned,
        "packages_checked":  total_packages_checked,
        "error":             None,
    }