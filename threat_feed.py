"""
XentinelAI — Threat Intelligence Feed
Polls public security databases and serves latest threats.

Sources:
  1. NVD (National Vulnerability Database) — NIST's authoritative CVE feed
  2. CISA KEV (Known Exploited Vulnerabilities) — actively exploited CVEs
  3. OSV (Open Source Vulnerabilities) — package-level vulnerabilities

Polling: Background task runs every 6 hours, caches to disk.
No Redis required — uses a simple JSON file cache.

Endpoints:
  GET /threats/latest      — latest CVEs (CRITICAL + HIGH from NVD)
  GET /threats/kev         — CISA actively exploited vulnerabilities
  GET /threats/refresh     — manually trigger a cache refresh
"""

import os
import json
import time
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL    = 6 * 3600          # 6 hours in seconds
MAX_RESULTS  = 20                 # CVEs to show per page
NVD_TIMEOUT  = 20
CISA_TIMEOUT = 15

_cache_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Cache helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cache_path(reports_dir: str, key: str) -> str:
    return os.path.join(reports_dir, f"threat-cache-{key}.json")


def _read_cache(reports_dir: str, key: str) -> Optional[Dict]:
    path = _cache_path(reports_dir, key)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        age = time.time() - data.get("cached_at", 0)
        if age < CACHE_TTL:
            return data
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return None


def _write_cache(reports_dir: str, key: str, data: Dict) -> None:
    path = _cache_path(reports_dir, key)
    data["cached_at"] = time.time()
    data["cached_at_iso"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        print(f"[THREATS] Cache write failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# NVD fetcher
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_nvd(reports_dir: str) -> Dict[str, Any]:
    """Fetch latest CRITICAL and HIGH CVEs from NVD."""
    cached = _read_cache(reports_dir, "nvd")
    if cached:
        print("[THREATS] NVD: serving from cache")
        return cached

    print("[THREATS] NVD: fetching fresh data")
    all_vulns = []

    for severity in ("CRITICAL", "HIGH"):
        # NVD: last 30 days, ordered by published date descending
        pub_end   = datetime.now(timezone.utc)
        pub_start = pub_end - timedelta(days=30)

        params = (
            f"?cvssV3Severity={severity}"
            f"&pubStartDate={pub_start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
            f"&pubEndDate={pub_end.strftime('%Y-%m-%dT%H:%M:%S.999')}"
            f"&resultsPerPage={MAX_RESULTS}"
            f"&startIndex=0"
        )
        url = NVD_API_URL + params

        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "XentinelAI/1.0 (security research tool)",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=NVD_TIMEOUT) as resp:
                raw = json.loads(resp.read().decode())

            for item in raw.get("vulnerabilities", []):
                cve  = item.get("cve", {})
                vuln = _parse_nvd_item(cve, severity)
                if vuln:
                    all_vulns.append(vuln)

        except urllib.error.HTTPError as e:
            if e.code == 429:
                print(f"[THREATS] NVD rate limited — using cached data if available")
            else:
                print(f"[THREATS] NVD HTTP error {e.code}: {e.reason}")
        except Exception as e:
            print(f"[THREATS] NVD fetch error: {type(e).__name__}: {e}")

        # NVD rate limit: 5 requests per 30s without API key
        time.sleep(6)

    # Sort by published date descending
    all_vulns.sort(key=lambda v: v.get("published", ""), reverse=True)

    result = {
        "source":    "NVD",
        "count":     len(all_vulns),
        "vulns":     all_vulns,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_cache(reports_dir, "nvd", result)
    return result


def _parse_nvd_item(cve: Dict, severity: str) -> Optional[Dict]:
    """Parse a single NVD CVE item into a clean dict."""
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Description
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")[:400]
            break

    # CVSS score
    score = None
    vector = ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            score  = m.get("baseScore")
            vector = m.get("vectorString", "")
            break

    # Published date
    published = cve.get("published", "")[:10]

    # References
    refs = [r.get("url", "") for r in cve.get("references", [])[:3] if r.get("url")]

    # CWE
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)

    return {
        "cve_id":    cve_id,
        "severity":  severity,
        "score":     score,
        "vector":    vector,
        "published": published,
        "description": desc,
        "cwes":      cwes[:3],
        "refs":      refs,
        "kev":       False,   # will be overlaid by CISA KEV
    }


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV fetcher
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_kev(reports_dir: str) -> Dict[str, Any]:
    """Fetch CISA Known Exploited Vulnerabilities catalogue."""
    cached = _read_cache(reports_dir, "kev")
    if cached:
        print("[THREATS] KEV: serving from cache")
        return cached

    print("[THREATS] KEV: fetching fresh data")
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={
            "User-Agent": "XentinelAI/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=CISA_TIMEOUT) as resp:
            raw = json.loads(resp.read().decode())

        vulns = raw.get("vulnerabilities", [])

        # Sort by dateAdded descending, take most recent 50
        vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        recent = vulns[:50]

        # Build a set of KEV CVE IDs for quick lookup
        kev_ids = {v.get("cveID", "") for v in vulns}

        parsed = []
        for v in recent:
            parsed.append({
                "cve_id":       v.get("cveID", ""),
                "vendor":       v.get("vendorProject", ""),
                "product":      v.get("product", ""),
                "vuln_name":    v.get("vulnerabilityName", ""),
                "date_added":   v.get("dateAdded", ""),
                "due_date":     v.get("dueDate", ""),
                "description":  v.get("shortDescription", "")[:300],
                "action":       v.get("requiredAction", ""),
                "notes":        v.get("notes", ""),
                "kev":          True,
            })

        result = {
            "source":     "CISA KEV",
            "total_kev":  len(kev_ids),
            "count":      len(parsed),
            "kev_ids":    list(kev_ids),
            "vulns":      parsed,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_cache(reports_dir, "kev", result)
        return result

    except Exception as e:
        print(f"[THREATS] KEV fetch error: {type(e).__name__}: {e}")
        return {
            "source":  "CISA KEV",
            "error":   str(e),
            "count":   0,
            "kev_ids": [],
            "vulns":   [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Cross-reference NVD with KEV
# ─────────────────────────────────────────────────────────────────────────────

def _overlay_kev(nvd_data: Dict, kev_data: Dict) -> Dict:
    """Mark NVD CVEs that appear in CISA KEV as actively exploited."""
    kev_ids = set(kev_data.get("kev_ids", []))
    for vuln in nvd_data.get("vulns", []):
        if vuln.get("cve_id") in kev_ids:
            vuln["kev"] = True
            vuln["kev_badge"] = "⚠ Actively Exploited (CISA KEV)"
    return nvd_data


# ─────────────────────────────────────────────────────────────────────────────
# Background poller
# ─────────────────────────────────────────────────────────────────────────────

_poll_thread: Optional[threading.Thread] = None


def start_background_poller(reports_dir: str) -> None:
    """Start a background thread that refreshes the threat cache every 6 hours."""
    global _poll_thread

    def _poll():
        while True:
            print("[THREATS] Background poll starting")
            try:
                with _cache_lock:
                    kev = _fetch_kev(reports_dir)
                    nvd = _fetch_nvd(reports_dir)
                    _overlay_kev(nvd, kev)
                    # Re-save with KEV overlay applied
                    _write_cache(reports_dir, "nvd", nvd)
            except Exception as e:
                print(f"[THREATS] Background poll error: {e}")
            print(f"[THREATS] Next poll in {CACHE_TTL//3600}h")
            time.sleep(CACHE_TTL)

    if _poll_thread is None or not _poll_thread.is_alive():
        _poll_thread = threading.Thread(target=_poll, daemon=True, name="threat-poller")
        _poll_thread.start()
        print("[THREATS] Background poller started")


# ─────────────────────────────────────────────────────────────────────────────
# Public entry points
# ─────────────────────────────────────────────────────────────────────────────

def get_latest_threats(reports_dir: str) -> Dict[str, Any]:
    """
    Get latest CRITICAL + HIGH CVEs with CISA KEV overlay.
    Serves from cache if fresh, fetches live if stale.
    """
    with _cache_lock:
        kev = _fetch_kev(reports_dir)
        nvd = _fetch_nvd(reports_dir)
        nvd = _overlay_kev(nvd, kev)

    kev_count = sum(1 for v in nvd.get("vulns", []) if v.get("kev"))

    return {
        "nvd":        nvd,
        "kev_count":  kev_count,
        "total_kev":  kev.get("total_kev", 0),
        "fetched_at": nvd.get("fetched_at", ""),
        "cached_at":  nvd.get("cached_at_iso", ""),
    }


def get_kev_feed(reports_dir: str) -> Dict[str, Any]:
    """Get the latest CISA KEV entries."""
    with _cache_lock:
        return _fetch_kev(reports_dir)


def force_refresh(reports_dir: str) -> Dict[str, Any]:
    """Force a cache refresh — deletes cached files and re-fetches."""
    for key in ("nvd", "kev"):
        path = _cache_path(reports_dir, key)
        try:
            os.remove(path)
        except OSError:
            pass

    kev = _fetch_kev(reports_dir)
    nvd = _fetch_nvd(reports_dir)
    nvd = _overlay_kev(nvd, kev)
    _write_cache(reports_dir, "nvd", nvd)

    return {"status": "refreshed", "nvd_count": nvd.get("count", 0), "kev_total": kev.get("total_kev", 0)}
