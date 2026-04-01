"""
github_pr.py — Auto-PR Fix Generator
Creates a GitHub branch + pull request applying AI-generated fixed_code patches.

IMPORTANT NOTES (surfaced in the UI — do not remove):
  - Requires a GitHub Personal Access Token with 'repo' write scope
  - Only works on repos the token owner has push access to
  - This is a best-effort patch: fixed_code is an AI snippet, not a full diff
  - For demo purposes, works reliably on xentinel-demo-repo or your own repos
  - In production, a proper diff/patch pipeline would replace the snippet approach

Drop-in — no changes to existing files required.
Integrated via: POST /scan/{scan_id}/create-pr  (added to main.py)
"""

import os
import re
import base64
import json
import datetime
import urllib.request
import urllib.error
from typing import Optional


# ── GitHub API helpers ────────────────────────────────────────────────────────

class GitHubAPIError(Exception):
    def __init__(self, status: int, message: str):
        self.status  = status
        self.message = message
        super().__init__(f"GitHub API {status}: {message}")


def _gh_request(
    method:  str,
    path:    str,
    token:   str,
    payload: Optional[dict] = None,
) -> dict:
    """
    Minimal GitHub REST API client using stdlib only — no extra dependencies.
    Raises GitHubAPIError on non-2xx responses.
    """
    url  = f"https://api.github.com{path}"
    data = json.dumps(payload).encode() if payload else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization",        f"Bearer {token}")
    req.add_header("Accept",               "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Content-Type",         "application/json")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            msg = json.loads(body).get("message", body)
        except Exception:
            msg = body
        raise GitHubAPIError(e.code, msg)


def _get_default_branch(owner: str, repo: str, token: str) -> str:
    data = _gh_request("GET", f"/repos/{owner}/{repo}", token)
    return data.get("default_branch", "main")


def _get_file(owner: str, repo: str, path: str, branch: str, token: str) -> tuple[str, str]:
    """Returns (decoded_content, sha)."""
    data    = _gh_request("GET", f"/repos/{owner}/{repo}/contents/{path}?ref={branch}", token)
    content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    return content, data["sha"]


def _create_branch(owner: str, repo: str, new_branch: str, base_sha: str, token: str) -> None:
    _gh_request("POST", f"/repos/{owner}/{repo}/git/refs", token, {
        "ref": f"refs/heads/{new_branch}",
        "sha": base_sha,
    })


def _update_file(
    owner:      str,
    repo:       str,
    path:       str,
    branch:     str,
    new_content: str,
    sha:        str,
    message:    str,
    token:      str,
) -> None:
    encoded = base64.b64encode(new_content.encode()).decode()
    _gh_request("PUT", f"/repos/{owner}/{repo}/contents/{path}", token, {
        "message": message,
        "content": encoded,
        "sha":     sha,
        "branch":  branch,
    })


def _create_pr(
    owner:   str,
    repo:    str,
    head:    str,
    base:    str,
    title:   str,
    body:    str,
    token:   str,
) -> str:
    data = _gh_request("POST", f"/repos/{owner}/{repo}/pulls", token, {
        "title": title,
        "head":  head,
        "base":  base,
        "body":  body,
    })
    return data["html_url"]


# ── Patch application ─────────────────────────────────────────────────────────

def _apply_patch(original: str, fixed_code: str, line: Optional[int]) -> str:
    """
    Best-effort splice of fixed_code into original file around the vulnerable line.
    Strategy:
      1. If line is known, replace a window of ±3 lines around it with fixed_code.
      2. If no line info, append fixed_code as a comment block at the end.
    This is intentionally conservative — it never deletes large blocks of code.
    """
    lines = original.splitlines(keepends=True)

    if line and 1 <= line <= len(lines):
        # Replace a small window around the vulnerable line
        start = max(0,          line - 2)
        end   = min(len(lines), line + 2)
        patched = (
            lines[:start]
            + [fixed_code.rstrip() + "\n"]
            + lines[end:]
        )
        return "".join(patched)

    # Fallback — append with clear marker
    return original + f"\n\n# === XentinelAI Fix Applied ===\n{fixed_code}\n"


# ── Public API ────────────────────────────────────────────────────────────────

def parse_github_url(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL. Raises ValueError if invalid."""
    url   = url.rstrip("/")
    match = re.search(r"github\.com[:/]([^/]+)/([^/\.]+)", url)
    if not match:
        raise ValueError(f"Cannot parse GitHub URL: {url}")
    return match.group(1), match.group(2)


def create_fix_pr(
    github_url:  str,
    token:       str,
    scan_id:     str,
    findings:    list,   # list of Finding-like dicts with fixed_code
    repo_name:   str,
) -> dict:
    """
    Main entry point. Creates a branch, applies AI fixes for all findings
    that have fixed_code, and opens a pull request.

    Returns a dict with pr_url, branch, files_patched, skipped, errors.
    """
    owner, repo = parse_github_url(github_url)

    # Verify token has access
    try:
        _gh_request("GET", f"/repos/{owner}/{repo}", token)
    except GitHubAPIError as e:
        if e.status == 404:
            raise ValueError(
                f"Repository '{owner}/{repo}' not found or token lacks access. "
                "Ensure your PAT has 'repo' scope and you have push access."
            )
        raise

    default_branch = _get_default_branch(owner, repo, token)
    branch_ref     = _gh_request("GET", f"/repos/{owner}/{repo}/git/ref/heads/{default_branch}", token)
    base_sha       = branch_ref["object"]["sha"]

    # Generate unique branch name
    ts         = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    new_branch = f"xentinel/fixes-{ts}"
    _create_branch(owner, repo, new_branch, base_sha, token)

    # Group findings by file — batch patches per file
    file_findings: dict[str, list] = {}
    skipped = []

    for f in findings:
        if not f.get("fixed_code") or not f.get("file"):
            skipped.append({
                "id":    f.get("id"),
                "title": f.get("title"),
                "reason": "no fixed_code or no file path",
            })
            continue

        # Normalise path — strip leading slashes and repo prefix
        file_path = f["file"].lstrip("/")
        # Remove upload temp prefix if present (e.g. uploads/reponame/src/app.py -> src/app.py)
        parts = file_path.split("/")
        if len(parts) > 2 and parts[0] in ("uploads", "xentinel-demo-repo", repo_name):
            file_path = "/".join(parts[2:]) if parts[0] == "uploads" else "/".join(parts[1:])

        file_findings.setdefault(file_path, []).append(f)

    files_patched = []
    errors        = []

    for file_path, file_fixes in file_findings.items():
        try:
            original, sha = _get_file(owner, repo, file_path, default_branch, token)
            patched = original

            for fix in file_fixes:
                patched = _apply_patch(patched, fix["fixed_code"], fix.get("line"))

            commit_msg = (
                f"fix: XentinelAI auto-patch — {len(file_fixes)} finding(s) in {file_path}\n\n"
                + "\n".join(f"- [{f.get('severity','?')}] {f.get('title','?')}" for f in file_fixes)
                + f"\n\nScan ID: {scan_id}"
            )
            _update_file(owner, repo, file_path, new_branch, patched, sha, commit_msg, token)
            files_patched.append({
                "file":         file_path,
                "fixes_applied": len(file_fixes),
            })

        except GitHubAPIError as e:
            errors.append({"file": file_path, "error": str(e)})
        except Exception as e:
            errors.append({"file": file_path, "error": f"{type(e).__name__}: {e}"})

    if not files_patched:
        # Clean up the empty branch
        try:
            _gh_request("DELETE", f"/repos/{owner}/{repo}/git/refs/heads/{new_branch}", token)
        except Exception:
            pass
        raise ValueError(
            "No files could be patched. All findings either lacked fixed_code "
            "or their files could not be found in the repository."
        )

    # Build PR body
    patched_summary = "\n".join(
        f"- `{fp['file']}` ({fp['fixes_applied']} fix{'es' if fp['fixes_applied'] != 1 else ''})"
        for fp in files_patched
    )
    error_summary = ""
    if errors:
        error_summary = "\n\n### ⚠️ Skipped files\n" + "\n".join(
            f"- `{e['file']}`: {e['error']}" for e in errors
        )

    pr_body = f"""## 🛡️ XentinelAI — Automated Security Fix

This PR was generated automatically by [XentinelAI](https://github.com) from scan `{scan_id}`.

> **Note:** These are AI-generated patches (best-effort snippet replacement).  
> Please review each change carefully before merging.  
> For production use, a full diff/patch pipeline is recommended.

### Files patched
{patched_summary}{error_summary}

---
*Generated by XentinelAI · Scan ID: `{scan_id}`*
"""

    pr_url = _create_pr(
        owner = owner,
        repo  = repo,
        head  = new_branch,
        base  = default_branch,
        title = f"[XentinelAI] Auto-fix {len(files_patched)} file(s) — scan {scan_id[:8]}",
        body  = pr_body,
        token = token,
    )

    return {
        "pr_url":        pr_url,
        "branch":        new_branch,
        "files_patched": files_patched,
        "skipped":       skipped,
        "errors":        errors,
        "scan_id":       scan_id,
    }
