import os
import re
import shutil
import zipfile
import subprocess
from urllib.parse import urlparse

_ALLOWED_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}

def _validate_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith("http"):
        url = "https://github.com/" + url
    if url.endswith(".git"):
        url = url[:-4]
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are allowed")
    if parsed.hostname not in _ALLOWED_HOSTS:
        raise ValueError(f"Host '{parsed.hostname}' not allowed. Use: {', '.join(sorted(_ALLOWED_HOSTS))}")
    if not re.match(r"^/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$", parsed.path):
        raise ValueError("URL path does not look like a valid repository")
    return url

def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True, timeout=5)
        return True
    except Exception:
        return False

def clone_github(url: str, base_dir: str) -> str:
    if not _git_available():
        raise RuntimeError("git is not installed or not in PATH")
    url = _validate_url(url)
    repo_name = re.sub(r"[^A-Za-z0-9_.\-]", "_", url.split("/")[-1]) or "repo"
    dest = os.path.join(base_dir, repo_name)
    if os.path.exists(dest):
        shutil.rmtree(dest, ignore_errors=True)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", url, dest],
        capture_output=True, text=True, timeout=90
    )
    if result.returncode != 0:
        raise RuntimeError(f"Git clone failed: {result.stderr.strip()}")
    return dest

def extract_zip(zip_path: str, base_dir: str) -> str:
    dest = os.path.join(base_dir, "uploaded_repo")
    if os.path.exists(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest, exist_ok=True)
    dest_real = os.path.realpath(dest)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
                member.filename = member.filename.lstrip("/").lstrip("./")
                if not member.filename:
                    continue
                target = os.path.realpath(os.path.join(dest_real, member.filename))
                if not (target == dest_real or target.startswith(dest_real + os.sep)):
                    raise RuntimeError(f"Zip slip detected: {member.filename}")
                zf.extract(member, dest_real)
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"Invalid zip file: {e}")
    entries = [e for e in os.listdir(dest) if not e.startswith(".")]
    if len(entries) == 1:
        candidate = os.path.join(dest, entries[0])
        if os.path.isdir(candidate):
            return candidate
    return dest

def cleanup(path: str) -> None:
    if path and os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)
