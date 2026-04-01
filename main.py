import os
import sys
import json
import re
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import ScanResult, Severity
from ingest import clone_github, extract_zip, cleanup
from scanners import code as code_scanner
from scanners import iac as iac_scanner
from scanners import iam as iam_scanner
from ai_engine import enrich_scan
from dotenv import load_dotenv
from risk_trend import attach_trend
from github_pr import create_fix_pr, parse_github_url, GitHubAPIError
from simulate_route import router as simulate_router
from slack_notify import notify_scan_complete
from pdf_report import generate_pdf
from remediation_roadmap import build_roadmap
from nlp_query import answer_question
from trend_api import get_trend_data
from compliance_map import build_compliance_report
from portfolio_scanner import run_portfolio_scan
load_dotenv()

try:
    import boto3
    _boto3_ok = True
except ImportError:
    _boto3_ok = False

AWS_ENABLED = _boto3_ok and bool(os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE"))

app = FastAPI(
    title="XentinelAI",
    description="Automated Security Review Agent — Code · IaC · IAM",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(simulate_router)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR  = os.path.join(BASE_DIR, "uploads")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(UPLOAD_DIR,  exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

scan_store: dict[str, ScanResult] = {}


class GithubScanRequest(BaseModel):
    github_url: str
    skip_ai: bool = False

class CreatePRRequest(BaseModel):
    github_url: str
    github_token: str
    finding_ids: list = []

class AskRequest(BaseModel):
    question: str

class PortfolioRequest(BaseModel):
    repos:       list[str]
    skip_ai:     bool = True
    max_workers: int  = 3


# ── Pipeline ──────────────────────────────────────────────────────────────────

def run_scan_pipeline(repo_path: str, repo_name: str, skip_ai: bool = False) -> ScanResult:
    result = ScanResult(repo=repo_name)
    print(f"[SCAN] Starting: {repo_name}")

    print("[SCAN] Code scanner...")
    try:
        result.findings.extend(code_scanner.run(repo_path))
    except Exception as e:
        print(f"[SCAN] Code scanner error: {e}")

    print("[SCAN] IaC scanner...")
    try:
        result.findings.extend(iac_scanner.run(repo_path))
    except Exception as e:
        print(f"[SCAN] IaC scanner error: {e}")

    print("[SCAN] IAM scanner...")
    try:
        result.findings.extend(iam_scanner.run(repo_path))
    except Exception as e:
        print(f"[SCAN] IAM scanner error: {e}")

    print(f"[SCAN] Raw findings: {len(result.findings)}")

    if not skip_ai:
        print("[SCAN] AI enrichment...")
        try:
            result = enrich_scan(result, repo_path)
        except Exception as e:
            print(f"[SCAN] AI enrichment error: {e}")

    result.compute_stats()
    result_dict = json.loads(result.model_dump_json())
    result_dict["repo_path"] = repo_path
    result_dict = attach_trend(result_dict, REPORTS_DIR)

    report_path = os.path.join(REPORTS_DIR, f"{result.scan_id}.json")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(result_dict, f, indent=2)
    except OSError as e:
        print(f"[SCAN] Could not save report: {e}")

    if AWS_ENABLED:
        _save_to_dynamo(result)
        if result.stats.get("critical", 0) > 0:
            _send_sns_alert(result)

    notify_scan_complete(
        scan_id       = result.scan_id,
        repo          = result.repo,
        scanned_at    = result.scanned_at,
        stats         = result.stats,
        attack_chains = [c.model_dump() for c in result.attack_chains],
        dashboard_url = os.getenv("DASHBOARD_URL", "http://localhost:8000"),
    )

    print(f"[SCAN] Done. scan_id={result.scan_id} findings={result.stats.get('total',0)}")
    return result


# ── AWS helpers ───────────────────────────────────────────────────────────────

def _save_to_dynamo(result: ScanResult) -> None:
    try:
        import boto3
        from boto3.dynamodb.types import TypeSerializer  # noqa
        table_name = os.getenv("DYNAMODB_TABLE", "xentinel-scans")
        dynamodb   = boto3.resource("dynamodb", region_name=os.getenv("AWS_REGION", "us-east-1"))
        table      = dynamodb.Table(table_name)
        findings_summary = [
            {"id": f.id, "domain": f.domain, "severity": f.severity,
             "title": f.title, "file": f.file}
            for f in result.findings[:100]
        ]
        table.put_item(Item={
            "scan_id":          result.scan_id,
            "repo":             result.repo,
            "scanned_at":       result.scanned_at,
            "stats":            result.stats,
            "findings_summary": findings_summary,
            "attack_chains":    len(result.attack_chains),
        })
        print(f"[DYNAMO] Saved {result.scan_id}")
    except Exception as e:
        print(f"[DYNAMO] Failed: {e}")


def _send_sns_alert(result: ScanResult) -> None:
    try:
        import boto3
        topic_arn = os.getenv("SNS_TOPIC_ARN")
        if not topic_arn:
            return
        sns      = boto3.client("sns", region_name=os.getenv("AWS_REGION", "us-east-1"))
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL.value]
        lines    = "\n".join(f"  • {f.title} ({f.file or 'N/A'})" for f in critical[:5])
        message  = (
            f"XentinelAI — {len(critical)} CRITICAL findings in '{result.repo}'\n\n"
            f"{lines}\n\n"
            f"Scan ID: {result.scan_id}\n"
            f"Total findings: {result.stats.get('total', 0)}"
        )
        sns.publish(
            TopicArn = topic_arn,
            Message  = message,
            Subject  = f"[XentinelAI CRITICAL] {result.repo} — {len(critical)} critical issues",
        )
        print(f"[SNS] Alert sent")
    except Exception as e:
        print(f"[SNS] Failed: {e}")


# ── Utilities ─────────────────────────────────────────────────────────────────

def _safe_scan_id(scan_id: str) -> str:
    """Whitelist scan_id to UUID chars only — prevents path traversal."""
    return re.sub(r"[^a-zA-Z0-9\-]", "", scan_id)[:64]


def _load_scan_json(scan_id: str) -> dict:
    """Load a scan JSON from disk. Raises HTTPException if not found."""
    report_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Scan not found")
    with open(report_path, encoding="utf-8") as f:
        return json.load(f)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    dash = os.path.join(BASE_DIR, "dashboard.html")
    if os.path.exists(dash):
        return FileResponse(dash, media_type="text/html")
    return {"name": "XentinelAI", "version": "1.0.0", "status": "ready"}


@app.get("/health")
def health():
    return {
        "status":      "ok",
        "aws_enabled": AWS_ENABLED,
        "region":      os.getenv("AWS_REGION", "us-east-1"),
        "version":     "1.0.0",
    }


@app.get("/{filename}.html")
def serve_html(filename: str):
    allowed = {"dashboard", "card", "simulation", "comparison", "insights", "compliance"}
    if filename not in allowed:
        raise HTTPException(status_code=404, detail="Not found")
    path = os.path.join(BASE_DIR, f"{filename}.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path, media_type="text/html")


@app.post("/scan/github", response_model=ScanResult)
def scan_github(req: GithubScanRequest):
    repo_path = None
    try:
        repo_path = clone_github(req.github_url, UPLOAD_DIR)
        repo_name = req.github_url.rstrip("/").split("/")[-1]
        result    = run_scan_pipeline(repo_path, repo_name, req.skip_ai)
        scan_store[result.scan_id] = result
        return result
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {type(e).__name__}: {e}")
    finally:
        if repo_path:
            cleanup(repo_path)


@app.post("/scan/upload", response_model=ScanResult)
async def scan_upload(
    file:    UploadFile = File(...),
    skip_ai: bool       = Query(False),
):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted")

    safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", os.path.basename(file.filename))
    zip_path  = os.path.join(UPLOAD_DIR, safe_name)
    repo_path = None

    try:
        contents = await file.read()
        if len(contents) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 50 MB)")
        if len(contents) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        with open(zip_path, "wb") as f:
            f.write(contents)

        repo_path = extract_zip(zip_path, UPLOAD_DIR)
        repo_name = safe_name.rsplit(".zip", 1)[0]
        result    = run_scan_pipeline(repo_path, repo_name, skip_ai)
        scan_store[result.scan_id] = result
        return result

    except HTTPException:
        raise
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {type(e).__name__}: {e}")
    finally:
        try:
            if os.path.exists(zip_path):
                os.remove(zip_path)
        except OSError:
            pass
        if repo_path:
            cleanup(repo_path)


# ── Collection endpoints — MUST be before /scan/{scan_id} ────────────────────

@app.get("/scans/trend")
def scans_trend():
    return get_trend_data(REPORTS_DIR)


@app.get("/scans")
def list_scans(limit: int = Query(20, ge=1, le=100)):
    reports = sorted(
        Path(REPORTS_DIR).glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:limit]

    results = []
    for r in reports:
        try:
            with open(r, encoding="utf-8") as f:
                data = json.load(f)
            results.append({
                "scan_id":    data["scan_id"],
                "repo":       data["repo"],
                "scanned_at": data["scanned_at"],
                "stats":      data.get("stats", {}),
            })
        except Exception:
            continue
    return results


@app.post("/portfolio/scan")
def portfolio_scan(req: PortfolioRequest):
    if not req.repos:
        raise HTTPException(status_code=400, detail="No repos provided")
    return run_portfolio_scan(
        repo_urls   = req.repos,
        upload_dir  = UPLOAD_DIR,
        reports_dir = REPORTS_DIR,
        skip_ai     = req.skip_ai,
        max_workers = min(req.max_workers, 5),
    )


# ── Per-scan endpoints ────────────────────────────────────────────────────────

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    scan_id = _safe_scan_id(scan_id)
    if not scan_id:
        raise HTTPException(status_code=400, detail="Invalid scan_id")

    if scan_id in scan_store:
        result = scan_store[scan_id]
        result_dict = json.loads(result.model_dump_json())
        result_dict = attach_trend(result_dict, REPORTS_DIR)
        return result_dict

    report_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    if os.path.exists(report_path):
        try:
            with open(report_path, encoding="utf-8") as f:
                result_dict = json.load(f)
            result_dict = attach_trend(result_dict, REPORTS_DIR)
            return result_dict
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to load report: {e}")

    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/scan/{scan_id}/report")
def download_report(scan_id: str):
    scan_id = _safe_scan_id(scan_id)
    report_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        report_path,
        media_type="application/json",
        filename=f"xentinel-report-{scan_id}.json",
    )


@app.get("/scan/{scan_id}/pdf")
def download_pdf(scan_id: str):
    scan_id = _safe_scan_id(scan_id)
    try:
        scan = _load_scan_json(scan_id)
        pdf_bytes = generate_pdf(scan)
        return Response(
            content    = pdf_bytes,
            media_type = "application/pdf",
            headers    = {"Content-Disposition": f"attachment; filename=xentinel-{scan_id[:8]}.pdf"},
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")


@app.get("/scan/{scan_id}/roadmap")
def get_roadmap(scan_id: str):
    scan_id = _safe_scan_id(scan_id)
    scan = _load_scan_json(scan_id)
    return build_roadmap(scan)


@app.get("/scan/{scan_id}/compliance")
def get_compliance(scan_id: str):
    scan_id = _safe_scan_id(scan_id)
    scan = _load_scan_json(scan_id)
    return build_compliance_report(scan)


@app.post("/scan/{scan_id}/ask")
def ask_question(scan_id: str, req: AskRequest):
    scan_id = _safe_scan_id(scan_id)
    scan = _load_scan_json(scan_id)
    return answer_question(scan, req.question)


@app.post("/scan/{scan_id}/create-pr")
def create_pr(scan_id: str, req: CreatePRRequest):
    scan_id = _safe_scan_id(scan_id)

    result = None
    if scan_id in scan_store:
        result = scan_store[scan_id]
    else:
        report_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
        if os.path.exists(report_path):
            try:
                with open(report_path, encoding="utf-8") as f:
                    from models import ScanResult as SR
                    result = SR(**json.load(f))
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to load scan: {e}")

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [f.model_dump() for f in result.findings if f.fixed_code]
    if req.finding_ids:
        findings = [f for f in findings if f["id"] in req.finding_ids]

    if not findings:
        raise HTTPException(
            status_code=400,
            detail="No findings with AI-generated fixes found. Run the scan with AI enrichment enabled."
        )

    try:
        pr_result = create_fix_pr(
            github_url = req.github_url,
            token      = req.github_token,
            scan_id    = scan_id,
            findings   = findings,
            repo_name  = result.repo,
        )
        return pr_result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except GitHubAPIError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PR creation failed: {type(e).__name__}: {e}")