import threading
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

try:
    from . import database as db
    from .runner import run_scan_job
except ImportError:
    import database as db
    from runner import run_scan_job

app = FastAPI(title="AWS Assessment Scanner")
db.init_db()


class ScanRequest(BaseModel):
    account_name: str
    access_key: str
    secret_key: str
    session_token: Optional[str] = None
    region: str = "eu-central-1"


@app.post("/api/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if not req.account_name.strip() or not req.access_key.strip() or not req.secret_key.strip():
        raise HTTPException(400, "account_name, access_key, and secret_key are required")

    scan_id = db.create_scan(req.account_name.strip())

    # Runs in a real background thread (not FastAPI's BackgroundTasks, which
    # would block the response) since a full assessment can take minutes.
    thread = threading.Thread(
        target=run_scan_job,
        args=(scan_id, req.account_name.strip(), req.access_key.strip(),
              req.secret_key.strip(), req.session_token, req.region),
        daemon=True,
    )
    thread.start()

    return {"scan_id": scan_id, "status": "running"}


@app.get("/api/reports")
def list_reports():
    return db.list_scans()


@app.get("/api/reports/{scan_id}/download")
def download_report(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan or scan["status"] != "success" or not scan["file_path"]:
        raise HTTPException(404, "Report not available")
    path = Path(scan["file_path"])
    if not path.exists():
        raise HTTPException(404, "Report file missing on disk")
    return FileResponse(
        path,
        filename=path.name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.get("/api/reports/{scan_id}/download/pdf")
def download_report_pdf(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan or scan["status"] != "success" or not scan.get("pdf_path"):
        raise HTTPException(404, "PDF report not available")
    path = Path(scan["pdf_path"])
    if not path.exists():
        raise HTTPException(404, "PDF file missing on disk")
    return FileResponse(
        path,
        filename=path.name,
        media_type="application/pdf",
    )


@app.get("/api/reports/{scan_id}/download/monitoring")
@app.get("/api/reports/{scan_id}/download/services")
def download_report_monitoring(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan or scan["status"] != "success" or not scan.get("svc_path"):
        raise HTTPException(404, "Monitoring file not available")
    path = Path(scan["svc_path"])
    if not path.exists():
        raise HTTPException(404, "Monitoring file missing on disk")
    return FileResponse(
        path,
        filename=path.name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")
