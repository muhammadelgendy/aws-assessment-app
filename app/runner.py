import os
import re
import boto3
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from .scanner_core import AWSAssessment
    from . import database as db
except ImportError:
    from scanner_core import AWSAssessment
    import database as db

REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", name.strip()) or "account"


def run_scan_job(scan_id: int, account_name: str, access_key: str, secret_key: str,
                  session_token: Optional[str], region: str):
    """
    Runs synchronously inside a background thread. Talks only to the DB and
    filesystem — never raises out to the caller, so the thread never dies silently.
    """
    def progress_callback(step_name: str, completed: int, total: int):
        progress = min(99, int((completed / total) * 100))
        db.update_progress(scan_id, progress, step_name.replace('_', ' ').title())

    db.update_progress(scan_id, 2, 'Starting scan')
    try:
        assessment = AWSAssessment(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token or None,
            region_name=region,
        )
        assessment.run_assessment(progress_callback=progress_callback)
        excel_bytes = assessment.generate_excel_bytes()

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        common_prefix = REPORTS_DIR / _safe_name(account_name) / datetime.now().strftime("%Y-%m-%d")
        common_prefix.mkdir(parents=True, exist_ok=True)

        filename = f"{_safe_name(account_name)}_{timestamp}.xlsx"
        file_path = common_prefix / filename
        file_path.write_bytes(excel_bytes)

        svc_bytes = assessment.generate_service_list_bytes()
        svc_filename = f"{_safe_name(account_name)}_{timestamp}_monitoring.xlsx"
        svc_path = common_prefix / svc_filename
        svc_path.write_bytes(svc_bytes)

        pdf_path = None
        try:
            pdf_bytes = assessment.generate_pdf_bytes(customer_name=account_name)
            pdf_filename = f"{_safe_name(account_name)}_{timestamp}.pdf"
            pdf_path = common_prefix / pdf_filename
            pdf_path.write_bytes(pdf_bytes)
        except Exception as pdf_error:
            print(f"PDF generation failed: {pdf_error}")

        sev = {"CRITICAL": 0, "HIGH": 0}
        for f in assessment.findings:
            if f["Severity"] in sev:
                sev[f["Severity"]] += 1

        s3_bucket = os.environ.get('S3_BUCKET', 'war-zain')
        s3_prefix = os.environ.get('S3_PREFIX', 'assessments')
        s3_region = os.environ.get('AWS_REGION', 'us-east-1')
        s3_access_key = os.environ.get('S3_ACCESS_KEY')
        s3_secret_key = os.environ.get('S3_SECRET_KEY')
        s3_session_token = os.environ.get('S3_SESSION_TOKEN')

        if s3_bucket and s3_access_key and s3_secret_key:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=s3_access_key,
                aws_secret_access_key=s3_secret_key,
                aws_session_token=s3_session_token or None,
                region_name=s3_region,
            )
            s3_folder = f"{s3_prefix}/{_safe_name(account_name)}/{datetime.now().strftime('%Y-%m-%d')}"
            try:
                for local_path, content_type in [
                    (file_path, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
                    (pdf_path, 'application/pdf'),
                    (svc_path, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
                ]:
                    if local_path and Path(local_path).exists():
                        key = f"{s3_folder}/{Path(local_path).name}"
                        s3_client.upload_file(str(local_path), s3_bucket, key, ExtraArgs={'ContentType': content_type})
            except Exception as s3_err:
                print(f"S3 upload failed: {s3_err}")
        else:
            print("S3 upload skipped: S3_ACCESS_KEY and/or S3_SECRET_KEY are not configured")

        db.mark_success(
            scan_id,
            file_path=str(file_path),
            findings_count=len(assessment.findings),
            critical=sev["CRITICAL"],
            high=sev["HIGH"],
            pdf_path=str(pdf_path) if pdf_path else None,
            svc_path=str(svc_path),
        )
    except Exception as e:
        db.mark_failed(scan_id, str(e))
