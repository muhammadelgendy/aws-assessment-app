# AWS assessment scanner

Simple web app around your `moo-data.py` scanner: submit AWS creds in a form,
scan runs in the background, download the resulting xlsx report whenever it's ready.

## Setup

```bash
cd app
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Open http://localhost:8000

## How it works

- `scanner_core.py` — your original `moo-data.py`, with one addition: the
  `AWSAssessment` constructor now also accepts raw `aws_access_key_id` /
  `aws_secret_access_key` / `aws_session_token` (in addition to the existing
  `profile_name` path), since the web form submits keys directly. Also fixed
  a bug where `_get_regions()` built an unauthenticated `boto3.Session()`
  instead of using the session with your credentials — this would have made
  every form-submitted scan fail while silently working fine on an EC2
  instance role.
- `runner.py` — runs a scan in a background thread, writes the xlsx to
  `reports/`, and updates SQLite with status/findings counts.
- `database.py` — SQLite (`scans.db`, created automatically) tracking each
  scan: account name, status (running/success/failed), findings counts,
  file path.
- `main.py` — FastAPI routes: `POST /api/scan` to start one, `GET
  /api/reports` polled by the frontend every 4s, `GET
  /api/reports/{id}/download` to fetch the xlsx.
- `static/index.html` — the form + report list, no build step, no framework.

## Notes on credentials

Right now access keys are held in memory only for the duration of the scan
and never written to disk — they're passed straight into `boto3.Session()`.
That's fine for personal/local use. Before letting other people submit
creds to this (i.e. before this leaves your laptop), you'd want:

- HTTPS in front of it (a raw HTTP form posting secret keys is not okay
  over a network)
- Basic auth or login on the app itself
- Rate limiting / a queue (Celery) instead of raw threads, since concurrent
  full-account scans (30 AWS services, up to 40 threads each) can throttle
  each other and exhaust the thread pool

None of that is needed to run this locally against your 14 accounts.

## Known limits of this simple version

- One scan at a time works well; several at once will contend for the
  same `MAX_WORKERS=40` thread ceiling inside `scanner_core.py` — lower it
  if you're going to run scans concurrently.
- No auth on the app itself — anyone with network access to this box can
  submit creds and download reports.
- Reports live in `app/reports/` as plain files. Back them up or move to
  S3 if you want them to survive a redeploy.
