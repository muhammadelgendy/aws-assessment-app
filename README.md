# zaintech_war Deployment

This repository contains a FastAPI backend in `app/` and a static frontend in `app/static/`.

## Netlify deployment

Netlify can host the frontend directly from `app/static`, but the Python backend must run separately.

### What to deploy on Netlify

- Publish directory: `app/static`
- Build command: `echo "No build required"`
- Site name: `zaintech_war`

### API proxy setup

The static frontend uses relative API calls to `/api/*`.
Netlify will proxy those requests to your backend using `netlify.toml`.

Open `netlify.toml` and replace `YOUR_BACKEND_DOMAIN` with your actual backend URL:

```toml
[[redirects]]
  from = "/api/*"
  to = "https://YOUR_BACKEND_DOMAIN/api/:splat"
  status = 200
  force = true
```

### How to use a custom domain

1. Create the site in Netlify.
2. Name it `zaintech_war` in the Netlify dashboard.
3. Add your custom domain in Netlify site settings.
4. Update any DNS records as instructed by Netlify.

### Backend hosting

Your FastAPI backend still needs to be deployed on a Python-friendly host.
Possible options:

- Render
- Fly.io
- Railway
- Heroku
- AWS Elastic Beanstalk
- A VPS or Docker host

The backend must respond to `https://YOUR_BACKEND_DOMAIN/api/scan` and `https://YOUR_BACKEND_DOMAIN/api/reports`.

### Render deployment

This repo includes `render.yaml` for a Render free-plan web service.
Render can run the full app from the root repository, serving the frontend from `app/static` and the API from `app/main.py`.

To deploy on Render:

1. Connect your repository in the Render dashboard.
2. Use the existing `render.yaml` manifest.
3. Render will install dependencies from `app/requirements.txt`.
4. The service starts with:
   `uvicorn app.main:app --host 0.0.0.0 --port ${PORT}`

After deployment, your app should work directly from the Render URL with API routes under `/api/*`.

### Local development

Run the backend locally from `app/`:

```bash
cd app
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Then deploy the static frontend to Netlify.
