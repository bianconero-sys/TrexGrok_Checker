# Grok Cookie Validator — Web Edition (v3.0)

A Flask + Socket.IO web dashboard that validates Grok.com / xAI cookies, classifies
them by subscription tier, and exports results — rebuilt from the original CLI tool
with a modern liquid-glass interface. By Trex.

## Features
- **Dashboard** with 6 live stat cards (Checked, Valid, Invalid, CF Block, Errors,
  Duplicate). **Every card is clickable** and jumps straight to the matching section
  in Live Results.
- **Email deduplication** — repeated valid emails are flagged as `duplicate`, counted
  on their own card, and skipped on export.
- **Single Check** and **Batch Process** (ZIP archive, multiple .txt, or pasted text),
  with live progress over WebSocket.
- **Settings → Export Fields**: per-field on/off toggles control exactly which details
  appear in each exported `.txt` (Email, Tier, Billing Intv, Sub Status, Period End,
  Product ID, Base Plan ID, Purchase Token, User ID, Name, Source File, Validation,
  Reason). The Cookie block is always kept.
- **Smart folder classification on export**: only cookies with an *active* paid sub
  (detected from REST subscription history) go to their tier folder. Inactive,
  cancelled, expired, or no-sub cookies are filtered into `/free/`.
- **Modern liquid-glass UI** — animated wallpaper, glass cards, cursor spotlight,
  clean line icons, and a working **dark / light theme toggle**.
- Proxy support (http / socks4 / socks5), threaded checking (1–50), Cloudflare
  challenge detection.

## Files
- `app.py` — Flask backend + all validation logic
- `dashboard.html` — the UI (loaded by `app.py` at startup)
- `requirements.txt`, `render.yaml`, `runtime.txt`, `python-version`

## Run locally
```bash
pip install -r requirements.txt
python app.py            # http://localhost:5000
```

## Deploy on Render.com
1. Push this folder to a Git repo (keep `app.py` and `dashboard.html` together).
2. On Render: **New → Blueprint**, point it at the repo (`render.yaml` is included).
3. Deploy. `SECRET_KEY` is generated automatically.

> For educational purposes only.
