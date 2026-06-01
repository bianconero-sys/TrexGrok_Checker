# Grok Cookie Validator — Web Edition
**by Trex** · v2.0

A web dashboard for validating Grok.com (xAI) cookies — rebuilt from the CLI
tool `Grok_byTrex.py` with a live GUI, batch processing, and one-click
deploy to Render.com.

---

## Features

| Feature | Description |
|---|---|
| **Single Check** | Paste one Netscape cookie, get instant result |
| **Batch Processing** | Upload `.zip` or multiple `.txt` files, real-time WebSocket progress |
| **Live Results** | Filterable table (Valid / Invalid / CF Block / Error) |
| **Export ZIP** | Download valid cookies organized by tier folder |
| **Proxy Support** | HTTP, SOCKS4, SOCKS5 — one per line, randomly rotated |
| **Preflight Toggle** | Optional GET to `grok.com` before session check |
| **Responsive UI** | Works on desktop and mobile |

---

## Cookie Format

Expects **Netscape tab-delimited** format:

```
.grok.com   TRUE    /   TRUE    0   sso         <value>
.grok.com   TRUE    /   TRUE    0   sso-rw      <value>
.grok.com   TRUE    /   TRUE    0   cf_clearance <value>
```

- Only cookies for `grok.com` and `x.ai` domains are used
- Expired cookies (by unix timestamp) are automatically filtered

---

## Local Development

```bash
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

## Deploy to Render.com

1. Push this folder to a GitHub repo
2. Create a new **Web Service** on [render.com](https://render.com)
3. Connect your repo — Render will auto-detect `render.yaml`
4. Click **Deploy**

The `render.yaml` handles everything: build command, start command, PORT,
and auto-generated `SECRET_KEY`.

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard UI |
| `POST` | `/api/check-single` | JSON: `{cookie, proxies, preflight}` |
| `POST` | `/api/batch` | FormData: files + options, streams via WebSocket |
| `GET` | `/api/results/<sid>` | All results for a session |
| `GET` | `/api/export/<sid>` | Download valid results as ZIP |

---

## Export Structure

```
grok_results.zip
├── free/
│   └── user@example.com+free_0001.txt
└── <tier_name>/
    └── user@example.com+<tier>_0001.txt
```

Each `.txt` contains full account info + raw cookie text.

---

*For educational purposes only.*
