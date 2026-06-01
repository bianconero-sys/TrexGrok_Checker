# ─────────────────────────────────────────────────────────────────────────────
#  Grok Cookie Validator — Web Edition v2.0
#  Core logic from Grok_byTrex.py | Web layer by Trex
# ─────────────────────────────────────────────────────────────────────────────

from flask import Flask, render_template_string, request, jsonify, Response
from flask_socketio import SocketIO, join_room, leave_room
import threading
import io
import os
import re
import time
import random
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─── App Setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "grok-validator-secret-2025")
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

results_store: Dict[str, List[dict]] = {}
batch_state:   Dict[str, dict]       = {}

# ─── Constants ────────────────────────────────────────────────────────────────

VERSION          = "2.0-web"
SESSION_URL      = "https://grok.com/api/auth/session"
SUBSCRIPTIONS_URL = "https://grok.com/rest/subscriptions"
HOME_URL         = "https://grok.com/"
TIMEOUT          = 25

BROWSER_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
    "Accept":          "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Referer":         "https://grok.com/",
    "Origin":          "https://grok.com",
    "Connection":      "keep-alive",
    "Sec-Fetch-Dest":  "empty",
    "Sec-Fetch-Mode":  "cors",
    "Sec-Fetch-Site":  "same-origin",
    "Priority":        "u=4",
    "Pragma":          "no-cache",
    "Cache-Control":   "no-cache",
}

CHALLENGE_MARKERS = [
    "cf-chl", "cloudflare", "attention required", "captcha",
    "challenge-platform", "just a moment", "checking your browser", "access denied",
]

# ─── Data Model ───────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    source_file:         str
    status:              str   # valid | invalid | cloudflare_blocked | error
    reason:              str
    email:               Optional[str] = None
    name:                Optional[str] = None
    user_id:             Optional[str] = None
    tier:                Optional[str] = None
    billing_interval:    Optional[str] = None
    subscription_status: Optional[str] = None
    billing_period_end:  Optional[str] = None
    base_plan_id:        Optional[str] = None
    product_id:          Optional[str] = None
    purchase_token:      Optional[str] = None
    cookie_text:         str           = ""

    def to_dict(self) -> dict:
        tier_disp = self._tier_display()
        return {
            "source_file":         self.source_file,
            "status":              self.status,
            "reason":              self.reason,
            "email":               self.email               or "",
            "name":                self.name                or "",
            "user_id":             self.user_id             or "",
            "tier":                self.tier                or "",
            "tier_display":        tier_disp,
            "billing_interval":    self.billing_interval    or "",
            "subscription_status": self.subscription_status or "",
            "billing_period_end":  self.billing_period_end  or "",
            "base_plan_id":        self.base_plan_id        or "",
            "product_id":          self.product_id          or "",
            "purchase_token":      self.purchase_token      or "",
            "cookie":              self.cookie_text,
        }

    def _tier_display(self) -> str:
        t = normalize_tier_name(self.tier)
        if t == "free":
            return "Free"
        return (self.tier or t).replace("_", " ").title()

# ─── Cookie Parsing ───────────────────────────────────────────────────────────

def parse_netscape_cookies_with_text(text: str) -> Tuple[Dict[str, str], str]:
    cookies: Dict[str, str] = {}
    kept_lines: List[str] = []
    for raw in text.splitlines():
        line    = raw.rstrip("\r\n")
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if stripped.startswith("#HttpOnly_") or stripped.startswith("# Netscape"):
                kept_lines.append(line)
            continue
        parts = stripped.split("\t")
        if len(parts) != 7:
            continue
        domain, _flag, _path, _secure, expires, name, value = parts
        try:
            if expires != "0" and float(expires) < time.time():
                continue
        except ValueError:
            pass
        if "grok.com" in domain or "x.ai" in domain:
            cookies[name] = value
            kept_lines.append(line)
    return cookies, "\n".join(kept_lines).strip()


def cookie_sets_from_text(text: str, filename: str) -> List[Tuple[str, Dict[str, str], str]]:
    cookies, cookie_text = parse_netscape_cookies_with_text(text)
    return [(filename, cookies, cookie_text)] if cookies else []


def cookie_sets_from_zip(data: bytes) -> List[Tuple[str, Dict[str, str], str]]:
    results = []
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".txt"):
                    continue
                with zf.open(info) as f:
                    text = f.read().decode("utf-8", errors="ignore")
                cookies, cookie_text = parse_netscape_cookies_with_text(text)
                if cookies:
                    results.append((info.filename, cookies, cookie_text))
    except Exception:
        pass
    return results

# ─── HTTP Utilities ───────────────────────────────────────────────────────────

def make_session(cookies: Dict[str, str], proxy: Optional[str]) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=2, connect=2, read=2, backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    session.mount("https://", adapter)
    session.headers.update(BROWSER_HEADERS)
    for name, value in cookies.items():
        for domain in (".grok.com", "grok.com", ".x.ai", "x.ai"):
            try:
                session.cookies.set(name, value, domain=domain)
            except Exception:
                pass
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


def looks_like_challenge(resp: requests.Response, text: str) -> bool:
    hay          = (text or "")[:4000].lower()
    headers_text = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
    if resp.status_code in (403, 429, 503):
        return True
    if any(m in hay for m in CHALLENGE_MARKERS):
        return True
    if any(m in headers_text for m in ["cf-ray", "cloudflare"]):
        ctype = resp.headers.get("content-type", "").lower()
        if "text/html" in ctype and any(x in hay for x in ["just a moment", "attention required", "challenge"]):
            return True
    return False


def preflight(session: requests.Session) -> None:
    try:
        session.get(HOME_URL, timeout=TIMEOUT, allow_redirects=True)
        time.sleep(random.uniform(0.15, 0.45))
    except Exception:
        pass


def first_non_empty(*values: Any) -> Optional[str]:
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return None

# ─── Subscription Logic ───────────────────────────────────────────────────────

def parse_subscriptions_payload(data: Any) -> Dict[str, Optional[str]]:
    items = []
    if isinstance(data, dict):
        if isinstance(data.get("subscriptions"), list):
            items = data["subscriptions"]
        elif isinstance(data.get("subscription"), dict):
            items = [data["subscription"]]
        elif all(k in data for k in ["tier", "status"]):
            items = [data]
    elif isinstance(data, list):
        items = data
    if not items:
        return {}
    sub    = items[0] if isinstance(items[0], dict) else {}
    google = sub.get("google") if isinstance(sub.get("google"), dict) else {}
    return {
        "tier":                first_non_empty(sub.get("tier")),
        "billing_interval":    first_non_empty(sub.get("billingInterval")),
        "subscription_status": first_non_empty(sub.get("status")),
        "billing_period_end":  first_non_empty(
            sub.get("billingPeriodEnd"), sub.get("expiryTime"), google.get("expiryTime")
        ),
        "base_plan_id":   first_non_empty(sub.get("basePlanId"),    google.get("basePlanId")),
        "product_id":     first_non_empty(sub.get("productId"),     google.get("productId")),
        "purchase_token": first_non_empty(sub.get("purchaseToken"), google.get("purchaseToken")),
        "user_id":        first_non_empty(sub.get("xaiUserId"),     sub.get("userId")),
    }


def probe_subscription(session: requests.Session) -> Tuple[Dict[str, Optional[str]], str]:
    try:
        resp = session.get(SUBSCRIPTIONS_URL, timeout=TIMEOUT, allow_redirects=True)
        text = resp.text or ""
        if looks_like_challenge(resp, text):
            return {}, "subscription_challenge"
        if resp.status_code != 200:
            return {}, f"subscription_http_{resp.status_code}"
        try:
            data = resp.json()
        except Exception:
            return {}, "subscription_json_error"
        parsed = parse_subscriptions_payload(data)
        return (parsed, "rest_subscriptions") if parsed else ({}, "subscription_empty")
    except Exception as e:
        return {}, f"subscription_error:{type(e).__name__}"


def normalize_tier_name(tier: Optional[str]) -> str:
    if not tier or not str(tier).strip():
        return "free"
    raw    = str(tier).strip()
    lowered = raw.lower()
    if lowered in {"free", "none", "basic", "subscription_tier_free", "free_tier"} or "free" in lowered:
        return "free"
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw).strip("._-")
    return safe or "free"

# ─── Core Validation ──────────────────────────────────────────────────────────

def validate_one(
    source_file: str,
    cookies:     Dict[str, str],
    cookie_text: str,
    proxy:       Optional[str],
    do_preflight: bool,
) -> ValidationResult:
    session = make_session(cookies, proxy)
    try:
        if do_preflight:
            preflight(session)

        resp = session.get(SESSION_URL, timeout=TIMEOUT, allow_redirects=True)
        text = resp.text or ""

        if looks_like_challenge(resp, text):
            return ValidationResult(source_file=source_file, status="cloudflare_blocked",
                                    reason="challenge_detected", cookie_text=cookie_text)

        data  = None
        ctype = resp.headers.get("content-type", "").lower()
        if "application/json" in ctype or text.strip().startswith("{"):
            try:
                data = resp.json()
            except Exception:
                data = None

        if resp.status_code == 200 and isinstance(data, dict):
            status  = str(data.get("status", "")).lower()
            email   = data.get("email")
            user_id = data.get("userId") or data.get("xUserId") or data.get("id")
            given   = (data.get("givenName")  or "").strip()
            family  = (data.get("familyName") or "").strip()
            name    = f"{given} {family}".strip() or None

            if status == "authenticated" or user_id or email:
                sub, sub_reason = probe_subscription(session)
                return ValidationResult(
                    source_file=source_file, status="valid", reason=sub_reason,
                    email=email, name=name,
                    user_id=first_non_empty(sub.get("user_id"), user_id),
                    tier=first_non_empty(sub.get("tier"), "free"),
                    billing_interval=sub.get("billing_interval"),
                    subscription_status=sub.get("subscription_status"),
                    billing_period_end=sub.get("billing_period_end"),
                    base_plan_id=sub.get("base_plan_id"),
                    product_id=sub.get("product_id"),
                    purchase_token=sub.get("purchase_token"),
                    cookie_text=cookie_text,
                )
            return ValidationResult(source_file=source_file, status="invalid",
                                    reason="unauthenticated_json", cookie_text=cookie_text)

        if resp.status_code in (401, 440):
            return ValidationResult(source_file=source_file, status="invalid",
                                    reason="unauthorized", cookie_text=cookie_text)
        return ValidationResult(source_file=source_file, status="error",
                                reason=f"unexpected_http_{resp.status_code}", cookie_text=cookie_text)

    except requests.exceptions.ProxyError:
        return ValidationResult(source_file=source_file, status="error", reason="proxy_error", cookie_text=cookie_text)
    except requests.exceptions.ConnectTimeout:
        return ValidationResult(source_file=source_file, status="error", reason="connect_timeout", cookie_text=cookie_text)
    except requests.exceptions.ReadTimeout:
        return ValidationResult(source_file=source_file, status="error", reason="read_timeout", cookie_text=cookie_text)
    except requests.exceptions.SSLError:
        return ValidationResult(source_file=source_file, status="error", reason="ssl_error", cookie_text=cookie_text)
    except requests.exceptions.RequestException as e:
        return ValidationResult(source_file=source_file, status="error",
                                reason=f"request_error:{type(e).__name__}", cookie_text=cookie_text)
    except Exception as e:
        return ValidationResult(source_file=source_file, status="error",
                                reason=f"exception:{type(e).__name__}", cookie_text=cookie_text)

# ─── Proxy Parsing ────────────────────────────────────────────────────────────

def parse_proxy_line(line: str) -> Optional[str]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = re.sub(r'^([a-zA-Z][a-zA-Z0-9+.-]*):/+', r'\1://', line)
    if re.match(r'^(https?|socks[45]h?|socks4a?)://', line, re.IGNORECASE):
        return line
    m = re.match(r'^([^:@\s]+):([^@\s]+)@([\w.\-\[\]]+):(\d+)$', line)
    if m:
        return f"http://{m.group(1)}:{m.group(2)}@{m.group(3)}:{m.group(4)}"
    m = re.match(r'^([\w.\-\[\]]+):(\d+)@([^:@\s]+):([^@\s]+)$', line)
    if m:
        return f"http://{m.group(3)}:{m.group(4)}@{m.group(1)}:{m.group(2)}"
    m = re.match(r'^([\w.\-\[\]]+):(\d+)$', line)
    if m:
        return f"http://{m.group(1)}:{m.group(2)}"
    parts = line.split(":")
    if len(parts) == 4:
        a, b, c, d = parts
        if b.isdigit() and not d.isdigit():
            return f"http://{c}:{d}@{a}:{b}"
        if d.isdigit() and not b.isdigit():
            return f"http://{a}:{b}@{c}:{d}"
    return None


def parse_proxies(text: str) -> List[str]:
    return [p for line in text.splitlines() if (p := parse_proxy_line(line))]

# ─── Batch Worker ─────────────────────────────────────────────────────────────

def process_batch(
    sid:         str,
    cookie_sets: List[Tuple[str, Dict[str, str], str]],
    proxies:     List[str],
    num_threads: int,
    do_preflight: bool,
) -> None:
    total  = len(cookie_sets)
    counts = {"valid": 0, "invalid": 0, "cloudflare_blocked": 0, "error": 0}
    tiers: Dict[str, int] = {}
    lock  = threading.Lock()
    queue = list(cookie_sets)
    ql    = threading.Lock()
    proc  = [0]

    def worker():
        while True:
            with ql:
                if not queue:
                    return
                if not batch_state.get(sid, {}).get("running", True):
                    return
                src, cks, ctxt = queue.pop(0)
            if not batch_state.get(sid, {}).get("running", True):
                return

            proxy  = random.choice(proxies) if proxies else None
            result = validate_one(src, cks, ctxt, proxy, do_preflight)

            if not batch_state.get(sid, {}).get("running", True):
                return

            with lock:
                proc[0] += 1
                counts[result.status] = counts.get(result.status, 0) + 1
                if result.status == "valid":
                    t = normalize_tier_name(result.tier)
                    tiers[t] = tiers.get(t, 0) + 1

                row = result.to_dict()
                row["idx"] = proc[0]
                results_store.setdefault(sid, []).append(row)
                socketio.emit("result_row", row, room=sid)
                socketio.emit("counts", {
                    **counts, "tiers": tiers,
                    "total": total, "processed": proc[0],
                }, room=sid)

    threads = [
        threading.Thread(target=worker, daemon=True)
        for _ in range(min(num_threads, total, 50))
    ]
    for t in threads: t.start()
    for t in threads: t.join()

    batch_state[sid] = {"running": False}
    socketio.emit("batch_done", {
        **counts, "tiers": tiers,
        "total": total, "processed": proc[0],
    }, room=sid)

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(DASHBOARD)


@app.route("/api/check-single", methods=["POST"])
def check_single():
    b = (request.get_json(silent=True) or {}) if request.is_json else request.form
    cookie_text  = (b.get("cookie", "") or "").strip()
    proxies_text = (b.get("proxies", "") or "").strip()
    do_preflight = str(b.get("preflight", "true")).lower() not in ("false", "0", "no")

    if not cookie_text:
        return jsonify({"status": "error", "message": "No cookie provided"})

    cookies, cookie_clean = parse_netscape_cookies_with_text(cookie_text)
    if not cookies:
        return jsonify({"status": "error",
                        "message": "Could not parse cookie — use Netscape tab-delimited format"})

    proxies = parse_proxies(proxies_text) if proxies_text else []
    proxy   = random.choice(proxies) if proxies else None
    result  = validate_one("single", cookies, cookie_clean, proxy, do_preflight)
    return jsonify(result.to_dict())


@app.route("/api/batch", methods=["POST"])
def start_batch():
    sid = request.form.get("sid", "")
    if not sid:
        return jsonify({"error": "No session id"})
    if batch_state.get(sid, {}).get("running"):
        return jsonify({"error": "Batch already running"})

    num_threads  = min(max(int(request.form.get("threads", 10)), 1), 50)
    do_preflight = request.form.get("preflight", "true").lower() not in ("false", "0", "no")
    proxies_text = request.form.get("proxies", "")
    proxies      = parse_proxies(proxies_text) if proxies_text.strip() else []

    cookie_sets: List[Tuple[str, Dict[str, str], str]] = []

    for f in request.files.getlist("cookies"):
        fname = f.filename or "file"
        try:
            f.seek(0)
            raw = f.read()
            if fname.lower().endswith(".zip"):
                cookie_sets.extend(cookie_sets_from_zip(raw))
            else:
                cookie_sets.extend(cookie_sets_from_text(raw.decode("utf-8", "replace"), fname))
        except Exception as e:
            app.logger.error("File error %s: %s", fname, e)

    paste = (request.form.get("paste_text", "") or "").strip()
    if paste:
        for i, block in enumerate(re.split(r'\n-{3,}\n', paste)):
            if block.strip():
                cookie_sets.extend(cookie_sets_from_text(block.strip(), f"paste_{i+1}.txt"))

    if not cookie_sets:
        return jsonify({"error": "No valid Grok cookie sets found"})

    results_store[sid] = []
    batch_state[sid]   = {"running": True}
    threading.Thread(
        target=process_batch,
        args=(sid, cookie_sets, proxies, num_threads, do_preflight),
        daemon=True,
    ).start()
    return jsonify({"started": True, "total": len(cookie_sets)})


@app.route("/api/results/<sid>")
def get_results(sid):
    return jsonify(results_store.get(sid, []))


@app.route("/api/export/<sid>")
def export_zip(sid):
    results = results_store.get(sid, [])
    if not results:
        return Response("No results.", mimetype="text/plain")

    buf      = io.BytesIO()
    counters: Dict[str, int] = {}

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in results:
            if r.get("status") != "valid":
                continue
            tier_folder = normalize_tier_name(r.get("tier"))
            counters[tier_folder] = counters.get(tier_folder, 0) + 1
            n = counters[tier_folder]

            email_safe = re.sub(r"[^a-zA-Z0-9._-]+", "_",
                                r.get("email") or r.get("user_id") or "unknown").strip("._-") or "unknown"
            tier_safe  = re.sub(r"[^a-zA-Z0-9._-]+", "_", tier_folder).strip("._-") or "free"

            lines = [
                f"Email          : {r.get('email', '')}",
                f"Tier           : {r.get('tier', '')}",
                f"Billing Intv   : {r.get('billing_interval', '')}",
                f"Sub Status     : {r.get('subscription_status', '')}",
                f"Period End     : {r.get('billing_period_end', '')}",
                f"Product ID     : {r.get('product_id', '')}",
                f"Base Plan ID   : {r.get('base_plan_id', '')}",
                f"Purchase Token : {r.get('purchase_token', '')}",
                f"User ID        : {r.get('user_id', '')}",
                f"Name           : {r.get('name', '')}",
                f"Source File    : {r.get('source_file', '')}",
                f"Validation     : {r.get('status', '')}",
                f"Reason         : {r.get('reason', '')}",
                "",
                "--------------------",
                "Cookie:",
                r.get("cookie", ""),
            ]
            zf.writestr(f"{tier_folder}/{email_safe}+{tier_safe}_{n:04d}.txt", "\n".join(lines))

    buf.seek(0)
    return Response(
        buf.read(), mimetype="application/zip",
        headers={"Content-Disposition": "attachment; filename=grok_results.zip"},
    )


@socketio.on("join")
def on_join(data):
    sid = data.get("sid", "")
    if sid: join_room(sid)

@socketio.on("leave")
def on_leave(data):
    sid = data.get("sid", "")
    if sid: leave_room(sid)

@socketio.on("stop_batch")
def on_stop(data):
    sid = data.get("sid", "")
    if sid and sid in batch_state:
        batch_state[sid]["running"] = False

# ─── Dashboard HTML ───────────────────────────────────────────────────────────

DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>Grok Validator · by Trex</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
<style>
:root {
  --bg:   #060810;
  --bg1:  #09091a;
  --bg2:  #0d1020;
  --bg3:  #121628;
  --blue: #3b82f6;
  --blu2: #60a5fa;
  --teal: #14f5c0;
  --teal-d:#0ec99b;
  --text: #c8d6f0;
  --tdim: #374a68;
  --tmid: #7a90b8;
  --bdr:  #1a2240;
  --bdr2: #233060;
  --red:    #f87171;
  --yellow: #fbbf24;
  --orange: #fb923c;
  --purple: #a78bfa;
  --cyan:   #22d3ee;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:'Syne',sans-serif;font-size:15px;display:flex}

::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg1)}
::-webkit-scrollbar-thumb{background:var(--bdr2);border-radius:3px}

/* ── Sidebar ─────────────────────────────────────────────── */
.sb{width:220px;min-width:220px;background:var(--bg1);border-right:1px solid var(--bdr);
    display:flex;flex-direction:column;position:relative;z-index:10;flex-shrink:0}
.sb::after{content:'';position:absolute;top:0;right:0;bottom:0;width:1px;
    background:linear-gradient(180deg,transparent,var(--blue) 50%,var(--teal) 80%,transparent);opacity:.35}

.logo{padding:20px 20px 16px;border-bottom:1px solid var(--bdr)}
.logo-mark{display:flex;align-items:center;gap:11px;margin-bottom:6px}
.logo-icon{width:34px;height:34px;flex-shrink:0}
.logo-name{display:flex;flex-direction:column}
.logo-t{font-size:13px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;
    background:linear-gradient(90deg,var(--blu2),var(--teal));-webkit-background-clip:text;
    -webkit-text-fill-color:transparent;background-clip:text;line-height:1.1;white-space:nowrap}
.logo-s{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--tdim);margin-top:3px}
.logo-ver{display:inline-block;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.3);
    color:var(--blu2);font-family:'JetBrains Mono',monospace;font-size:10px;padding:2px 7px;
    border-radius:3px;margin-top:7px}

.nav{flex:1;padding:12px 0;overflow-y:auto}
.ni{display:flex;align-items:center;gap:10px;padding:11px 20px;cursor:pointer;
    color:var(--tdim);font-size:13px;font-weight:600;letter-spacing:.04em;
    transition:all .15s;position:relative;user-select:none;-webkit-tap-highlight-color:transparent}
.ni:hover{color:var(--text);background:rgba(255,255,255,.03)}
.ni.active{color:var(--teal);background:rgba(20,245,192,.06)}
.ni.active::before{content:'';position:absolute;left:0;top:5px;bottom:5px;width:3px;
    background:var(--teal);border-radius:0 3px 3px 0;box-shadow:0 0 10px var(--teal)}
.ni-ic{font-size:14px;width:18px;text-align:center;flex-shrink:0}

.sb-foot{padding:14px 20px;border-top:1px solid var(--bdr);font-family:'JetBrains Mono',monospace;
    font-size:10px;color:var(--tdim);line-height:1.9}
.dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--teal);
    box-shadow:0 0 6px var(--teal);animation:pulse 2s infinite;margin-right:5px;vertical-align:middle}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}

/* ── Main ────────────────────────────────────────────────── */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}

.topbar{display:flex;align-items:center;padding:0 24px;height:50px;border-bottom:1px solid var(--bdr);
    background:var(--bg1);gap:12px;flex-shrink:0;position:relative;z-index:20}
.topbar::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
    background:linear-gradient(90deg,transparent,var(--blue) 40%,var(--teal) 70%,transparent);opacity:.4}
.tb-title{font-size:16px;font-weight:700;color:var(--text);letter-spacing:.03em}
.tb-sub{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--tdim);margin-left:auto}

.hbg{display:none;background:none;border:none;cursor:pointer;padding:8px 10px;
    flex-direction:column;gap:5px;touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.hbg span{display:block;width:20px;height:2px;background:var(--blu2);border-radius:2px}
.mob-ov{display:none;position:fixed;inset:0;z-index:900;backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}
.mob-ov.on{display:block;background:rgba(0,0,0,.6)}

.content{flex:1;overflow-y:auto;padding:22px 24px}
.page{display:none}.page.active{display:block}

/* ── Cards ───────────────────────────────────────────────── */
.card{background:var(--bg2);border:1px solid var(--bdr);border-radius:10px;padding:20px;margin-bottom:14px}
.ct{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;color:var(--blu2);
    letter-spacing:.1em;text-transform:uppercase;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.ctd{width:5px;height:5px;background:var(--blue);border-radius:50%;box-shadow:0 0 6px var(--blue)}

/* ── Forms ───────────────────────────────────────────────── */
label{display:block;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;
    color:var(--tdim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:7px}
textarea,input[type=text],input[type=number],select{
    background:var(--bg);border:1px solid var(--bdr2);border-radius:7px;
    color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px;
    padding:10px 13px;width:100%;outline:none;transition:border-color .2s,box-shadow .2s;resize:vertical}
textarea:focus,input:focus,select:focus{border-color:var(--blue);box-shadow:0 0 0 2px rgba(59,130,246,.1)}
textarea{min-height:150px}
select{appearance:none;cursor:pointer;padding-right:34px;
    background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%234a6080' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
    background-repeat:no-repeat;background-position:right 12px center}

/* ── Buttons ─────────────────────────────────────────────── */
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;border-radius:7px;
    border:none;cursor:pointer;font-family:'Syne',sans-serif;font-size:13px;font-weight:700;
    letter-spacing:.06em;text-transform:uppercase;transition:all .15s;outline:none;
    touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.btn:active{transform:scale(.97)}
.btn-p{background:linear-gradient(135deg,var(--blue),var(--teal));color:#000;
    box-shadow:0 0 20px rgba(59,130,246,.2)}
.btn-p:hover{box-shadow:0 0 28px rgba(20,245,192,.3)}
.btn-g{background:transparent;border:1px solid var(--bdr2);color:var(--tmid)}
.btn-g:hover{border-color:var(--bdr2);color:var(--text);background:rgba(255,255,255,.03)}
.btn-d{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);color:var(--red)}
.btn-d:hover{background:rgba(248,113,113,.18)}
.btn-full{width:100%;justify-content:center;padding:13px;font-size:14px}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none}

/* ── Stats ───────────────────────────────────────────────── */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:16px}
.sc{background:var(--bg2);border:1px solid var(--bdr);border-radius:9px;padding:14px 10px;text-align:center}
.sv{font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;line-height:1;margin-bottom:5px}
.sl{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;letter-spacing:.08em;
    text-transform:uppercase;color:var(--tdim)}
.sc-chk .sv{color:var(--yellow)}
.sc-val .sv{color:var(--teal);text-shadow:0 0 14px rgba(20,245,192,.4)}
.sc-inv .sv{color:var(--red)}
.sc-cf  .sv{color:var(--orange)}
.sc-err .sv{color:var(--purple)}

/* ── Progress ────────────────────────────────────────────── */
.prog-wrap{background:var(--bg);border:1px solid var(--bdr);border-radius:6px;height:6px;overflow:hidden;margin:10px 0}
.prog-bar{height:100%;background:linear-gradient(90deg,var(--blue),var(--teal));border-radius:6px;
    transition:width .4s;box-shadow:0 0 10px rgba(20,245,192,.4);width:0}
.prog-txt{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--tdim);margin-bottom:14px}

/* ── Drop Zone ───────────────────────────────────────────── */
.dz{border:2px dashed var(--bdr2);border-radius:8px;padding:28px;text-align:center;
    cursor:pointer;transition:all .2s;position:relative}
.dz:hover,.dz.over{border-color:var(--blue);background:rgba(59,130,246,.04)}
.dz input[type=file]{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer}
.dz-ic{font-size:28px;margin-bottom:9px}
.dz-tx{font-size:13px;color:var(--tmid)}
.dz-hi{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--tdim);margin-top:5px}
.fchip{display:inline-flex;align-items:center;gap:5px;background:rgba(59,130,246,.1);
    border:1px solid rgba(59,130,246,.25);color:var(--blu2);padding:3px 9px;border-radius:4px;
    font-family:'JetBrains Mono',monospace;font-size:11px;margin:3px}
.flist{margin-top:10px}

/* ── Tabs ────────────────────────────────────────────────── */
.tbar{display:flex;border-bottom:1px solid var(--bdr);margin-bottom:16px}
.tab{padding:8px 18px;font-size:12px;font-weight:700;letter-spacing:.05em;color:var(--tdim);
    cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;
    touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.tab:hover{color:var(--text)}.tab.active{color:var(--teal);border-bottom-color:var(--teal)}
.tc{display:none}.tc.active{display:block}

/* ── Toggle ──────────────────────────────────────────────── */
.trow{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--bdr)}
.trow:last-child{border-bottom:none}
.tlbl{font-size:13px;color:var(--tmid);font-weight:600}
.tlbl small{display:block;font-size:11px;color:var(--tdim);font-weight:400;margin-top:2px;
    font-family:'JetBrains Mono',monospace}
.tgl{position:relative;width:38px;height:20px;display:inline-block;flex-shrink:0}
.tgl input{opacity:0;width:0;height:0}
.tsldr{position:absolute;inset:0;background:var(--bg);border:1px solid var(--bdr2);
    border-radius:10px;cursor:pointer;transition:.2s}
.tsldr::before{content:'';position:absolute;left:3px;top:3px;width:12px;height:12px;
    background:var(--tdim);border-radius:50%;transition:.2s}
.tgl input:checked+.tsldr{background:rgba(20,245,192,.12);border-color:var(--teal-d)}
.tgl input:checked+.tsldr::before{transform:translateX(18px);background:var(--teal);box-shadow:0 0 6px var(--teal)}

/* ── Single Result ───────────────────────────────────────── */
.rbanner{display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:7px;
    margin-bottom:14px;font-size:14px;font-weight:700;letter-spacing:.06em}
.r-valid{background:rgba(20,245,192,.08);border:1px solid rgba(20,245,192,.25);color:var(--teal)}
.r-invalid{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.25);color:var(--red)}
.r-cf{background:rgba(251,146,60,.08);border:1px solid rgba(251,146,60,.25);color:var(--orange)}
.r-error{background:rgba(167,139,250,.08);border:1px solid rgba(167,139,250,.25);color:var(--purple)}
.rrow{display:flex;gap:10px;align-items:baseline;padding:4px 0;border-bottom:1px solid rgba(26,34,64,.5)}
.rrow:last-child{border-bottom:none}
.rk{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--tdim);width:140px;flex-shrink:0;text-transform:uppercase}
.rv{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text);word-break:break-all}
.sbtns{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}

/* ── Filter Bar ──────────────────────────────────────────── */
.fbar{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.fb{padding:5px 13px;border-radius:5px;border:1px solid var(--bdr2);background:transparent;
    color:var(--tdim);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:11px;
    font-weight:700;letter-spacing:.06em;text-transform:uppercase;transition:all .15s;
    touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.fb:hover{border-color:var(--tmid);color:var(--text)}
.fb.active{border-color:var(--teal);color:var(--teal);background:rgba(20,245,192,.07)}

/* ── Table ───────────────────────────────────────────────── */
.twrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
thead th{background:var(--bg1);color:var(--tdim);font-family:'JetBrains Mono',monospace;
    font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
    padding:10px 12px;text-align:left;border-bottom:1px solid var(--bdr);white-space:nowrap}
tbody tr{border-bottom:1px solid rgba(26,34,64,.4);transition:background .1s}
tbody tr:hover{background:rgba(59,130,246,.03)}
tbody td{padding:9px 12px;font-family:'JetBrains Mono',monospace;color:var(--tmid);
    white-space:nowrap;max-width:180px;overflow:hidden;text-overflow:ellipsis}

.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;
    font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.bv{background:rgba(20,245,192,.1);color:var(--teal);border:1px solid rgba(20,245,192,.25)}
.bi{background:rgba(248,113,113,.1);color:var(--red);border:1px solid rgba(248,113,113,.25)}
.bc{background:rgba(251,146,60,.1);color:var(--orange);border:1px solid rgba(251,146,60,.25)}
.be{background:rgba(167,139,250,.1);color:var(--purple);border:1px solid rgba(167,139,250,.25)}

.empty{text-align:center;padding:50px 20px;color:var(--tdim)}
.eic{font-size:32px;margin-bottom:10px}
.etx{font-family:'JetBrains Mono',monospace;font-size:12px}

.ab{padding:4px 10px;border-radius:4px;border:1px solid var(--bdr2);background:transparent;
    color:var(--tdim);cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:11px;
    transition:all .15s;touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.ab:hover{border-color:var(--blue);color:var(--blu2)}

/* ── Tier Grid ───────────────────────────────────────────── */
.tgrid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}
.tprow{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;
    background:var(--bg);border:1px solid var(--bdr);border-radius:6px}
.tpname{font-size:12px;color:var(--tmid);font-family:'JetBrains Mono',monospace;text-transform:capitalize}
.tpcnt{font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--teal);font-weight:700}

/* ── Grid Options ────────────────────────────────────────── */
.orow{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}

/* ── Spinner ─────────────────────────────────────────────── */
.spin{width:14px;height:14px;border:2px solid rgba(20,245,192,.2);border-top-color:var(--teal);
    border-radius:50%;animation:sp .7s linear infinite;display:none}
@keyframes sp{to{transform:rotate(360deg)}}

/* ── Toast ───────────────────────────────────────────────── */
.tc-wrap{position:fixed;bottom:20px;right:20px;display:flex;flex-direction:column;
    gap:8px;z-index:9999;pointer-events:none}
.toast{background:var(--bg2);border:1px solid var(--bdr2);border-radius:7px;padding:9px 15px;
    font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text);
    box-shadow:0 4px 20px rgba(0,0,0,.5);animation:tin .2s ease,tout .3s ease 2.7s forwards;pointer-events:none}
.toast.ok{border-color:rgba(20,245,192,.35);color:var(--teal)}
.toast.err{border-color:rgba(248,113,113,.35);color:var(--red)}
@keyframes tin{from{transform:translateX(30px);opacity:0}to{transform:none;opacity:1}}
@keyframes tout{to{opacity:0;transform:translateX(10px)}}

/* ── Responsive ──────────────────────────────────────────── */
@media(max-width:768px){
  .hbg{display:flex}
  .sb{position:fixed;top:0;left:0;bottom:0;width:235px;z-index:999;
    transform:translateX(-100%);visibility:hidden;pointer-events:none;
    transition:transform .28s cubic-bezier(.4,0,.2,1),visibility .28s,box-shadow .28s}
  .sb.open{transform:translateX(0);visibility:visible;pointer-events:auto;box-shadow:4px 0 40px rgba(0,0,0,.7)}
  .topbar{padding:0 10px}.tb-sub{display:none}
  .content{padding:14px 12px}
  .stats{grid-template-columns:repeat(3,1fr);gap:8px}
  .sv{font-size:20px}.sc{padding:12px 6px}
  .orow{grid-template-columns:1fr;gap:10px}
  .tgrid{grid-template-columns:1fr}
  thead th:nth-child(2),tbody td:nth-child(2){display:none}
  thead th:nth-child(7),tbody td:nth-child(7){display:none}
  .btn-full{font-size:13px;padding:12px}
}
@media(max-width:480px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .fb{font-size:10px;padding:4px 9px}
  .sc-cf{grid-column:span 2}
}
</style>
</head>
<body>

<!-- Sidebar -->
<nav class="sb" id="sidebar">
  <div class="logo">
    <div class="logo-mark">
      <svg class="logo-icon" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="40" height="40" rx="10" fill="#09091a"/>
        <path d="M12 14h7l-4 12h4M20 14l8 0M24 20h-4" stroke="#14f5c0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <circle cx="32" cy="14" r="2.5" fill="#3b82f6"/>
      </svg>
      <div class="logo-name">
        <span class="logo-t">Grok Validator</span>
        <span class="logo-s">by Trex</span>
      </div>
    </div>
    <span class="logo-ver">v2.0 WEB</span>
  </div>
  <div class="nav">
    <div class="ni active" data-page="single"><span class="ni-ic">📋</span>Single Check</div>
    <div class="ni"        data-page="batch"> <span class="ni-ic">⚡</span>Batch Process</div>
    <div class="ni"        data-page="results"><span class="ni-ic">📊</span>Live Results</div>
    <div class="ni"        data-page="settings"><span class="ni-ic">⚙</span>Settings</div>
  </div>
  <div class="sb-foot">
    <div><span class="dot"></span>Connected</div>
    <div style="margin-top:3px">For educational purposes only.</div>
    <div style="margin-top:2px">Session: <span id="sid-lbl" style="color:var(--blu2)">-</span></div>
  </div>
</nav>

<div class="mob-ov" id="mob-ov" style="display:none"></div>

<div class="main">
  <div class="topbar">
    <button class="hbg" id="hbg" aria-label="Menu">
      <span></span><span></span><span></span>
    </button>
    <div class="tb-title" id="pg-title">Single Cookie Check</div>
    <div class="tb-sub" id="tb-sub">Grok Cookie Validator · by Trex</div>
  </div>

  <div class="content">

    <!-- ── PAGE: SINGLE ──────────────────────────────────────── -->
    <div class="page active" id="page-single">
      <div class="card">
        <div class="ct"><div class="ctd"></div>Cookie Input</div>
        <label>Paste Netscape Cookie (tab-delimited format)</label>
        <textarea id="sc-input" style="min-height:180px"
          placeholder=".grok.com&#9;TRUE&#9;/&#9;TRUE&#9;0&#9;sso&#9;...&#10;.grok.com&#9;TRUE&#9;/&#9;TRUE&#9;0&#9;sso-rw&#9;...&#10;&#10;Drag &amp; drop a .txt file here, or click 'Load File'"></textarea>
        <div style="display:flex;gap:9px;margin-top:12px">
          <button class="btn btn-g" onclick="document.getElementById('sc-file').click()">⬆ Load File</button>
          <input type="file" id="sc-file" accept=".txt" style="display:none">
          <button class="btn btn-g" onclick="document.getElementById('sc-input').value=''">🗑 Clear</button>
        </div>
      </div>

      <div class="card">
        <div class="ct"><div class="ctd"></div>Run Check</div>
        <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px">
          <label style="margin:0;white-space:nowrap">Preflight GET</label>
          <label class="tgl" style="margin:0">
            <input type="checkbox" id="sc-preflight" checked>
            <span class="tsldr"></span>
          </label>
          <span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--tdim)">
            visit grok.com before session check
          </span>
        </div>
        <button class="btn btn-p btn-full" id="sc-btn">
          <div class="spin" id="sc-spin"></div>
          <span id="sc-btntxt">✓ Check Cookie</span>
        </button>
      </div>

      <div class="card" id="sc-result-card" style="display:none">
        <div class="ct"><div class="ctd"></div>Result</div>
        <div id="sc-result"></div>
      </div>
    </div>

    <!-- ── PAGE: BATCH ───────────────────────────────────────── -->
    <div class="page" id="page-batch">
      <div class="stats">
        <div class="sc sc-chk"><div class="sv" id="b-chk">0</div><div class="sl">Checked</div></div>
        <div class="sc sc-val"><div class="sv" id="b-val">0</div><div class="sl">Valid ↗</div></div>
        <div class="sc sc-inv"><div class="sv" id="b-inv">0</div><div class="sl">Invalid</div></div>
        <div class="sc sc-cf" ><div class="sv" id="b-cf" >0</div><div class="sl">CF Block</div></div>
        <div class="sc sc-err"><div class="sv" id="b-err">0</div><div class="sl">Errors</div></div>
      </div>

      <div id="prog-wrap" class="prog-wrap" style="display:none">
        <div class="prog-bar" id="prog-bar"></div>
      </div>
      <div id="prog-txt" class="prog-txt" style="display:none"></div>

      <div class="card">
        <div class="ct"><div class="ctd"></div>Cookie Files</div>
        <div class="tbar">
          <div class="tab active" data-tab="zip">ZIP Archive</div>
          <div class="tab"        data-tab="multi">Multiple TXT</div>
          <div class="tab"        data-tab="paste">Paste Text</div>
        </div>
        <div class="tc active" id="tab-zip">
          <div class="dz" id="dz-zip">
            <div class="dz-ic">📦</div>
            <div class="dz-tx">Drop ZIP file here or click to browse</div>
            <div class="dz-hi">ZIP should contain Netscape .txt cookie files</div>
            <input type="file" id="inp-zip" accept=".zip">
          </div>
          <div class="flist" id="fl-zip"></div>
        </div>
        <div class="tc" id="tab-multi">
          <div class="dz" id="dz-multi">
            <div class="dz-ic">📂</div>
            <div class="dz-tx">Drop .txt files here or click to browse</div>
            <div class="dz-hi">Select one or multiple Netscape cookie files</div>
            <input type="file" id="inp-multi" accept=".txt" multiple>
          </div>
          <div class="flist" id="fl-multi"></div>
        </div>
        <div class="tc" id="tab-paste">
          <label>Paste cookies — separate multiple with ---</label>
          <textarea id="b-paste" style="min-height:200px"
            placeholder=".grok.com&#9;TRUE&#9;/&#9;TRUE&#9;0&#9;sso&#9;token1&#10;---&#10;.grok.com&#9;TRUE&#9;/&#9;TRUE&#9;0&#9;sso&#9;token2"></textarea>
        </div>
      </div>

      <div class="card">
        <div class="ct"><div class="ctd"></div>Options</div>
        <div class="orow">
          <div>
            <label>Threads (1–50)</label>
            <input type="number" id="b-threads" value="10" min="1" max="50">
          </div>
          <div style="display:flex;flex-direction:column;justify-content:flex-end">
            <div class="trow" style="padding:0;border:none">
              <div class="tlbl">Preflight GET <small>visit grok.com first</small></div>
              <label class="tgl"><input type="checkbox" id="b-preflight" checked><span class="tsldr"></span></label>
            </div>
          </div>
        </div>
      </div>

      <div class="card" id="tier-card" style="display:none">
        <div class="ct"><div class="ctd"></div>Tier Breakdown</div>
        <div class="tgrid" id="tier-grid"></div>
      </div>

      <button class="btn btn-p btn-full" id="batch-btn">▶ Start Batch</button>
      <div style="height:8px"></div>
      <button class="btn btn-d btn-full" id="stop-btn" style="display:none">■ Stop Processing</button>
    </div>

    <!-- ── PAGE: RESULTS ─────────────────────────────────────── -->
    <div class="page" id="page-results">
      <div class="card" style="padding:16px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:10px">
          <div class="ct" style="margin:0"><div class="ctd"></div>Results</div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <input type="text" id="search-input"
              style="width:190px;height:32px;font-size:11px;padding:4px 10px"
              placeholder="email, tier, file...">
            <button class="btn btn-g" style="padding:6px 14px;font-size:12px" id="exp-btn">⬇ Export ZIP</button>
            <button class="btn btn-g" style="padding:6px 14px;font-size:12px" id="clr-btn">🗑 Clear</button>
          </div>
        </div>
        <div class="fbar">
          <button class="fb active" data-f="all">All</button>
          <button class="fb" data-f="valid">Valid</button>
          <button class="fb" data-f="invalid">Invalid</button>
          <button class="fb" data-f="cloudflare_blocked">CF Block</button>
          <button class="fb" data-f="error">Error</button>
        </div>
        <div class="twrap">
          <table>
            <thead><tr>
              <th>#</th>
              <th>File</th>
              <th>Status</th>
              <th>Tier</th>
              <th>Email</th>
              <th>User ID</th>
              <th>Reason</th>
              <th>Actions</th>
            </tr></thead>
            <tbody id="res-body">
              <tr><td colspan="8">
                <div class="empty">
                  <div class="eic">📭</div>
                  <div class="etx">No results yet — run a check or batch</div>
                </div>
              </td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ── PAGE: SETTINGS ────────────────────────────────────── -->
    <div class="page" id="page-settings">
      <div class="card">
        <div class="ct"><div class="ctd"></div>Proxies</div>
        <label>One proxy per line — http, socks4, socks5 supported</label>
        <textarea id="prx-input" style="min-height:140px;margin-top:8px"
          placeholder="192.168.1.1:8080&#10;user:pass@10.0.0.1:3128&#10;socks5://user:pass@host:1080&#10;http://host:port@user:pass"></textarea>
        <div style="display:flex;gap:10px;margin-top:12px">
          <button class="btn btn-g" onclick="document.getElementById('prx-file').click()">⬆ Load .txt</button>
          <input type="file" id="prx-file" accept=".txt" style="display:none">
          <button class="btn btn-g" id="prx-clr">🗑 Clear</button>
        </div>
        <div id="prx-cnt" style="margin-top:9px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--tdim)"></div>
      </div>

      <div class="card">
        <div class="ct"><div class="ctd"></div>Default Options</div>
        <div class="trow">
          <div class="tlbl">Preflight GET by default
            <small>GET grok.com before each session check</small>
          </div>
          <label class="tgl"><input type="checkbox" id="cfg-preflight" checked><span class="tsldr"></span></label>
        </div>
        <div class="trow" style="margin-top:14px;border-top:1px solid var(--bdr);padding-top:14px">
          <div style="max-width:200px">
            <label>Default Threads</label>
            <input type="number" id="cfg-threads" value="10" min="1" max="50">
          </div>
        </div>
      </div>

      <div class="card">
        <div class="ct"><div class="ctd"></div>Cookie Format</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--tmid);line-height:2">
          <p>Expects <strong style="color:var(--teal)">Netscape tab-delimited</strong> format:</p>
          <p style="margin-top:8px;color:var(--tdim)">&lt;domain&gt; &lt;flag&gt; &lt;path&gt; &lt;secure&gt; &lt;expires&gt; &lt;name&gt; &lt;value&gt;</p>
          <p style="margin-top:8px">Only cookies for <strong style="color:var(--blu2)">grok.com</strong> and
            <strong style="color:var(--blu2)">x.ai</strong> domains are used.</p>
          <p style="margin-top:8px;color:var(--tdim)">Expired cookies (by unix timestamp) are auto-filtered.</p>
        </div>
      </div>

      <button class="btn btn-p" id="save-btn">💾 Save Settings</button>
    </div>

  </div><!-- /content -->
</div><!-- /main -->

<div class="tc-wrap" id="tc-wrap"></div>

<script>
(function(){
'use strict';

// ── State ────────────────────────────────────────────────────────────────────
var SID          = 'g' + Math.random().toString(36).slice(2, 10);
var socket       = null;
var allResults   = [];
var curFilter    = 'all';
var searchQ      = '';
var batchRunning = false;
var batchStopped = false;
var zipFile      = null;
var multiFiles   = [];
var renderTimer  = null;

function scheduleRender(){
  if(renderTimer) clearTimeout(renderTimer);
  renderTimer = setTimeout(function(){ renderTimer = null; renderTable(); }, 160);
}

var BADGE = {
  valid:               {cls:'bv', lbl:'VALID'},
  invalid:             {cls:'bi', lbl:'INVALID'},
  cloudflare_blocked:  {cls:'bc', lbl:'CF BLOCK'},
  error:               {cls:'be', lbl:'ERROR'},
};
var PAGE_TITLES = {
  single: 'Single Cookie Check',
  batch:  'Batch Processing',
  results:'Live Results',
  settings:'Settings',
};

// ── Utilities ────────────────────────────────────────────────────────────────
function ge(id){ return document.getElementById(id); }
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function toast(msg, type){
  var w  = ge('tc-wrap');
  var el = document.createElement('div');
  el.className = 'toast' + (type ? ' '+type : '');
  el.textContent = msg;
  w.appendChild(el);
  setTimeout(function(){ el.remove(); }, 3100);
}

function clipCopy(text, msg){
  if(!text){ toast('Nothing to copy','err'); return; }
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(text)
      .then(function(){ toast(msg||'Copied!','ok'); })
      .catch(function(){ fbCopy(text, msg); });
  } else { fbCopy(text, msg); }
}
function fbCopy(text, msg){
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0;font-size:16px';
  document.body.appendChild(ta);
  ta.focus(); ta.select();
  try{ document.execCommand('copy'); toast(msg||'Copied!','ok'); }
  catch(e){ toast('Copy failed','err'); }
  document.body.removeChild(ta);
}

function fmtSize(b){
  if(b < 1024) return b+'B';
  if(b < 1048576) return (b/1024).toFixed(1)+'KB';
  return (b/1048576).toFixed(1)+'MB';
}

// ── Socket ───────────────────────────────────────────────────────────────────
function initSocket(){
  socket = io({ transports:['websocket','polling'] });
  socket.on('connect',    function(){ socket.emit('join',{sid:SID}); setDot(true); });
  socket.on('disconnect', function(){ setDot(false); });
  socket.on('result_row', function(row){ if(batchStopped) return; allResults.push(row); scheduleRender(); });
  socket.on('counts',     function(d){ if(batchStopped) return; onCounts(d); });
  socket.on('batch_done', function(d){ if(batchStopped) return; onBatchDone(d); });
}
function setDot(on){
  var d = document.querySelector('.dot');
  if(!d) return;
  d.style.background = on ? 'var(--teal)' : 'var(--red)';
  d.style.boxShadow  = on ? '0 0 6px var(--teal)' : '0 0 6px var(--red)';
}

// ── Navigation ───────────────────────────────────────────────────────────────
document.querySelectorAll('.ni').forEach(function(item){
  item.addEventListener('click', function(){
    var pg = item.dataset.page;
    document.querySelectorAll('.ni').forEach(function(n){ n.classList.remove('active'); });
    document.querySelectorAll('.page').forEach(function(p){ p.classList.remove('active'); });
    item.classList.add('active');
    ge('page-'+pg).classList.add('active');
    ge('pg-title').textContent = PAGE_TITLES[pg] || pg;
    closeSidebar();
  });
});

// ── Sidebar / Hamburger ──────────────────────────────────────────────────────
function toggleSidebar(){
  var sb = ge('sidebar'), ov = ge('mob-ov');
  if(sb.classList.contains('open')){
    sb.classList.remove('open'); ov.classList.remove('on');
    setTimeout(function(){ ov.style.display='none'; }, 300);
  } else {
    ov.style.display='block'; void ov.offsetWidth;
    sb.classList.add('open'); ov.classList.add('on');
  }
}
function closeSidebar(){
  var sb = ge('sidebar'), ov = ge('mob-ov');
  if(sb) sb.classList.remove('open');
  if(ov){ ov.classList.remove('on'); setTimeout(function(){ ov.style.display='none'; }, 300); }
}
ge('hbg').addEventListener('click', toggleSidebar);
ge('mob-ov').addEventListener('click', closeSidebar);

// ── Tabs ─────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(function(tab){
  tab.addEventListener('click', function(){
    var tid = tab.dataset.tab;
    tab.parentElement.querySelectorAll('.tab').forEach(function(t){ t.classList.remove('active'); });
    tab.classList.add('active');
    document.querySelectorAll('.tc').forEach(function(c){ c.classList.remove('active'); });
    ge('tab-'+tid).classList.add('active');
  });
});

// ── Single Check ─────────────────────────────────────────────────────────────
ge('sc-file').addEventListener('change', function(){
  var f = this.files[0]; if(!f) return;
  var r = new FileReader();
  r.onload = function(e){ ge('sc-input').value = e.target.result; };
  r.readAsText(f);
});

// drag-drop onto textarea
var sca = ge('sc-input');
sca.addEventListener('dragover', function(e){ e.preventDefault(); });
sca.addEventListener('drop', function(e){
  e.preventDefault();
  var f = e.dataTransfer.files[0];
  if(f){ var rd=new FileReader(); rd.onload=function(ev){ sca.value=ev.target.result; }; rd.readAsText(f); }
});

ge('sc-btn').addEventListener('click', doSingleCheck);

function doSingleCheck(){
  var cookie = ge('sc-input').value.trim();
  if(!cookie){ toast('Paste a cookie first','err'); return; }
  var btn  = ge('sc-btn');
  var spin = ge('sc-spin');
  var txt  = ge('sc-btntxt');
  btn.disabled = true; spin.style.display='inline-block'; txt.textContent=' Checking...';

  fetch('/api/check-single',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      cookie:    cookie,
      proxies:   ge('prx-input').value.trim(),
      preflight: ge('sc-preflight').checked,
    })
  })
  .then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
  .then(function(d){ showSingleResult(d); })
  .catch(function(e){ toast('Request failed: '+e.message,'err'); })
  .finally(function(){
    btn.disabled=false; spin.style.display='none'; txt.textContent='\u2713 Check Cookie';
  });
}

function showSingleResult(data){
  var card = ge('sc-result-card');
  var div  = ge('sc-result');
  card.style.display = 'block';

  var st   = data.status || 'error';
  var info = BADGE[st] || {cls:'be',lbl:'UNKNOWN'};
  var bcls = {valid:'r-valid',invalid:'r-invalid',cloudflare_blocked:'r-cf',error:'r-error'}[st]||'r-error';
  var icon = {valid:'✅',invalid:'❌',cloudflare_blocked:'🛡',error:'⚠'}[st]||'⚠';

  var html = '<div class="rbanner '+bcls+'">'+icon+' '+info.lbl+(data.tier_display?' — '+esc(data.tier_display):'')+'</div>';
  if(data.message){
    html += '<div style="font-family:\'JetBrains Mono\',monospace;font-size:12px;color:var(--tdim);margin-bottom:12px">'+esc(data.message)+'</div>';
  }

  var fields = [
    ['Email',          data.email],
    ['Name',           data.name],
    ['User ID',        data.user_id],
    ['Tier',           data.tier_display],
    ['Sub Status',     data.subscription_status],
    ['Billing Intv',   data.billing_interval],
    ['Period End',     data.billing_period_end],
    ['Product ID',     data.product_id],
    ['Base Plan ID',   data.base_plan_id],
    ['Reason',         data.reason],
  ];
  html += '<div style="line-height:1.8">';
  fields.forEach(function(f){
    var v = f[1];
    if(!v || v==='-') return;
    html += '<div class="rrow"><span class="rk">'+esc(f[0])+'</span><span class="rv">'+esc(String(v))+'</span></div>';
  });
  html += '</div>';

  if(data.cookie){
    html += '<div class="sbtns"><button class="btn btn-g" id="s-ck" style="padding:7px 16px;font-size:12px">🍪 Copy Cookie</button></div>';
  }
  div.innerHTML = html;
  var bck = ge('s-ck');
  if(bck) bck.addEventListener('click', function(){ clipCopy(data.cookie, 'Cookie copied!'); });

  // add to results table
  allResults.push({
    idx: allResults.length+1, source_file:'single',
    status: st, tier_display: data.tier_display||'-',
    email: data.email||'-', user_id: data.user_id||'-',
    reason: data.reason||'-', cookie: data.cookie||'',
  });
  renderTable();
}

// ── Batch ─────────────────────────────────────────────────────────────────────
ge('inp-zip').addEventListener('change',   function(){ handleZip(this); });
ge('inp-multi').addEventListener('change', function(){ handleMulti(this); });
ge('batch-btn').addEventListener('click',  startBatch);
ge('stop-btn').addEventListener('click',   stopBatch);

function handleZip(input){
  zipFile=input.files[0]; multiFiles=[];
  ge('fl-zip').innerHTML = zipFile ? '<div class="fchip">📦 '+esc(zipFile.name)+'</div>' : '';
}
function handleMulti(input){
  multiFiles = Array.from(input.files); zipFile=null;
  ge('fl-multi').innerHTML = multiFiles.map(function(f){
    return '<div class="fchip">📄 '+esc(f.name)+'</div>';
  }).join('');
}

function startBatch(){
  var paste = ge('b-paste').value.trim();
  if(!zipFile && !multiFiles.length && !paste){
    toast('Provide cookie files or paste cookies','err'); return;
  }
  var fd = new FormData();
  fd.append('sid',       SID);
  fd.append('threads',   ge('b-threads').value);
  fd.append('preflight', ge('b-preflight').checked ? 'true':'false');
  fd.append('proxies',   ge('prx-input').value);
  if(paste) fd.append('paste_text', paste);
  if(zipFile)       { fd.append('cookies', zipFile); }
  else multiFiles.forEach(function(f){ fd.append('cookies', f); });

  resetBatchUI();
  batchRunning=true; batchStopped=false;
  ge('batch-btn').disabled=true; ge('batch-btn').textContent='Uploading...';
  ge('stop-btn').style.display='block';
  ge('prog-wrap').style.display='block';
  ge('prog-txt').style.display='block';
  ge('prog-txt').textContent='Uploading...';

  var xhr = new XMLHttpRequest();
  xhr.open('POST','/api/batch');
  xhr.upload.addEventListener('progress', function(e){
    if(e.lengthComputable){
      var pct = Math.round(e.loaded/e.total*100);
      ge('prog-bar').style.width = pct+'%';
      ge('prog-txt').textContent = 'Uploading: '+pct+'% ('+fmtSize(e.loaded)+' / '+fmtSize(e.total)+')';
      if(pct===100){ ge('prog-txt').textContent='Upload done — processing cookies...'; ge('batch-btn').textContent='Processing...'; }
    }
  });
  xhr.onload = function(){
    if(xhr.status>=200 && xhr.status<300){
      try{
        var d = JSON.parse(xhr.responseText);
        if(d.error){ toast(d.error,'err'); resetBatchBtn(); }
        else { toast('Started — processing '+d.total+' cookies','ok'); }
      } catch(e){ toast('Parse error','err'); resetBatchBtn(); }
    } else { toast('Upload failed: HTTP '+xhr.status,'err'); resetBatchBtn(); }
  };
  xhr.onerror   = function(){ toast('Upload failed','err'); resetBatchBtn(); };
  xhr.timeout   = 300000;
  xhr.ontimeout = function(){ toast('Upload timed out','err'); resetBatchBtn(); };
  xhr.send(fd);
}

function stopBatch(){
  if(socket) socket.emit('stop_batch',{sid:SID});
  batchRunning=false; batchStopped=true;
  resetBatchBtn(); toast('Batch stopped','');
}
function resetBatchUI(){
  ['b-chk','b-val','b-inv','b-cf','b-err'].forEach(function(id){ ge(id).textContent='0'; });
  ge('prog-bar').style.width='0%';
  allResults=[]; renderTable();
}
function resetBatchBtn(){
  batchRunning=false;
  ge('batch-btn').disabled=false;
  ge('batch-btn').textContent='\u25B6 Start Batch';
  ge('stop-btn').style.display='none';
}

function onCounts(d){
  var checked = (d.valid||0)+(d.invalid||0)+(d.cloudflare_blocked||0)+(d.error||0);
  ge('b-chk').textContent = checked;
  ge('b-val').textContent = d.valid||0;
  ge('b-inv').textContent = d.invalid||0;
  ge('b-cf' ).textContent = d.cloudflare_blocked||0;
  ge('b-err').textContent = d.error||0;
  if(d.total){
    var pct = Math.round(d.processed/d.total*100);
    ge('prog-bar').style.width = pct+'%';
    ge('prog-txt').textContent = 'Processing: '+d.processed+'/'+d.total+' ('+pct+'%)';
  }
}
function onBatchDone(d){
  batchRunning=false; onCounts(d);
  ge('batch-btn').disabled=false;
  ge('batch-btn').textContent='\u25B6 Start Batch';
  ge('stop-btn').style.display='none';
  showTiers(d.tiers||{});
  toast('Batch done! '+(d.valid||0)+' valid found.','ok');
}
function showTiers(tiers){
  var html = Object.keys(tiers).filter(function(k){ return tiers[k]>0; }).map(function(k){
    return '<div class="tprow"><span class="tpname">'+esc(k)+'</span><span class="tpcnt">'+tiers[k]+'</span></div>';
  }).join('');
  ge('tier-grid').innerHTML = html || '<div style="color:var(--tdim);font-family:\'JetBrains Mono\',monospace;font-size:12px">No tier data</div>';
  ge('tier-card').style.display='block';
}

// ── Results Table ─────────────────────────────────────────────────────────────
ge('clr-btn').addEventListener('click',  function(){ allResults=[]; renderTable(); });
ge('exp-btn').addEventListener('click',  exportZip);
ge('search-input').addEventListener('input', function(){ searchQ=this.value.toLowerCase(); renderTable(); });

document.querySelectorAll('.fb').forEach(function(btn){
  btn.addEventListener('click', function(){
    curFilter = btn.dataset.f;
    document.querySelectorAll('.fb').forEach(function(b){ b.classList.remove('active'); });
    btn.classList.add('active');
    renderTable();
  });
});

function renderTable(){
  var tbody = ge('res-body');
  var rows  = allResults.slice();
  if(curFilter !== 'all') rows = rows.filter(function(r){ return r.status===curFilter; });
  if(searchQ) rows = rows.filter(function(r){
    return (r.email||'').toLowerCase().indexOf(searchQ)>-1 ||
           (r.tier_display||'').toLowerCase().indexOf(searchQ)>-1 ||
           (r.source_file||'').toLowerCase().indexOf(searchQ)>-1 ||
           (r.user_id||'').toLowerCase().indexOf(searchQ)>-1;
  });

  if(!rows.length){
    tbody.innerHTML='<tr><td colspan="8"><div class="empty"><div class="eic">📭</div><div class="etx">No results'+
      (curFilter!=='all'?' for filter: '+curFilter:'')+'</div></div></td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(function(r, i){
    var b    = BADGE[r.status] || {cls:'be',lbl:'ERR'};
    var acts = r.cookie
      ? '<button class="ab" data-i="'+i+'" data-a="ck">🍪 Cookie</button>'
      : '—';
    return '<tr>'
      +'<td style="color:var(--tdim)">'+esc(r.idx||i+1)+'</td>'
      +'<td style="color:var(--tmid);max-width:110px">'+esc(r.source_file||'')+'</td>'
      +'<td><span class="badge '+b.cls+'">'+b.lbl+'</span></td>'
      +'<td style="color:var(--teal)">'+esc(r.tier_display||'-')+'</td>'
      +'<td>'+esc(r.email||'-')+'</td>'
      +'<td style="color:var(--tdim)">'+esc((r.user_id||'-').slice(0,20))+'</td>'
      +'<td style="color:var(--tdim)">'+esc((r.reason||'-').slice(0,30))+'</td>'
      +'<td>'+acts+'</td>'
      +'</tr>';
  }).join('');

  tbody.querySelectorAll('[data-a]').forEach(function(btn){
    btn.addEventListener('click', function(){
      var idx = parseInt(btn.dataset.i);
      var r   = rows[idx]; if(!r) return;
      if(btn.dataset.a==='ck') clipCopy(r.cookie, 'Cookie copied!');
    });
  });
}

function exportZip(){
  var a = document.createElement('a');
  a.href     = '/api/export/'+SID;
  a.download = 'grok_results.zip';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  toast('Downloading ZIP...','ok');
}

// ── Settings ──────────────────────────────────────────────────────────────────
ge('prx-input').addEventListener('input', updateProxyCnt);
ge('prx-clr').addEventListener('click',  function(){ ge('prx-input').value=''; updateProxyCnt(); });
ge('prx-file').addEventListener('change',function(){
  var f = this.files[0]; if(!f) return;
  var rd=new FileReader();
  rd.onload=function(e){ ge('prx-input').value=e.target.result; updateProxyCnt(); };
  rd.readAsText(f);
});
ge('save-btn').addEventListener('click', function(){
  // Sync cfg toggles → batch/single defaults
  ge('sc-preflight').checked = ge('cfg-preflight').checked;
  ge('b-preflight').checked  = ge('cfg-preflight').checked;
  ge('b-threads').value      = ge('cfg-threads').value;
  toast('Settings applied','ok');
});

function updateProxyCnt(){
  var n = ge('prx-input').value.split('\n')
    .filter(function(l){ return l.trim() && !l.trim().startsWith('#'); }).length;
  ge('prx-cnt').textContent = n ? n+' proxy lines loaded' : '';
}

// ── Drop Zones ────────────────────────────────────────────────────────────────
function setupDrop(id, handler){
  var el = ge(id); if(!el) return;
  el.addEventListener('dragover',  function(e){ e.preventDefault(); el.classList.add('over'); });
  el.addEventListener('dragleave', function(){  el.classList.remove('over'); });
  el.addEventListener('drop',      function(e){
    e.preventDefault(); el.classList.remove('over');
    handler(Array.from(e.dataTransfer.files));
  });
}
setupDrop('dz-zip',  function(files){
  var z=files.filter(function(f){return f.name.toLowerCase().endsWith('.zip');});
  if(z.length){ zipFile=z[0]; handleZip({files:z}); }
});
setupDrop('dz-multi', function(files){
  var v=files.filter(function(f){return f.name.toLowerCase().endsWith('.txt');});
  if(v.length){ multiFiles=v; handleMulti({files:v}); }
});

// ── Init ──────────────────────────────────────────────────────────────────────
ge('sid-lbl').textContent = SID;
initSocket();
})();
</script>
</body>
</html>"""

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
