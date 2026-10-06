"""
License Server — hardened, compatible with the License Manager panel.

Admin authentication:
- ADMIN_TOKEN must be exactly 8 numeric digits (kept in environment, never in HTML/code).
- The panel continues sending it through X-Admin-Token, so no frontend change is required.
"""

import os
import re
import sqlite3
import secrets
import hashlib
import time
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024  # 32 KiB per request

# ── Config ────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "licenses.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()

# User explicitly wants a short numeric admin password.
# Eight decimal digits have only ~26.6 bits of entropy, so failed admin attempts
# are aggressively rate-limited below. Always serve the API over HTTPS.
if not re.fullmatch(r"\d{8}", ADMIN_TOKEN):
    raise RuntimeError(
        "ADMIN_TOKEN must be exactly 8 numeric digits. "
        "Example: set ADMIN_TOKEN=58310427 in Render Environment."
    )

# Comma-separated browser origins allowed to call the API.
# Add the real hosted panel domain here/in Render when you deploy the panel.
CORS_ORIGINS = {
    x.strip()
    for x in os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:8080,http://127.0.0.1:8080",
    ).split(",")
    if x.strip()
}

# Validation limits
VALIDATE_RATE_MAX = int(os.environ.get("VALIDATE_RATE_MAX", "10"))
VALIDATE_RATE_WINDOW = int(os.environ.get("VALIDATE_RATE_WINDOW", "60"))
KEY_RATE_MAX = int(os.environ.get("KEY_RATE_MAX", "30"))
KEY_RATE_WINDOW = int(os.environ.get("KEY_RATE_WINDOW", "60"))

# Admin password protection: 5 bad guesses per 10 minutes per IP.
ADMIN_FAIL_MAX = int(os.environ.get("ADMIN_FAIL_MAX", "5"))
ADMIN_FAIL_WINDOW = int(os.environ.get("ADMIN_FAIL_WINDOW", "600"))

# Anti-sharing: allow at most N different IPs for one key in a rolling 24h window.
MAX_IPS_PER_KEY_DAY = int(os.environ.get("MAX_IPS_PER_KEY_DAY", "3"))

# ── CORS + response hardening ─────────────────────────────────
@app.after_request
def security_headers(response):
    origin = request.headers.get("Origin")
    if origin and origin in CORS_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Token"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 204


# ── DB ────────────────────────────────────────────────────────
def get_db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=5000")
    return c


def init_db():
    with get_db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("""CREATE TABLE IF NOT EXISTS licenses (
            key        TEXT PRIMARY KEY,
            hwid       TEXT DEFAULT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            note       TEXT DEFAULT '',
            active     INTEGER DEFAULT 1,
            use_count  INTEGER DEFAULT 0,
            last_seen  INTEGER DEFAULT 0
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS logs (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            key    TEXT,
            hwid   TEXT,
            ip     TEXT,
            result TEXT,
            ts     INTEGER
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS banned_hwids (
            hwid TEXT PRIMARY KEY,
            reason TEXT DEFAULT '',
            banned_at INTEGER
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT DEFAULT '',
            blocked_at INTEGER
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS rate_events (
            scope TEXT NOT NULL,
            subject TEXT NOT NULL,
            ts INTEGER NOT NULL
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_key_ts ON logs(key, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip_ts ON logs(ip, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_rate_scope_subject_ts ON rate_events(scope, subject, ts)")
        c.commit()


init_db()


# ── Helpers ───────────────────────────────────────────────────
def now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def valid_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value or ""))


def normalize_prefix(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]", "", (value or "EVS").upper())[:10]
    return value or "EVS"


def gen_key(prefix: str = "EVS") -> str:
    """Generate a real 256-bit random license key using Python's CSPRNG."""
    raw = secrets.token_hex(32).upper()  # 32 random bytes = 256 bits
    groups = "-".join(raw[i:i + 8] for i in range(0, len(raw), 8))
    return f"{normalize_prefix(prefix)}-{groups}"


def client_ip() -> str:
    """
    Render's public endpoint is fronted by Cloudflare. Prefer the Cloudflare-set
    address when present. Do not blindly trust arbitrary X-Forwarded-For unless
    TRUST_X_FORWARDED_FOR=1 is explicitly enabled.
    """
    cf_ip = (request.headers.get("CF-Connecting-IP") or "").strip()
    if cf_ip:
        return cf_ip[:64]

    if os.environ.get("TRUST_X_FORWARDED_FOR", "0") == "1":
        xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if xff:
            return xff[:64]

    return (request.remote_addr or "unknown")[:64]


def log_event(key: str, hwid_hash: str, ip_hash: str, result: str):
    with get_db() as c:
        c.execute(
            "INSERT INTO logs (key,hwid,ip,result,ts) VALUES(?,?,?,?,?)",
            ((key or "")[:160], (hwid_hash or "")[:64], (ip_hash or "")[:64], result[:64], now()),
        )
        c.commit()


def expiry_fmt(ts: int):
    dt = datetime.fromtimestamp(ts, timezone.utc)
    remaining_seconds = ts - now()
    days_left = max(0, (remaining_seconds + 86399) // 86400)
    return {
        "timestamp": ts,
        "date_utc": dt.strftime("%d/%m/%Y %H:%M UTC"),
        "days_left": int(days_left),
        "expired": remaining_seconds <= 0,
    }


def parse_int(value, default, minimum, maximum):
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    return max(minimum, min(n, maximum))


def rate_limited(scope: str, subject: str, maximum: int, window: int, record: bool = True) -> bool:
    """SQLite-backed rolling-window limiter, shared by Gunicorn workers."""
    cutoff = now() - window
    with get_db() as c:
        c.execute("BEGIN IMMEDIATE")
        c.execute("DELETE FROM rate_events WHERE ts < ?", (now() - max(window, ADMIN_FAIL_WINDOW, 3600),))
        count = c.execute(
            "SELECT COUNT(*) FROM rate_events WHERE scope=? AND subject=? AND ts>=?",
            (scope, subject, cutoff),
        ).fetchone()[0]
        limited = count >= maximum
        if record and not limited:
            c.execute(
                "INSERT INTO rate_events(scope,subject,ts) VALUES(?,?,?)",
                (scope, subject, now()),
            )
        c.commit()
    return limited


def record_admin_failure(ip_hash: str):
    with get_db() as c:
        c.execute(
            "INSERT INTO rate_events(scope,subject,ts) VALUES('admin_fail',?,?)",
            (ip_hash, now()),
        )
        c.commit()


def admin_failure_limited(ip_hash: str) -> bool:
    cutoff = now() - ADMIN_FAIL_WINDOW
    with get_db() as c:
        count = c.execute(
            "SELECT COUNT(*) FROM rate_events WHERE scope='admin_fail' AND subject=? AND ts>=?",
            (ip_hash, cutoff),
        ).fetchone()[0]
    return count >= ADMIN_FAIL_MAX


def admin_only(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        ip_hash = sha256_text(client_ip())

        if admin_failure_limited(ip_hash):
            return jsonify({"success": False, "message": "Muitas tentativas. Aguarde alguns minutos."}), 429

        # Keep frontend compatibility: it sends the 8-digit password in X-Admin-Token.
        supplied = (request.headers.get("X-Admin-Token") or "").strip()

        if not secrets.compare_digest(supplied, ADMIN_TOKEN):
            record_admin_failure(ip_hash)
            # Same generic reply for every incorrect password.
            return jsonify({"success": False, "message": "Senha administrativa invalida."}), 401

        return f(*args, **kwargs)

    return wrap


def sharing_detected(key: str, current_ip_hash: str) -> bool:
    """Block only when the current IP would exceed the allowed distinct-IP count."""
    cutoff = now() - 86400
    with get_db() as c:
        already_seen = c.execute(
            "SELECT 1 FROM logs WHERE key=? AND ip=? AND ts>=? AND result='ok' LIMIT 1",
            (key, current_ip_hash, cutoff),
        ).fetchone()
        if already_seen:
            return False

        distinct_ips = c.execute(
            "SELECT COUNT(DISTINCT ip) FROM logs WHERE key=? AND ts>=? AND result='ok'",
            (key, cutoff),
        ).fetchone()[0]

    return distinct_ips >= MAX_IPS_PER_KEY_DAY


def public_denied(key: str, hwid_hash: str, ip_hash: str, internal_result: str, status=200):
    log_event(key, hwid_hash, ip_hash, internal_result)
    # Avoid exposing whether a guessed key exists, is revoked, expired, etc.
    return jsonify({"success": False, "message": "Licenca invalida ou indisponivel."}), status


# ── Health ────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ── Validate ──────────────────────────────────────────────────
@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "JSON invalido."}), 400

    key = str(data.get("key") or "").strip().upper()
    hwid = str(data.get("hwid") or "").strip()

    if not key or not hwid or len(key) > 160 or len(hwid) > 512:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400

    ip = client_ip()
    ip_hash = sha256_text(ip)
    hwid_hash = sha256_text(hwid)

    if rate_limited("validate_ip", ip_hash, VALIDATE_RATE_MAX, VALIDATE_RATE_WINDOW):
        log_event(key, hwid_hash, ip_hash, "rate_limited_ip")
        return jsonify({"success": False, "message": "Muitas tentativas. Aguarde."}), 429

    key_subject = sha256_text(key)
    if rate_limited("validate_key", key_subject, KEY_RATE_MAX, KEY_RATE_WINDOW):
        log_event(key, hwid_hash, ip_hash, "rate_limited_key")
        return jsonify({"success": False, "message": "Muitas tentativas. Aguarde."}), 429

    # Block list checks.
    with get_db() as c:
        if c.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip_hash,)).fetchone():
            return public_denied(key, hwid_hash, ip_hash, "ip_blocked", 403)
        if c.execute("SELECT 1 FROM banned_hwids WHERE hwid=?", (hwid_hash,)).fetchone():
            return public_denied(key, hwid_hash, ip_hash, "hwid_banned", 403)

    # Atomic first-device binding. BEGIN IMMEDIATE prevents two PCs from both
    # winning the first activation race on an unbound license.
    with get_db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()

        if not row:
            c.rollback()
            return public_denied(key, hwid_hash, ip_hash, "invalid_key")

        if not row["active"]:
            c.rollback()
            return public_denied(key, hwid_hash, ip_hash, "revoked")

        if row["expires_at"] <= now():
            c.rollback()
            return public_denied(key, hwid_hash, ip_hash, "expired")

        stored_hwid = row["hwid"]

        if stored_hwid is None:
            changed = c.execute(
                "UPDATE licenses SET hwid=?, use_count=use_count+1, last_seen=? "
                "WHERE key=? AND hwid IS NULL",
                (hwid_hash, now(), key),
            ).rowcount
            if changed != 1:
                # Defensive fallback; the immediate transaction should already serialize this.
                c.rollback()
                return public_denied(key, hwid_hash, ip_hash, "activation_race")
            c.commit()

        elif not secrets.compare_digest(stored_hwid, hwid_hash):
            c.rollback()
            # Do NOT permanently auto-ban a client-supplied HWID from one mismatch;
            # that can be weaponized to ban innocent devices.
            return public_denied(key, hwid_hash, ip_hash, "hwid_mismatch")

        else:
            if sharing_detected(key, ip_hash):
                c.rollback()
                log_event(key, hwid_hash, ip_hash, "sharing_detected")
                return jsonify({"success": False, "message": "Atividade suspeita detectada."}), 403

            c.execute(
                "UPDATE licenses SET use_count=use_count+1,last_seen=? WHERE key=?",
                (now(), key),
            )
            c.commit()

    log_event(key, hwid_hash, ip_hash, "ok")
    return jsonify({
        "success": True,
        "message": "ok",
        "expiry": expiry_fmt(row["expires_at"]),
    }), 200


# ── Admin endpoints ───────────────────────────────────────────
@app.route("/generate", methods=["POST"])
@admin_only
def generate():
    data = request.get_json(silent=True) or {}
    days = parse_int(data.get("days"), 30, 1, 3650)
    qty = parse_int(data.get("quantity"), 1, 1, 500)
    prefix = normalize_prefix(str(data.get("prefix") or "EVS"))
    note = str(data.get("note") or "")[:250]
    created = now()
    exp = created + days * 86400
    keys = []

    with get_db() as c:
        for _ in range(qty):
            # Collision is already astronomically unlikely; retry defensively.
            while True:
                k = gen_key(prefix)
                try:
                    c.execute(
                        "INSERT INTO licenses (key,expires_at,created_at,note) VALUES(?,?,?,?)",
                        (k, exp, created, note),
                    )
                    keys.append(k)
                    break
                except sqlite3.IntegrityError:
                    continue
        c.commit()

    return jsonify({"success": True, "keys": keys, "days": days, "expires": expiry_fmt(exp)})


@app.route("/renew", methods=["POST"])
@admin_only
def renew():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key") or "").strip().upper()
    days = parse_int(data.get("days"), 30, 1, 3650)
    if not key:
        return jsonify({"success": False, "message": "Key nao informada."}), 400

    with get_db() as c:
        row = c.execute("SELECT expires_at FROM licenses WHERE key=?", (key,)).fetchone()
        if not row:
            return jsonify({"success": False, "message": "Key nao encontrada."}), 404
        new_exp = max(row["expires_at"], now()) + days * 86400
        c.execute("UPDATE licenses SET expires_at=?, active=1 WHERE key=?", (new_exp, key))
        c.commit()

    return jsonify({"success": True, "message": f"+{days} dias.", "expires": expiry_fmt(new_exp)})


@app.route("/revoke", methods=["POST"])
@admin_only
def revoke():
    key = str((request.get_json(silent=True) or {}).get("key") or "").strip().upper()
    if not key:
        return jsonify({"success": False, "message": "Key nao informada."}), 400
    with get_db() as c:
        changed = c.execute("UPDATE licenses SET active=0 WHERE key=?", (key,)).rowcount
        c.commit()
    if not changed:
        return jsonify({"success": False, "message": "Key nao encontrada."}), 404
    return jsonify({"success": True, "message": "Revogada."})


@app.route("/delete", methods=["POST"])
@admin_only
def delete_key():
    key = str((request.get_json(silent=True) or {}).get("key") or "").strip().upper()
    if not key:
        return jsonify({"success": False, "message": "Key nao informada."}), 400
    with get_db() as c:
        changed = c.execute("DELETE FROM licenses WHERE key=?", (key,)).rowcount
        c.execute("DELETE FROM logs WHERE key=?", (key,))
        c.commit()
    if not changed:
        return jsonify({"success": False, "message": "Key nao encontrada."}), 404
    return jsonify({"success": True, "message": "Deletada."})


@app.route("/reset_hwid", methods=["POST"])
@admin_only
def reset_hwid():
    key = str((request.get_json(silent=True) or {}).get("key") or "").strip().upper()
    if not key:
        return jsonify({"success": False, "message": "Key nao informada."}), 400
    with get_db() as c:
        changed = c.execute("UPDATE licenses SET hwid=NULL WHERE key=?", (key,)).rowcount
        c.commit()
    if not changed:
        return jsonify({"success": False, "message": "Key nao encontrada."}), 404
    return jsonify({"success": True, "message": "HWID resetado."})


@app.route("/ban_hwid", methods=["POST"])
@admin_only
def ban_hwid():
    data = request.get_json(silent=True) or {}
    supplied = str(data.get("hwid") or "").strip()
    reason = str(data.get("reason") or "")[:250]
    if not supplied:
        return jsonify({"success": False, "message": "HWID nao informado."}), 400
    hwid_hash = supplied.lower() if valid_sha256(supplied) else sha256_text(supplied)
    with get_db() as c:
        c.execute(
            "INSERT OR REPLACE INTO banned_hwids (hwid,reason,banned_at) VALUES(?,?,?)",
            (hwid_hash, reason, now()),
        )
        c.commit()
    return jsonify({"success": True, "message": "HWID banido."})


@app.route("/unban_hwid", methods=["POST"])
@admin_only
def unban_hwid():
    supplied = str((request.get_json(silent=True) or {}).get("hwid") or "").strip()
    if not supplied:
        return jsonify({"success": False, "message": "HWID nao informado."}), 400
    hwid_hash = supplied.lower() if valid_sha256(supplied) else sha256_text(supplied)
    with get_db() as c:
        c.execute("DELETE FROM banned_hwids WHERE hwid=?", (hwid_hash,))
        c.commit()
    return jsonify({"success": True, "message": "HWID desbanido."})


def _block_ip_impl():
    data = request.get_json(silent=True) or {}
    supplied = str(data.get("ip") or "").strip()
    reason = str(data.get("reason") or "")[:250]
    if not supplied:
        return jsonify({"success": False, "message": "IP nao informado."}), 400
    ip_hash = supplied.lower() if valid_sha256(supplied) else sha256_text(supplied)
    with get_db() as c:
        c.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip,reason,blocked_at) VALUES(?,?,?)",
            (ip_hash, reason, now()),
        )
        c.commit()
    return jsonify({"success": True, "message": "IP bloqueado."})


@app.route("/block_ip", methods=["POST"])
@app.route("/blacklist_ip", methods=["POST"])
@admin_only
def block_ip():
    return _block_ip_impl()


def _unblock_ip_impl():
    supplied = str((request.get_json(silent=True) or {}).get("ip") or "").strip()
    if not supplied:
        return jsonify({"success": False, "message": "IP nao informado."}), 400
    ip_hash = supplied.lower() if valid_sha256(supplied) else sha256_text(supplied)
    with get_db() as c:
        c.execute("DELETE FROM blocked_ips WHERE ip=?", (ip_hash,))
        c.commit()
    return jsonify({"success": True, "message": "IP desbloqueado."})


@app.route("/unblock_ip", methods=["POST"])
@app.route("/unblacklist_ip", methods=["POST"])
@admin_only
def unblock_ip():
    return _unblock_ip_impl()


@app.route("/keys", methods=["GET", "POST"])
@admin_only
def list_keys():
    with get_db() as c:
        rows = c.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()

    return jsonify({
        "success": True,
        "total": len(rows),
        "keys": [{
            "key": r["key"],
            "hwid_bound": r["hwid"] is not None,
            "active": bool(r["active"]),
            "note": r["note"] or "",
            "use_count": r["use_count"],
            "expires": expiry_fmt(r["expires_at"]),
            "created_at": datetime.fromtimestamp(r["created_at"], timezone.utc).strftime("%d/%m/%Y"),
        } for r in rows],
    })


@app.route("/logs", methods=["GET", "POST"])
@admin_only
def get_logs():
    limit = parse_int(request.args.get("limit"), 300, 1, 1000)
    with get_db() as c:
        rows = c.execute("SELECT * FROM logs ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()

    return jsonify({
        "success": True,
        "logs": [{
            "id": r["id"],
            "key": r["key"],
            "hwid": r["hwid"],
            "ip": r["ip"],
            "result": r["result"],
            "ts": datetime.fromtimestamp(r["ts"], timezone.utc).strftime("%d/%m/%Y %H:%M:%S"),
        } for r in rows],
    })


@app.route("/banned_hwids", methods=["GET", "POST"])
@admin_only
def list_banned():
    with get_db() as c:
        rows = c.execute("SELECT * FROM banned_hwids ORDER BY banned_at DESC").fetchall()
    return jsonify({
        "success": True,
        "banned": [{
            "hwid": r["hwid"],
            "reason": r["reason"],
            "banned_at": datetime.fromtimestamp(r["banned_at"], timezone.utc).strftime("%d/%m/%Y %H:%M"),
        } for r in rows],
    })


def _list_blocked_impl():
    with get_db() as c:
        rows = c.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    return jsonify({
        "success": True,
        "ips": [{
            "ip": r["ip"],
            "reason": r["reason"],
            "blacklisted_at": datetime.fromtimestamp(r["blocked_at"], timezone.utc).strftime("%d/%m/%Y %H:%M"),
            "blocked_at": datetime.fromtimestamp(r["blocked_at"], timezone.utc).strftime("%d/%m/%Y %H:%M"),
        } for r in rows],
    })


@app.route("/blocked_ips", methods=["GET", "POST"])
@app.route("/blacklisted_ips", methods=["GET", "POST"])
@admin_only
def list_blocked():
    return _list_blocked_impl()


@app.route("/analytics", methods=["GET", "POST"])
@admin_only
def analytics():
    n = now()
    with get_db() as c:
        total = c.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
        active = c.execute(
            "SELECT COUNT(*) FROM licenses WHERE active=1 AND expires_at>?", (n,)
        ).fetchone()[0]
        expired = c.execute(
            "SELECT COUNT(*) FROM licenses WHERE active=1 AND expires_at<=?", (n,)
        ).fetchone()[0]
        revoked = c.execute("SELECT COUNT(*) FROM licenses WHERE active=0").fetchone()[0]
        soon = c.execute(
            "SELECT COUNT(*) FROM licenses WHERE active=1 AND expires_at>? AND expires_at<=?",
            (n, n + 7 * 86400),
        ).fetchone()[0]
        bans = c.execute("SELECT COUNT(*) FROM banned_hwids").fetchone()[0]
        bips = c.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        daily = c.execute(
            """SELECT date(ts,'unixepoch') d, COUNT(*) cnt FROM logs
               WHERE result='ok' AND ts>=? GROUP BY d ORDER BY d""",
            (n - 14 * 86400,),
        ).fetchall()
        top_ips = c.execute(
            """SELECT ip, COUNT(*) cnt FROM logs WHERE ts>=?
               GROUP BY ip ORDER BY cnt DESC LIMIT 10""",
            (n - 86400,),
        ).fetchall()
        errors = c.execute(
            """SELECT result, COUNT(*) cnt FROM logs
               WHERE result!='ok' AND ts>=?
               GROUP BY result ORDER BY cnt DESC""",
            (n - 7 * 86400,),
        ).fetchall()

    daily_payload = [{"day": r["d"], "count": r["cnt"]} for r in daily]
    top_ip_payload = [{"ip": r["ip"], "count": r["cnt"]} for r in top_ips]
    error_payload = [{"type": r["result"], "count": r["cnt"]} for r in errors]

    # Return both names so older/newer versions of your panel keep working.
    return jsonify({
        "success": True,
        "summary": {
            "total": total,
            "active": active,
            "expired": expired,
            "revoked": revoked,
            "expiring_soon": soon,
            "banned_hwids": bans,
            "blocked_ips": bips,
        },
        "daily": daily_payload,
        "daily_activations": daily_payload,
        "top_ips": top_ip_payload,
        "errors": error_payload,
        "error_types": error_payload,
    })


@app.errorhandler(413)
def too_large(_):
    return jsonify({"success": False, "message": "Request muito grande."}), 413


@app.errorhandler(404)
def not_found(_):
    return jsonify({"success": False, "message": "Endpoint nao encontrado."}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
