"""
License Server — Hardened
Flask + SQLite, preserving the original API shape where practical.

Required environment variables:
  ADMIN_TOKEN   - high-entropy admin bearer secret (>= 32 chars)
  HASH_PEPPER   - independent high-entropy secret used for HMAC pseudonymization (>= 32 chars)

Recommended:
  CORS_ORIGINS=https://admin.example.com
  TRUST_PROXY_HOPS=1        # only when really behind exactly one trusted reverse proxy
  AUTO_REVOKE_ON_SHARING=0  # set to 1 only if false positives are acceptable
"""

import os
import re
import hmac
import time
import sqlite3
import secrets
import hashlib
from datetime import datetime, timezone
from functools import wraps
from typing import Optional

from flask import Flask, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix


# ── App / security configuration ──────────────────────────────────────────────

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_BODY_BYTES", "16384"))

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
HASH_PEPPER = os.environ.get("HASH_PEPPER", "")
DB_PATH = os.environ.get("DB_PATH", "licenses.db")

if len(ADMIN_TOKEN) < 32 or ADMIN_TOKEN == "TROQUE_ISSO":
    raise RuntimeError(
        "ADMIN_TOKEN ausente/fraco. Defina um segredo aleatorio com pelo menos 32 caracteres."
    )
if len(HASH_PEPPER) < 32:
    raise RuntimeError(
        "HASH_PEPPER ausente/fraco. Defina um segredo aleatorio independente com pelo menos 32 caracteres."
    )

CORS_ORIGINS = {
    x.strip()
    for x in os.environ.get("CORS_ORIGINS", "").split(",")
    if x.strip()
}

TRUST_PROXY_HOPS = int(os.environ.get("TRUST_PROXY_HOPS", "0"))
if TRUST_PROXY_HOPS < 0 or TRUST_PROXY_HOPS > 10:
    raise RuntimeError("TRUST_PROXY_HOPS invalido.")
if TRUST_PROXY_HOPS:
    # Only enable this when those hops are controlled/trusted reverse proxies.
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=TRUST_PROXY_HOPS,
        x_proto=TRUST_PROXY_HOPS,
    )

RATE_IP_MAX = int(os.environ.get("RATE_IP_MAX", "12"))
RATE_IP_WINDOW = int(os.environ.get("RATE_IP_WINDOW", "60"))
RATE_KEY_MAX = int(os.environ.get("RATE_KEY_MAX", "30"))
RATE_KEY_WINDOW = int(os.environ.get("RATE_KEY_WINDOW", "60"))
ADMIN_AUTH_MAX = int(os.environ.get("ADMIN_AUTH_MAX", "12"))
ADMIN_AUTH_WINDOW = int(os.environ.get("ADMIN_AUTH_WINDOW", "300"))
ADMIN_REQUEST_MAX = int(os.environ.get("ADMIN_REQUEST_MAX", "300"))
ADMIN_REQUEST_WINDOW = int(os.environ.get("ADMIN_REQUEST_WINDOW", "60"))
MISMATCH_MAX = int(os.environ.get("MISMATCH_MAX", "6"))
MISMATCH_WINDOW = int(os.environ.get("MISMATCH_WINDOW", "3600"))

MAX_IPS_PER_KEY_DAY = int(os.environ.get("MAX_IPS_PER_KEY_DAY", "5"))
AUTO_REVOKE_ON_SHARING = os.environ.get("AUTO_REVOKE_ON_SHARING", "0") == "1"

MAX_GENERATE_QTY = int(os.environ.get("MAX_GENERATE_QTY", "100"))
MAX_LICENSE_DAYS = int(os.environ.get("MAX_LICENSE_DAYS", "3650"))
MAX_LOG_LIMIT = int(os.environ.get("MAX_LOG_LIMIT", "500"))

GENERIC_LICENSE_ERROR = "Licenca invalida ou indisponivel."

HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
LEGACY_KEY_RE = re.compile(r"^[A-F0-9]{8}(?:-[A-F0-9]{8}){3}$")
NEW_KEY_RE = re.compile(
    r"^[A-Z0-9]{2,12}-[A-F0-9]{8}(?:-[A-F0-9]{8}){7}$"
)
PREFIX_RE = re.compile(r"^[A-Z0-9]{2,12}$")


# ── HTTP hardening / CORS ─────────────────────────────────────────────────────

@app.after_request
def security_headers(resp):
    origin = request.headers.get("Origin")
    if origin and origin in CORS_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Token"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"

    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    origin = request.headers.get("Origin")
    if origin and origin not in CORS_ORIGINS:
        return jsonify({"success": False}), 403
    return ("", 204)


# ── Database ───────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    with get_db() as c:
        c.execute("PRAGMA journal_mode=WAL")

        c.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key        TEXT PRIMARY KEY,
                hwid       TEXT DEFAULT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                note       TEXT DEFAULT '',
                active     INTEGER DEFAULT 1,
                use_count  INTEGER DEFAULT 0,
                last_seen  INTEGER DEFAULT 0
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                key    TEXT,
                hwid   TEXT,
                ip     TEXT,
                result TEXT,
                ts     INTEGER
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS banned_hwids (
                hwid      TEXT PRIMARY KEY,
                reason    TEXT DEFAULT '',
                banned_at INTEGER
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip         TEXT PRIMARY KEY,
                reason     TEXT DEFAULT '',
                blocked_at INTEGER
            )
        """)

        # Persistent limiter works across multiple workers using the same SQLite DB.
        c.execute("""
            CREATE TABLE IF NOT EXISTS rate_events (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket  TEXT NOT NULL,
                subject TEXT NOT NULL,
                ts      INTEGER NOT NULL
            )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_key_ts ON logs(key, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip_ts ON logs(ip, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_hwid_ts ON logs(hwid, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_rate_bucket_subject_ts "
                  "ON rate_events(bucket, subject, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_rate_ts ON rate_events(ts)")
        c.commit()


init_db()


# ── Helpers ────────────────────────────────────────────────────────────────────

def now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def clamp_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    if n < minimum or n > maximum:
        raise ValueError(f"valor fora do intervalo {minimum}..{maximum}")
    return n


def clean_text(value, max_len: int) -> str:
    value = str(value or "").strip()
    # Keep text usable in JSON/UI while rejecting control characters.
    value = "".join(ch for ch in value if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return value[:max_len]


def normalize_key(value: str) -> str:
    key = str(value or "").strip().upper()
    if not (LEGACY_KEY_RE.fullmatch(key) or NEW_KEY_RE.fullmatch(key)):
        return ""
    return key


def gen_key(prefix: str = "EVS") -> str:
    """
    32 CSPRNG bytes = 256 bits of entropy.
    Prefix is only a label and is NOT counted as entropy.
    Example:
      EVS-AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD-EEEEEEEE-FFFFFFFF-11111111-22222222
    """
    prefix = (prefix or "EVS").strip().upper()
    if not PREFIX_RE.fullmatch(prefix):
        raise ValueError("prefixo invalido")
    raw = secrets.token_hex(32).upper()  # 32 random bytes => 64 hex chars
    groups = "-".join(raw[i:i + 8] for i in range(0, len(raw), 8))
    return f"{prefix}-{groups}"


def legacy_sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def keyed_hash(kind: str, value: str) -> str:
    # HMAC avoids making predictable IP/HWID values cheaply reversible from DB dumps.
    msg = f"{kind}\x00{value}".encode("utf-8")
    return hmac.new(HASH_PEPPER.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def hash_candidates(kind: str, value: str):
    """
    New HMAC first, old raw SHA-256 second for gradual compatibility with an
    existing database created by the original server.
    """
    secure = keyed_hash(kind, value)
    legacy = legacy_sha(value)
    return secure, legacy


def safe_compare(a: str, b: str) -> bool:
    return secrets.compare_digest(str(a or ""), str(b or ""))


def mask_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 12:
        return "***"
    return f"{key[:4]}...{key[-8:]}"


def log_key_ref(key: str) -> str:
    # Human-recognizable hint + collision-resistant server-keyed reference.
    return f"{mask_key(key)}#{keyed_hash('log-key', key)[:20]}"


def log_event(key: str, hwid_hash: str, ip_hash: str, result: str):
    # Do not persist the full license key in new log rows.
    key_ref = log_key_ref(key)
    with get_db() as c:
        c.execute(
            "INSERT INTO logs (key,hwid,ip,result,ts) VALUES(?,?,?,?,?)",
            (key_ref, hwid_hash or "", ip_hash or "", clean_text(result, 64), now()),
        )
        c.commit()


def expiry_fmt(ts: int):
    t = now()
    dt = datetime.fromtimestamp(ts, timezone.utc)
    seconds_left = ts - t
    days_left = max((seconds_left + 86399) // 86400, 0)
    return {
        "timestamp": ts,
        "date_utc": dt.strftime("%d/%m/%Y %H:%M UTC"),
        "days_left": int(days_left),
        "expired": ts <= t,
    }


def client_ip() -> str:
    # request.remote_addr is safe against raw X-Forwarded-For spoofing unless
    # ProxyFix above is explicitly enabled for the exact trusted proxy count.
    return (request.remote_addr or "").strip()


def json_body():
    if not request.is_json:
        return None
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def rate_limited(bucket: str, subject: str, limit: int, window: int) -> bool:
    subject_hash = keyed_hash(f"rate:{bucket}", subject or "<empty>")
    t = now()
    cutoff = t - window

    with get_db() as c:
        c.execute("BEGIN IMMEDIATE")
        count = c.execute(
            """
            SELECT COUNT(*) FROM rate_events
            WHERE bucket=? AND subject=? AND ts>?
            """,
            (bucket, subject_hash, cutoff),
        ).fetchone()[0]

        if count >= limit:
            c.commit()
            return True

        c.execute(
            "INSERT INTO rate_events(bucket,subject,ts) VALUES(?,?,?)",
            (bucket, subject_hash, t),
        )

        # Opportunistic cleanup to cap storage without doing a full cleanup each request.
        if secrets.randbelow(100) == 0:
            c.execute("DELETE FROM rate_events WHERE ts<?", (t - 86400,))

        c.commit()
        return False


def migrate_hash_if_needed(table: str, column: str, legacy: str, secure: str):
    # Table/column names are internal constants only, never user-controlled.
    with get_db() as c:
        c.execute(
            f"UPDATE OR IGNORE {table} SET {column}=? WHERE {column}=?",
            (secure, legacy),
        )
        c.commit()


def is_hash_listed(table: str, column: str, kind: str, raw_value: str) -> bool:
    secure, legacy = hash_candidates(kind, raw_value)
    with get_db() as c:
        row = c.execute(
            f"SELECT {column} FROM {table} WHERE {column} IN (?,?) LIMIT 1",
            (secure, legacy),
        ).fetchone()

    if not row:
        return False

    if safe_compare(row[column], legacy):
        migrate_hash_if_needed(table, column, legacy, secure)
    return True


def admin_only(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        ip = client_ip()
        token = request.headers.get("X-Admin-Token", "")

        # No token-in-body fallback: secrets should stay in the auth header.
        if not token or not safe_compare(token, ADMIN_TOKEN):
            if rate_limited("admin-auth-fail", ip, ADMIN_AUTH_MAX, ADMIN_AUTH_WINDOW):
                return jsonify({"success": False, "message": "Unauthorized"}), 429
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        # Separate, much higher limit for authenticated admin traffic.
        if rate_limited("admin-authenticated", ip, ADMIN_REQUEST_MAX, ADMIN_REQUEST_WINDOW):
            return jsonify({"success": False, "message": "Too many requests"}), 429

        return fn(*args, **kwargs)

    return wrapped


def public_denied(status: int = 403):
    # Same public response for nonexistent, expired, revoked and wrong-device keys.
    return jsonify({"success": False, "message": GENERIC_LICENSE_ERROR}), status


def sharing_state_for_key(key: str, ip_hash: str, since_ts: int):
    """
    Count distinct successful IP identities and determine whether the current IP
    has already been observed. We read both legacy full-key logs and new redacted
    log references so upgrades do not instantly forget recent history.
    """
    key_ref = log_key_ref(key)
    with get_db() as c:
        distinct = c.execute(
            """
            SELECT COUNT(DISTINCT ip)
            FROM logs
            WHERE key IN (?,?) AND ts>=? AND result='ok' AND ip<>''
            """,
            (key, key_ref, since_ts),
        ).fetchone()[0]
        current_seen = c.execute(
            """
            SELECT 1 FROM logs
            WHERE key IN (?,?) AND ts>=? AND result='ok' AND ip=?
            LIMIT 1
            """,
            (key, key_ref, since_ts, ip_hash),
        ).fetchone() is not None
    return distinct, current_seen


def handle_sharing_signal(key: str, hwid_hash: str, ip_hash: str) -> bool:
    distinct, current_seen = sharing_state_for_key(key, ip_hash, now() - 86400)

    # Existing IPs do not create additional sharing risk. A new IP only exceeds
    # the configured allowance after MAX_IPS_PER_KEY_DAY distinct prior IPs.
    if current_seen or distinct < MAX_IPS_PER_KEY_DAY:
        return False

    log_event(key, hwid_hash, ip_hash, "sharing_detected")

    if AUTO_REVOKE_ON_SHARING:
        with get_db() as c:
            c.execute("UPDATE licenses SET active=0 WHERE key=?", (key,))
            c.commit()
        return True

    # Flag-only mode: do not lock a legitimate user whose ISP/VPN rotates IPs.
    return False


# ── Health ─────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ── Public validation ──────────────────────────────────────────────────────────

@app.route("/validate", methods=["POST"])
def validate():
    data = json_body()
    if data is None:
        return jsonify({"success": False, "message": "JSON invalido."}), 400

    ip = client_ip()
    key = normalize_key(data.get("key"))
    hwid_raw = clean_text(data.get("hwid"), 512)

    if not key or not hwid_raw:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400

    # Multi-dimensional limits: IP + key + HWID. OWASP recommends not relying on
    # only one limiter identity for abuse-sensitive operations.
    if rate_limited("validate-ip", ip, RATE_IP_MAX, RATE_IP_WINDOW):
        return jsonify({"success": False, "message": "Muitas tentativas. Aguarde."}), 429

    if rate_limited("validate-key", key, RATE_KEY_MAX, RATE_KEY_WINDOW):
        return jsonify({"success": False, "message": "Muitas tentativas. Aguarde."}), 429

    if rate_limited("validate-hwid", hwid_raw, RATE_KEY_MAX, RATE_KEY_WINDOW):
        return jsonify({"success": False, "message": "Muitas tentativas. Aguarde."}), 429

    ip_hash, ip_legacy = hash_candidates("ip", ip)
    hwid_hash, hwid_legacy = hash_candidates("hwid", hwid_raw)

    if is_hash_listed("blocked_ips", "ip", "ip", ip):
        log_event(key, hwid_hash, ip_hash, "ip_blocked")
        return public_denied()

    if is_hash_listed("banned_hwids", "hwid", "hwid", hwid_raw):
        log_event(key, hwid_hash, ip_hash, "hwid_banned")
        return public_denied()

    # One write transaction protects first activation from the race where two PCs
    # simultaneously observe hwid=NULL and both claim success.
    with get_db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()

        if not row:
            c.commit()
            log_event(key, hwid_hash, ip_hash, "invalid_key")
            return public_denied()

        if not row["active"]:
            c.commit()
            log_event(key, hwid_hash, ip_hash, "revoked")
            return public_denied()

        if row["expires_at"] <= now():
            c.commit()
            log_event(key, hwid_hash, ip_hash, "expired")
            return public_denied()

        bound_hwid = row["hwid"]

        if bound_hwid is None:
            cur = c.execute(
                """
                UPDATE licenses
                SET hwid=?, use_count=use_count+1, last_seen=?
                WHERE key=? AND hwid IS NULL AND active=1 AND expires_at>?
                """,
                (hwid_hash, now(), key, now()),
            )
            if cur.rowcount != 1:
                # Defensive re-read if another worker changed the row.
                row = c.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
                bound_hwid = row["hwid"] if row else None
                if not (
                    bound_hwid
                    and (
                        safe_compare(bound_hwid, hwid_hash)
                        or safe_compare(bound_hwid, hwid_legacy)
                    )
                ):
                    c.rollback()
                    log_event(key, hwid_hash, ip_hash, "hwid_race_lost")
                    return public_denied()
            c.commit()

        elif safe_compare(bound_hwid, hwid_hash):
            c.execute(
                "UPDATE licenses SET use_count=use_count+1,last_seen=? WHERE key=?",
                (now(), key),
            )
            c.commit()

        elif safe_compare(bound_hwid, hwid_legacy):
            # Gradually upgrade old SHA-256-only bindings to keyed HMAC.
            c.execute(
                """
                UPDATE licenses
                SET hwid=?, use_count=use_count+1,last_seen=?
                WHERE key=? AND hwid=?
                """,
                (hwid_hash, now(), key, bound_hwid),
            )
            c.commit()

        else:
            c.rollback()

            log_event(key, hwid_hash, ip_hash, "hwid_mismatch")

            # Never permanently ban a client-supplied HWID after one mismatch.
            # A hostile client can spoof someone else's HWID and weaponize such a ban.
            if rate_limited("mismatch-ip", ip, MISMATCH_MAX, MISMATCH_WINDOW):
                return jsonify(
                    {"success": False, "message": "Muitas tentativas. Aguarde."}
                ), 429

            return public_denied()

    # Anti-sharing signal: now correctly counts distinct IP hashes.
    if handle_sharing_signal(key, hwid_hash, ip_hash):
        return public_denied()

    log_event(key, hwid_hash, ip_hash, "ok")

    # Re-read expiry in case an admin changed it during the request.
    with get_db() as c:
        row = c.execute(
            "SELECT expires_at FROM licenses WHERE key=?", (key,)
        ).fetchone()

    return jsonify(
        {
            "success": True,
            "message": "ok",
            "expiry": expiry_fmt(row["expires_at"]),
        }
    ), 200


# ── Admin endpoints ────────────────────────────────────────────────────────────

@app.route("/generate", methods=["POST"])
@admin_only
def generate():
    data = json_body()
    if data is None:
        return jsonify({"success": False, "message": "JSON invalido."}), 400

    try:
        days = clamp_int(data.get("days", 30), 30, 1, MAX_LICENSE_DAYS)
        qty = clamp_int(data.get("quantity", 1), 1, 1, MAX_GENERATE_QTY)
    except ValueError:
        return jsonify({"success": False, "message": "Parametros invalidos."}), 400

    prefix = clean_text(data.get("prefix", "EVS"), 12).upper()
    note = clean_text(data.get("note", ""), 200)

    if not PREFIX_RE.fullmatch(prefix):
        return jsonify({"success": False, "message": "Prefixo invalido."}), 400

    created = now()
    exp = created + days * 86400
    keys = []

    with get_db() as c:
        for _ in range(qty):
            # Collision is astronomically unlikely, but handle it correctly.
            for _attempt in range(5):
                key = gen_key(prefix)
                try:
                    c.execute(
                        """
                        INSERT INTO licenses(key,expires_at,created_at,note)
                        VALUES(?,?,?,?)
                        """,
                        (key, exp, created, note),
                    )
                    keys.append(key)
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                c.rollback()
                return jsonify(
                    {"success": False, "message": "Falha ao gerar chave unica."}
                ), 500
        c.commit()

    return jsonify(
        {
            "success": True,
            "keys": keys,
            "days": days,
            "expires": expiry_fmt(exp),
        }
    )


@app.route("/renew", methods=["POST"])
@admin_only
def renew():
    data = json_body()
    if data is None:
        return jsonify({"success": False, "message": "JSON invalido."}), 400

    key = normalize_key(data.get("key"))
    if not key:
        return jsonify({"success": False, "message": "Key invalida."}), 400

    try:
        days = clamp_int(data.get("days", 30), 30, 1, MAX_LICENSE_DAYS)
    except ValueError:
        return jsonify({"success": False, "message": "Dias invalidos."}), 400

    with get_db() as c:
        row = c.execute(
            "SELECT expires_at FROM licenses WHERE key=?", (key,)
        ).fetchone()
        if not row:
            return jsonify({"success": False, "message": "Key nao encontrada."}), 404

        new_exp = max(row["expires_at"], now()) + days * 86400
        c.execute(
            "UPDATE licenses SET expires_at=?,active=1 WHERE key=?",
            (new_exp, key),
        )
        c.commit()

    return jsonify(
        {
            "success": True,
            "message": f"+{days} dias.",
            "expires": expiry_fmt(new_exp),
        }
    )


@app.route("/revoke", methods=["POST"])
@admin_only
def revoke():
    data = json_body()
    key = normalize_key(data.get("key") if data else "")
    if not key:
        return jsonify({"success": False, "message": "Key invalida."}), 400

    with get_db() as c:
        cur = c.execute("UPDATE licenses SET active=0 WHERE key=?", (key,))
        c.commit()

    if cur.rowcount != 1:
        return jsonify({"success": False, "message": "Key nao encontrada."}), 404
    return jsonify({"success": True, "message": "Revogada."})


@app.route("/delete", methods=["POST"])
@admin_only
def delete():
    data = json_body()
    key = normalize_key(data.get("key") if data else "")
    if not key:
        return jsonify({"success": False, "message": "Key invalida."}), 400

    key_ref = log_key_ref(key)
    with get_db() as c:
        cur = c.execute("DELETE FROM licenses WHERE key=?", (key,))
        c.execute("DELETE FROM logs WHERE key IN (?,?)", (key, key_ref))
        c.commit()

    if cur.rowcount != 1:
        return jsonify({"success": False, "message": "Key nao encontrada."}), 404
    return jsonify({"success": True, "message": "Deletada."})


@app.route("/reset_hwid", methods=["POST"])
@admin_only
def reset_hwid():
    data = json_body()
    key = normalize_key(data.get("key") if data else "")
    if not key:
        return jsonify({"success": False, "message": "Key invalida."}), 400

    with get_db() as c:
        cur = c.execute(
            "UPDATE licenses SET hwid=NULL WHERE key=?",
            (key,),
        )
        c.commit()

    if cur.rowcount != 1:
        return jsonify({"success": False, "message": "Key nao encontrada."}), 404
    return jsonify({"success": True, "message": "HWID resetado."})


def admin_hash_input(kind: str, raw: str) -> Optional[str]:
    raw = clean_text(raw, 512)
    if not raw:
        return None
    if HEX64_RE.fullmatch(raw):
        # Supports hashes copied from the admin listing / old database.
        return raw.lower()
    return keyed_hash(kind, raw)


@app.route("/ban_hwid", methods=["POST"])
@admin_only
def ban_hwid():
    data = json_body()
    if data is None:
        return jsonify({"success": False, "message": "JSON invalido."}), 400

    hwid_hash = admin_hash_input("hwid", data.get("hwid"))
    reason = clean_text(data.get("reason", ""), 200)

    if not hwid_hash:
        return jsonify({"success": False, "message": "HWID nao informado."}), 400

    with get_db() as c:
        c.execute(
            """
            INSERT INTO banned_hwids(hwid,reason,banned_at)
            VALUES(?,?,?)
            ON CONFLICT(hwid) DO UPDATE SET
              reason=excluded.reason,
              banned_at=excluded.banned_at
            """,
            (hwid_hash, reason, now()),
        )
        c.commit()

    return jsonify({"success": True, "message": "HWID banido."})


@app.route("/unban_hwid", methods=["POST"])
@admin_only
def unban_hwid():
    data = json_body()
    if data is None:
        return jsonify({"success": False, "message": "JSON invalido."}), 400

    raw = clean_text(data.get("hwid"), 512)
    if not raw:
        return jsonify({"success": False, "message": "HWID nao informado."}), 400

    candidates = [raw.lower()] if HEX64_RE.fullmatch(raw) else list(hash_candidates("hwid", raw))

    with get_db() as c:
        q = ",".join("?" for _ in candidates)
        cur = c.execute(f"DELETE FROM banned_hwids WHERE hwid IN ({q})", candidates)
        c.commit()

    return jsonify({"success": True, "message": "HWID desbanido.", "removed": cur.rowcount})


@app.route("/block_ip", methods=["POST"])
@app.route("/blacklist_ip", methods=["POST"])  # compatibility alias
@admin_only
def block_ip():
    data = json_body()
    if data is None:
        return jsonify({"success": False, "message": "JSON invalido."}), 400

    raw_ip = clean_text(data.get("ip"), 128)
    reason = clean_text(data.get("reason", ""), 200)
    ip_hash = admin_hash_input("ip", raw_ip)

    if not ip_hash:
        return jsonify({"success": False, "message": "IP nao informado."}), 400

    with get_db() as c:
        c.execute(
            """
            INSERT INTO blocked_ips(ip,reason,blocked_at)
            VALUES(?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
              reason=excluded.reason,
              blocked_at=excluded.blocked_at
            """,
            (ip_hash, reason, now()),
        )
        c.commit()

    return jsonify({"success": True, "message": "IP bloqueado."})


@app.route("/unblock_ip", methods=["POST"])
@app.route("/unblacklist_ip", methods=["POST"])  # compatibility alias
@admin_only
def unblock_ip():
    data = json_body()
    if data is None:
        return jsonify({"success": False, "message": "JSON invalido."}), 400

    raw = clean_text(data.get("ip"), 128)
    if not raw:
        return jsonify({"success": False, "message": "IP nao informado."}), 400

    candidates = [raw.lower()] if HEX64_RE.fullmatch(raw) else list(hash_candidates("ip", raw))

    with get_db() as c:
        q = ",".join("?" for _ in candidates)
        cur = c.execute(f"DELETE FROM blocked_ips WHERE ip IN ({q})", candidates)
        c.commit()

    return jsonify({"success": True, "message": "IP desbloqueado.", "removed": cur.rowcount})


@app.route("/keys", methods=["GET", "POST"])
@admin_only
def list_keys():
    with get_db() as c:
        rows = c.execute(
            "SELECT * FROM licenses ORDER BY created_at DESC LIMIT 2000"
        ).fetchall()

    return jsonify(
        {
            "success": True,
            "total": len(rows),
            "keys": [
                {
                    # Preserved for compatibility with your current admin UI.
                    # For maximum DB-compromise resistance, migrate to key hashes and show
                    # the full key only once at generation time.
                    "key": r["key"],
                    "hwid_bound": r["hwid"] is not None,
                    "active": bool(r["active"]),
                    "note": r["note"] or "",
                    "use_count": r["use_count"],
                    "expires": expiry_fmt(r["expires_at"]),
                    "created_at": datetime.fromtimestamp(
                        r["created_at"], timezone.utc
                    ).strftime("%d/%m/%Y"),
                }
                for r in rows
            ],
        }
    )


@app.route("/logs", methods=["GET", "POST"])
@admin_only
def get_logs():
    try:
        limit = clamp_int(request.args.get("limit", 300), 300, 1, MAX_LOG_LIMIT)
    except ValueError:
        return jsonify({"success": False, "message": "Limit invalido."}), 400

    with get_db() as c:
        rows = c.execute(
            "SELECT * FROM logs ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()

    return jsonify(
        {
            "success": True,
            "logs": [
                {
                    "id": r["id"],
                    "key": r["key"],
                    "ip": r["ip"],
                    "result": r["result"],
                    "ts": datetime.fromtimestamp(
                        r["ts"], timezone.utc
                    ).strftime("%d/%m/%Y %H:%M:%S"),
                }
                for r in rows
            ],
        }
    )


@app.route("/banned_hwids", methods=["GET", "POST"])
@admin_only
def list_banned():
    with get_db() as c:
        rows = c.execute(
            "SELECT * FROM banned_hwids ORDER BY banned_at DESC LIMIT 2000"
        ).fetchall()

    return jsonify(
        {
            "success": True,
            "banned": [
                {
                    "hwid": r["hwid"],
                    "reason": r["reason"],
                    "banned_at": datetime.fromtimestamp(
                        r["banned_at"], timezone.utc
                    ).strftime("%d/%m/%Y %H:%M"),
                }
                for r in rows
            ],
        }
    )


@app.route("/blocked_ips", methods=["GET", "POST"])
@app.route("/blacklisted_ips", methods=["GET", "POST"])  # compatibility alias
@admin_only
def list_blocked():
    with get_db() as c:
        rows = c.execute(
            "SELECT * FROM blocked_ips ORDER BY blocked_at DESC LIMIT 2000"
        ).fetchall()

    return jsonify(
        {
            "success": True,
            "ips": [
                {
                    "ip": r["ip"],
                    "reason": r["reason"],
                    "blocked_at": datetime.fromtimestamp(
                        r["blocked_at"], timezone.utc
                    ).strftime("%d/%m/%Y %H:%M"),
                }
                for r in rows
            ],
        }
    )


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
        revoked = c.execute(
            "SELECT COUNT(*) FROM licenses WHERE active=0"
        ).fetchone()[0]
        soon = c.execute(
            """
            SELECT COUNT(*) FROM licenses
            WHERE active=1 AND expires_at>? AND expires_at<=?
            """,
            (n, n + 7 * 86400),
        ).fetchone()[0]
        bans = c.execute("SELECT COUNT(*) FROM banned_hwids").fetchone()[0]
        bips = c.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]

        daily = c.execute(
            """
            SELECT date(ts,'unixepoch') d, COUNT(*) cnt
            FROM logs
            WHERE result='ok' AND ts>=?
            GROUP BY d ORDER BY d
            """,
            (n - 14 * 86400,),
        ).fetchall()

        top_ips = c.execute(
            """
            SELECT ip, COUNT(*) cnt
            FROM logs
            WHERE ts>=? AND ip<>''
            GROUP BY ip ORDER BY cnt DESC LIMIT 10
            """,
            (n - 86400,),
        ).fetchall()

        errors = c.execute(
            """
            SELECT result, COUNT(*) cnt
            FROM logs
            WHERE result!='ok' AND ts>=?
            GROUP BY result ORDER BY cnt DESC
            """,
            (n - 7 * 86400,),
        ).fetchall()

    # Return both the original API names and the names expected by the newer HTML.
    daily_data = [{"day": r["d"], "count": r["cnt"]} for r in daily]
    error_data = [{"type": r["result"], "count": r["cnt"]} for r in errors]
    top_ip_data = [{"ip": r["ip"], "count": r["cnt"]} for r in top_ips]

    return jsonify(
        {
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
            "daily": daily_data,
            "daily_activations": daily_data,
            "top_ips": top_ip_data,
            "errors": error_data,
            "error_types": error_data,
        }
    )


# ── Error handling ─────────────────────────────────────────────────────────────

@app.errorhandler(413)
def body_too_large(_):
    return jsonify({"success": False, "message": "Request muito grande."}), 413


@app.errorhandler(404)
def not_found(_):
    return jsonify({"success": False, "message": "Not found."}), 404


@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"success": False, "message": "Method not allowed."}), 405


if __name__ == "__main__":
    # Development only. In production use gunicorn/uwsgi behind HTTPS.
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
