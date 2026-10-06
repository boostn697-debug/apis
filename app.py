"""
EVS GEN — License Server
API de licenciamento propria. Hospede no Railway (gratuito).

Endpoints:
  POST /validate     — valida key + hwid, retorna expiracao
  POST /generate     — gera uma ou mais keys (protegido por ADMIN_TOKEN)
  POST /revoke       — revoga uma key (protegido por ADMIN_TOKEN)
  POST /reset_hwid   — reseta o hwid de uma key (protegido por ADMIN_TOKEN)
  GET  /keys         — lista todas as keys (protegido por ADMIN_TOKEN)
  GET  /health       — healthcheck
"""

import os
import sqlite3
import secrets
import string
import hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Config ────────────────────────────────────────────────────────────────────
# Defina estas variaveis de ambiente no Railway:
#   ADMIN_TOKEN  — senha do painel/API admin (troque antes de subir)
#   DATABASE_URL — deixe vazio, usa SQLite local no Railway volume
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "TROQUE_ISSO_ANTES_DE_SUBIR")
DB_PATH     = os.environ.get("DB_PATH", "licenses.db")

# ── Banco de dados ────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key         TEXT PRIMARY KEY,
                hwid        TEXT DEFAULT NULL,
                expires_at  INTEGER NOT NULL,
                created_at  INTEGER NOT NULL,
                note        TEXT DEFAULT '',
                active      INTEGER DEFAULT 1
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                key         TEXT,
                hwid        TEXT,
                ip          TEXT,
                action      TEXT,
                result      TEXT,
                ts          INTEGER
            )
        """)
        db.commit()

init_db()

# ── Helpers ───────────────────────────────────────────────────────────────────
def now_ts():
    return int(datetime.now(timezone.utc).timestamp())

def generate_key(prefix="EVS"):
    chars = string.ascii_uppercase + string.digits
    part  = lambda n: ''.join(secrets.choice(chars) for _ in range(n))
    return f"{prefix}-{part(5)}-{part(5)}-{part(5)}-{part(5)}"

def hash_hwid(hwid: str) -> str:
    """Armazena hash do HWID, nao o valor bruto."""
    return hashlib.sha256(hwid.encode()).hexdigest()

def log_action(key, hwid, ip, action, result):
    with get_db() as db:
        db.execute(
            "INSERT INTO logs (key, hwid, ip, action, result, ts) VALUES (?,?,?,?,?,?)",
            (key, hwid, ip, action, result, now_ts())
        )
        db.commit()

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Admin-Token") or request.json.get("admin_token", "") if request.is_json else ""
        if token != ADMIN_TOKEN:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def fmt_expiry(ts):
    dt    = datetime.fromtimestamp(ts, timezone.utc)
    delta = dt - datetime.now(timezone.utc)
    days  = delta.days
    return {
        "timestamp": ts,
        "date_utc":  dt.strftime("%d/%m/%Y %H:%M UTC"),
        "days_left": max(days, 0),
        "expired":   days < 0
    }

# ── Endpoints publicos ────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ts": now_ts()})


@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(silent=True) or {}
    key  = (data.get("key") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip()
    ip   = request.headers.get("X-Forwarded-For", request.remote_addr)

    if not key or not hwid:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400

    hwid_hash = hash_hwid(hwid)

    with get_db() as db:
        row = db.execute("SELECT * FROM licenses WHERE key = ?", (key,)).fetchone()

    if not row:
        log_action(key, hwid_hash, ip, "validate", "invalid_key")
        return jsonify({"success": False, "message": "Chave invalida."}), 200

    if not row["active"]:
        log_action(key, hwid_hash, ip, "validate", "revoked")
        return jsonify({"success": False, "message": "Chave revogada."}), 200

    if row["expires_at"] < now_ts():
        log_action(key, hwid_hash, ip, "validate", "expired")
        return jsonify({"success": False, "message": "Chave expirada."}), 200

    # HWID binding — vincula na primeira ativacao
    if row["hwid"] is None:
        with get_db() as db:
            db.execute("UPDATE licenses SET hwid = ? WHERE key = ?", (hwid_hash, key))
            db.commit()
    elif row["hwid"] != hwid_hash:
        log_action(key, hwid_hash, ip, "validate", "hwid_mismatch")
        return jsonify({"success": False, "message": "Chave vinculada a outro dispositivo."}), 200

    log_action(key, hwid_hash, ip, "validate", "ok")
    return jsonify({
        "success": True,
        "message": "Acesso liberado.",
        "expiry":  fmt_expiry(row["expires_at"])
    }), 200


# ── Endpoints admin ───────────────────────────────────────────────────────────

@app.route("/generate", methods=["POST"])
@require_admin
def generate():
    data     = request.get_json(silent=True) or {}
    days     = int(data.get("days", 30))
    quantity = min(int(data.get("quantity", 1)), 100)
    note     = data.get("note", "")
    prefix   = data.get("prefix", "EVS")

    expires_at = now_ts() + (days * 86400)
    created_at = now_ts()
    keys = []

    with get_db() as db:
        for _ in range(quantity):
            k = generate_key(prefix)
            db.execute(
                "INSERT INTO licenses (key, expires_at, created_at, note) VALUES (?,?,?,?)",
                (k, expires_at, created_at, note)
            )
            keys.append(k)
        db.commit()

    return jsonify({
        "success":  True,
        "keys":     keys,
        "days":     days,
        "expires":  fmt_expiry(expires_at)
    }), 200


@app.route("/revoke", methods=["POST"])
@require_admin
def revoke():
    data = request.get_json(silent=True) or {}
    key  = (data.get("key") or "").strip().upper()
    if not key:
        return jsonify({"success": False, "message": "Key nao informada."}), 400
    with get_db() as db:
        db.execute("UPDATE licenses SET active = 0 WHERE key = ?", (key,))
        db.commit()
    return jsonify({"success": True, "message": f"Key {key} revogada."})


@app.route("/reset_hwid", methods=["POST"])
@require_admin
def reset_hwid():
    data = request.get_json(silent=True) or {}
    key  = (data.get("key") or "").strip().upper()
    if not key:
        return jsonify({"success": False, "message": "Key nao informada."}), 400
    with get_db() as db:
        db.execute("UPDATE licenses SET hwid = NULL WHERE key = ?", (key,))
        db.commit()
    return jsonify({"success": True, "message": f"HWID resetado para {key}."})


@app.route("/keys", methods=["GET", "POST"])
@require_admin
def list_keys():
    with get_db() as db:
        rows = db.execute(
            "SELECT key, hwid, expires_at, created_at, note, active FROM licenses ORDER BY created_at DESC"
        ).fetchall()

    result = []
    for r in rows:
        exp = fmt_expiry(r["expires_at"])
        result.append({
            "key":        r["key"],
            "hwid_bound": r["hwid"] is not None,
            "active":     bool(r["active"]),
            "note":       r["note"],
            "expires":    exp,
            "created_at": datetime.fromtimestamp(r["created_at"], timezone.utc).strftime("%d/%m/%Y")
        })

    return jsonify({"success": True, "total": len(result), "keys": result})


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
