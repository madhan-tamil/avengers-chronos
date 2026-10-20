import os
import time
import hmac
import hashlib
import secrets
import sqlite3

from pathlib import Path
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    session,
)


app = Flask(__name__)

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY")
RECEIPT_SIGNING_KEY = os.environ.get("RECEIPT_SIGNING_KEY")

if not SESSION_SECRET_KEY or not RECEIPT_SIGNING_KEY:
    raise RuntimeError(
        "Set SESSION_SECRET_KEY and RECEIPT_SIGNING_KEY before starting."
    )

app.config["SECRET_KEY"] = SESSION_SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
)

DATABASE_PATH = os.environ.get(
    "CHRONOS_DATABASE",
    str(Path(app.root_path) / "data" / "chronos.db")
)

LEASE_LIFETIME_MS = 5000
# Intentionally vulnerable for the isolated CTF challenge.
CHRONOS_VULNERABLE_REDEMPTION = (
    os.environ.get("CHRONOS_VULNERABLE_REDEMPTION", "1") == "1"
)

CHRONOS_RACE_DELAY_SECONDS = float(
    os.environ.get("CHRONOS_RACE_DELAY_SECONDS", "0.15")
)

CHRONOS_FLAG = os.environ.get("CHRONOS_FLAG")

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


# -------------------------------------------------------------------
# Database
# -------------------------------------------------------------------

def get_db():
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=5.0,
        check_same_thread=False
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    connection = get_db()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS leases (
                lease_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL UNIQUE,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0
                    CHECK (consumed IN (0, 1))
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                lease_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                issued_at REAL NOT NULL,
                signature TEXT NOT NULL,
                FOREIGN KEY (lease_id) REFERENCES leases(lease_id)
            )
        """)

        connection.commit()

    finally:
        connection.close()


# -------------------------------------------------------------------
# Session identity
# -------------------------------------------------------------------

def get_session_id():
    """Create a random server-side session identifier if needed."""
    if "chronos_sid" not in session:
        session["chronos_sid"] = secrets.token_urlsafe(24)

    return session["chronos_sid"]


# -------------------------------------------------------------------
# Receipt signing helper
# This will be used by the redemption endpoint in Step 4.
# -------------------------------------------------------------------

def sign_receipt(receipt_id, lease_id, session_id, issued_at):
    payload = (
        f"{receipt_id}|{lease_id}|{session_id}|{issued_at:.6f}"
    ).encode("utf-8")

    return hmac.new(
        RECEIPT_SIGNING_KEY.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()


# -------------------------------------------------------------------
# Existing landing page and health endpoint
# -------------------------------------------------------------------

@app.get("/")
def landing_page():
    return render_template("index.html")


@app.get("/healthz")
def health_check():
    return {"status": "ok"}, 200


# -------------------------------------------------------------------
# Existing reconnaissance clues
# -------------------------------------------------------------------

@app.get("/robots.txt")
def robots():
    content = """User-agent: *
Disallow: /archive-maint/
"""
    return Response(content, mimetype="text/plain")


@app.get("/archive-maint/CHR-05/manifest.json")
def incident_manifest():
    return jsonify({
        "incident": "CHR-05",
        "service": "chronos-legacy",
        "status_api": "/api/v1/chronos/status",
        "timeline_log": "/archive-maint/CHR-05/timeline.log",
        "operator_note": (
            "The records came from three clock domains. "
            "Normalize timestamps before ordering events."
        )
    })


@app.get("/api/v1/chronos/status")
def chronos_status():
    return jsonify({
        "service": "chronos-legacy",
        "incident": "CHR-05",
        "state": "degraded",
        "lease_window_ms": LEASE_LIFETIME_MS,
        "clock_basis": "server-side",
        "legacy_redeemer": "v1"
    })


@app.get("/archive-maint/CHR-05/timeline.log")
def timeline_log():
    log = """\
[edge]    2026-10-20T09:48:10.000+05:30 incident=CHR-05 event=lease_issued
[api]     2026-10-20T04:18:14.710Z incident=CHR-05 event=redeem_received trace=8b31
[archive] 2026-10-20T00:18:14.761-04:00 incident=CHR-05 event=receipt_write_started trace=8b31
[api]     2026-10-20T04:18:14.820Z incident=CHR-05 event=response_committed trace=8b31
"""
    return Response(log, mimetype="text/plain")


# -------------------------------------------------------------------
# Step 3: Lease issuance
# One lease per browser session, enforced by the database.
# -------------------------------------------------------------------

@app.post("/api/v1/lease/issue")
def issue_lease():
    session_id = get_session_id()

    now = time.time()
    lease_id = secrets.token_urlsafe(18)
    expires_at = now + (LEASE_LIFETIME_MS / 1000.0)

    connection = get_db()

    try:
        connection.execute(
            """
            INSERT INTO leases
                (lease_id, session_id, issued_at, expires_at, consumed)
            VALUES (?, ?, ?, ?, 0)
            """,
            (lease_id, session_id, now, expires_at)
        )

        connection.commit()

    except sqlite3.IntegrityError:
        connection.rollback()

        existing = connection.execute(
            """
            SELECT lease_id, issued_at, expires_at, consumed
            FROM leases
            WHERE session_id = ?
            """,
            (session_id,)
        ).fetchone()

        return jsonify({
            "error": "lease_already_issued",
            "message": "This session has already received its lease.",
            "existing_lease": dict(existing) if existing else None
        }), 409

    finally:
        connection.close()

    return jsonify({
        "lease_id": lease_id,
        "issued_at": now,
        "expires_at": expires_at,
        "lifetime_ms": LEASE_LIFETIME_MS,
        "message": "Chronos lease issued."
    }), 201

# -------------------------------------------------------------------
# Step 4: Redeem a lease and issue a signed receipt.
# -------------------------------------------------------------------

@app.post("/api/v1/lease/redeem")
def redeem_lease():
    payload = request.get_json(silent=True) or {}
    lease_id = payload.get("lease_id")

    if not isinstance(lease_id, str) or not lease_id:
        return jsonify({
            "error": "missing_lease_id"
        }), 400

    session_id = get_session_id()
    connection = get_db()

    vulnerable = CHRONOS_VULNERABLE_REDEMPTION

    try:
        # Secure mode obtains the write lock before checking the lease.
        # Concurrent requests then observe the updated consumed state.
        if not vulnerable:
            connection.execute("BEGIN IMMEDIATE")

        lease = connection.execute(
            """
            SELECT lease_id, session_id, expires_at, consumed
            FROM leases
            WHERE lease_id = ? AND session_id = ?
            """,
            (lease_id, session_id)
        ).fetchone()

        if lease is None:
            if not vulnerable:
                connection.rollback()

            return jsonify({
                "error": "invalid_lease"
            }), 404

        if time.time() >= lease["expires_at"]:
            if not vulnerable:
                connection.rollback()

            return jsonify({
                "error": "lease_expired"
            }), 410

        if lease["consumed"]:
            if not vulnerable:
                connection.rollback()

            return jsonify({
                "error": "lease_already_consumed"
            }), 409

        if vulnerable:
            # INTENTIONAL CTF FLAW:
            # Two concurrent requests can both pass the check above.
            time.sleep(CHRONOS_RACE_DELAY_SECONDS)

            if time.time() >= lease["expires_at"]:
                return jsonify({
                    "error": "lease_expired"
                }), 410

            # Deliberately missing "AND consumed = 0".
            connection.execute(
                """
                UPDATE leases
                SET consumed = 1
                WHERE lease_id = ? AND session_id = ?
                """,
                (lease_id, session_id)
            )

        else:
            # Secure alternative: atomically consume only an unused,
            # unexpired lease.
            cursor = connection.execute(
                """
                UPDATE leases
                SET consumed = 1
                WHERE lease_id = ?
                  AND session_id = ?
                  AND consumed = 0
                  AND expires_at > ?
                """,
                (lease_id, session_id, time.time())
            )

            if cursor.rowcount != 1:
                connection.rollback()

                return jsonify({
                    "error": "lease_unavailable"
                }), 409

        # Create a unique receipt for this redemption.
        receipt_id = secrets.token_urlsafe(18)
        issued_at = time.time()

        signature = sign_receipt(
            receipt_id,
            lease_id,
            session_id,
            issued_at
        )

        connection.execute(
            """
            INSERT INTO receipts (
                receipt_id,
                lease_id,
                session_id,
                issued_at,
                signature
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                receipt_id,
                lease_id,
                session_id,
                issued_at,
                signature
            )
        )

        connection.commit()

        return jsonify({
            "message": "Redemption accepted",
            "receipt": {
                "receipt_id": receipt_id,
                "lease_id": lease_id,
                "issued_at": issued_at,
                "signature": signature
            }
        }), 201

    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("CHRONOS database operation failed")

        return jsonify({
            "error": "storage_error"
        }), 500

    finally:
        connection.close()


# -------------------------------------------------------------------
# Step 4: Protected archive.
# Requires two distinct, authentic receipts from this session.
# Deliberately does NOT require distinct lease IDs.
# -------------------------------------------------------------------

@app.post("/api/v1/archive/mission")
def retrieve_mission():
    if not CHRONOS_FLAG:
        return jsonify({
            "error": "challenge_flag_not_configured"
        }), 503

    payload = request.get_json(silent=True) or {}
    receipts = payload.get("receipts")

    if not isinstance(receipts, list) or len(receipts) != 2:
        return jsonify({
            "error": "two_receipts_required"
        }), 400

    receipt_ids = []

    for receipt in receipts:
        if not isinstance(receipt, dict):
            return jsonify({
                "error": "invalid_receipt_format"
            }), 400

        receipt_id = receipt.get("receipt_id")

        if not isinstance(receipt_id, str) or not receipt_id:
            return jsonify({
                "error": "invalid_receipt_id"
            }), 400

        receipt_ids.append(receipt_id)

    if len(set(receipt_ids)) != 2:
        return jsonify({
            "error": "two_distinct_receipt_ids_required"
        }), 400

    session_id = get_session_id()
    connection = get_db()

    try:
        for supplied in receipts:
            row = connection.execute(
                """
                SELECT receipt_id, lease_id, session_id,
                       issued_at, signature
                FROM receipts
                WHERE receipt_id = ? AND session_id = ?
                """,
                (supplied["receipt_id"], session_id)
            ).fetchone()

            if row is None:
                return jsonify({
                    "error": "receipt_not_found_for_session"
                }), 403

            try:
                supplied_time = float(supplied["issued_at"])
            except (KeyError, TypeError, ValueError):
                return jsonify({
                    "error": "invalid_receipt_timestamp"
                }), 400

            supplied_signature = supplied.get("signature")

            expected_signature = sign_receipt(
                row["receipt_id"],
                row["lease_id"],
                row["session_id"],
                row["issued_at"]
            )

            valid = (
                supplied.get("lease_id") == row["lease_id"]
                and abs(supplied_time - row["issued_at"]) < 0.000001
                and isinstance(supplied_signature, str)
                and hmac.compare_digest(
                    supplied_signature,
                    row["signature"]
                )
                and hmac.compare_digest(
                    row["signature"],
                    expected_signature
                )
            )

            if not valid:
                return jsonify({
                    "error": "invalid_receipt"
                }), 403

        # Intentionally do not require the two lease IDs to differ.
        # The CTF exploit should produce two receipts from one lease.
        return jsonify({
            "message": "Chronos archive unlocked",
            "mission": "CLASSIFIED // CHR-05",
            "flag": CHRONOS_FLAG
        }), 200

    finally:
        connection.close()

# Initialize the database before serving requests.
init_db()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        threaded=True
    )
