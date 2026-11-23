
import os
import re
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SECRET_KEY = os.environ["SUPABASE_SECRET_KEY"]
ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
ADMIN_PASSWORD_HASH = os.environ["ADMIN_PASSWORD_HASH"]

supabase = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)


def response(message, status=200, **extra):
    return jsonify({"message": message, **extra}), status


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return response("Admin login required", 401)
        return fn(*args, **kwargs)
    return wrapper


def find_license(key):
    result = (
        supabase.table("licenses")
        .select("*")
        .eq("license_key", key)
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


def valid_device(value):
    return (
        isinstance(value, str)
        and 16 <= len(value) <= 200
        and re.fullmatch(r"[A-Za-z0-9._:-]+", value) is not None
    )


@app.get("/")
def home():
    return response("HUZAIFA PRO License Server is running")


@app.get("/health")
def health():
    return response("Healthy")


@app.post("/admin/login")
def admin_login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    if (
        username == ADMIN_USERNAME
        and isinstance(password, str)
        and check_password_hash(ADMIN_PASSWORD_HASH, password)
    ):
        session["admin"] = True
        return response("Admin login successful")

    return response("Invalid credentials", 401)


@app.post("/admin/logout")
@admin_required
def admin_logout():
    session.clear()
    return response("Logged out")


@app.post("/admin/licenses")
@admin_required
def create_license():
    data = request.get_json(silent=True) or {}

    name = str(data.get("customer_name", "")).strip()
    password = data.get("license_password", "")
    amount = data.get("amount", 0)
    days = data.get("days", 30)

    if not name or len(name) > 150:
        return response("Valid customer name required", 400)

    if not isinstance(password, str) or len(password) < 12:
        return response("License password must be at least 12 characters", 400)

    try:
        amount = float(amount)
        days = int(days)
        if amount < 0 or days < 1 or days > 3650:
            raise ValueError()
    except (ValueError, TypeError):
        return response("Invalid amount or duration", 400)

    key = secrets.token_urlsafe(32)
    expiry = datetime.now(timezone.utc) + timedelta(days=days)

    record = {
        "license_key": key,
        "password_hash": generate_password_hash(password),
        "customer_name": name,
        "customer_email": data.get("customer_email"),
        "amount": amount,
        "currency": "PKR",
        "payment_status": "pending",
        "status": "active",
        "expires_at": expiry.isoformat(),
        "max_devices": 1
    }

    result = supabase.table("licenses").insert(record).execute()

    if not result.data:
        return response("Could not create license", 500)

    return jsonify({
        "message": "License created. Mark payment as paid before activation.",
        "license_key": key,
        "customer_name": name,
        "payment_status": "pending",
        "expires_at": expiry.isoformat()
    }), 201


@app.post("/admin/licenses/<key>/payment")
@admin_required
def mark_paid(key):
    license_data = find_license(key)
    if not license_data:
        return response("License not found", 404)

    supabase.table("licenses").update({
        "payment_status": "paid"
    }).eq("license_key", key).execute()

    return response("Payment marked as paid")


@app.post("/admin/licenses/<key>/status")
@admin_required
def change_status(key):
    data = request.get_json(silent=True) or {}
    status = data.get("status")

    if status not in ("active", "suspended", "revoked"):
        return response("Invalid status", 400)

    if not find_license(key):
        return response("License not found", 404)

    supabase.table("licenses").update({
        "status": status
    }).eq("license_key", key).execute()

    return response("License status updated")


@app.post("/admin/licenses/<key>/renew")
@admin_required
def renew_license(key):
    data = request.get_json(silent=True) or {}

    try:
        days = int(data.get("days", 30))
        if days < 1 or days > 3650:
            raise ValueError()
    except (ValueError, TypeError):
        return response("Invalid duration", 400)

    license_data = find_license(key)
    if not license_data:
        return response("License not found", 404)

    current_expiry = datetime.fromisoformat(
        license_data["expires_at"].replace("Z", "+00:00")
    )
    now = datetime.now(timezone.utc)
    base = max(current_expiry, now)
    new_expiry = base + timedelta(days=days)

    supabase.table("licenses").update({
        "expires_at": new_expiry.isoformat(),
        "status": "active"
    }).eq("license_key", key).execute()

    return response("License renewed", expires_at=new_expiry.isoformat())


@app.get("/admin/licenses")
@admin_required
def list_licenses():
    result = (
        supabase.table("licenses")
        .select(
            "id,license_key,customer_name,customer_email,amount,currency,"
            "payment_status,status,expires_at,created_at,activated_at"
        )
        .order("created_at", desc=True)
        .limit(500)
        .execute()
    )
    return jsonify(result.data)


@app.post("/license/activate")
def activate_license():
    data = request.get_json(silent=True) or {}

    key = data.get("license_key", "")
    password = data.get("license_password", "")
    device = data.get("device_fingerprint", "")

    if not valid_device(device):
        return response("Invalid device identifier", 400)

    license_data = find_license(key)

    if not license_data or not check_password_hash(
        license_data["password_hash"], password
    ):
        return response("Invalid license credentials", 401)

    if license_data["payment_status"] != "paid":
        return response("Payment has not been confirmed", 403)

    if license_data["status"] != "active":
        return response("License is not active", 403)

    expiry = datetime.fromisoformat(
        license_data["expires_at"].replace("Z", "+00:00")
    )

    if expiry <= datetime.now(timezone.utc):
        return response("License expired", 403)

    bound_device = license_data.get("device_fingerprint")

    if bound_device and bound_device != device:
        return response("License is already bound to another device", 403)

    if not bound_device:
        update = (
            supabase.table("licenses")
            .update({
                "device_fingerprint": device,
                "activated_at": datetime.now(timezone.utc).isoformat()
            })
            .eq("id", license_data["id"])
            .is_("device_fingerprint", "null")
            .execute()
        )

        if not update.data:
            latest = find_license(key)
            if not latest or latest.get("device_fingerprint") != device:
                return response("Activation conflict. Please retry.", 409)

    return response(
        "License activated",
        expires_at=expiry.isoformat(),
        customer_name=license_data["customer_name"]
    )


@app.post("/license/validate")
def validate_license():
    data = request.get_json(silent=True) or {}

    key = data.get("license_key", "")
    password = data.get("license_password", "")
    device = data.get("device_fingerprint", "")

    if not valid_device(device):
        return response("Invalid device identifier", 400)

    license_data = find_license(key)

    if not license_data or not check_password_hash(
        license_data["password_hash"], password
    ):
        return response("Invalid license credentials", 401)

    if license_data["payment_status"] != "paid":
        return response("Payment not confirmed", 403)

    if license_data["status"] != "active":
        return response("License inactive", 403)

    if license_data.get("device_fingerprint") != device:
        return response("Device mismatch", 403)

    expiry = datetime.fromisoformat(
        license_data["expires_at"].replace("Z", "+00:00")
    )

    if expiry <= datetime.now(timezone.utc):
        return response("License expired", 403)

    return response(
        "License valid",
        customer_name=license_data["customer_name"],
        expires_at=expiry.isoformat()
    )


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("Internal server error")
    return response("Internal server error"), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
