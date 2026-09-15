"""
Minimal AutoQTO account API.

  POST /v1/auth/login          {email, password} -> {token, entitlements}
  GET  /v1/me                  Bearer token -> entitlements
  POST /v1/stripe/webhook      Stripe events

Run:
  pip install fastapi uvicorn[standard] psycopg[binary] bcrypt stripe pyjwt
  uvicorn api:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import psycopg
import stripe
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
TOKEN_DAYS = 60

stripe.api_key = STRIPE_SECRET_KEY
app = FastAPI(title="AutoQTO accounts")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def db():
    return psycopg.connect(DATABASE_URL)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


def _entitlements_row(cur, user_id) -> dict | None:
    cur.execute(
        """
        SELECT user_id, email, display_name, org_id, plan_id,
               subscription_status, seat_limit, seats_used,
               current_period_end, is_enterprise, is_paid
        FROM entitlements
        WHERE user_id = %s
        ORDER BY is_paid DESC
        LIMIT 1
        """,
        (user_id,),
    )
    row = cur.fetchone()
    if not row:
        return None
    (uid, email, name, org_id, plan_id, status, seat_limit, seats_used,
     period_end, is_ent, is_paid) = row
    return {
        "valid": bool(is_paid),
        "user_id": str(uid),
        "email": email,
        "display_name": name,
        "org_id": str(org_id) if org_id else None,
        "plan": plan_id,
        "tier": "enterprise" if is_ent and is_paid else ("individual" if is_paid else "free"),
        "is_paid": bool(is_paid),
        "is_enterprise": bool(is_ent and is_paid),
        "status": status,
        "expires_at": period_end.isoformat() if period_end else None,
        "seats": {"used": int(seats_used or 0), "limit": int(seat_limit or 1)},
    }


@app.post("/v1/auth/login")
def login(body: LoginIn):
    email = body.email.strip().lower()
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, password_hash FROM users WHERE email_norm = %s",
            (email,),
        )
        row = cur.fetchone()
        if not row or not row[1]:
            raise HTTPException(401, "Unknown account or password.")
        user_id, pw_hash = row
        if not bcrypt.checkpw(body.password.encode(), pw_hash.encode()):
            raise HTTPException(401, "Unknown account or password.")
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        exp = datetime.now(timezone.utc) + timedelta(days=TOKEN_DAYS)
        cur.execute(
            "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (%s,%s,%s)",
            (user_id, token_hash, exp),
        )
        cur.execute(
            "UPDATE users SET last_login_at = now() WHERE id = %s",
            (user_id,),
        )
        conn.commit()
        ent = _entitlements_row(cur, user_id) or {
            "valid": False,
            "user_id": str(user_id),
            "email": email,
            "is_paid": False,
            "is_enterprise": False,
            "tier": "free",
            "expires_at": None,
        }
    return {"token": token, "expires_at": exp.isoformat(), "entitlements": ent}


def _user_from_bearer(authorization: str = Header(default="")) -> str:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing token.")
    token = authorization.split(" ", 1)[1].strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT user_id FROM sessions
            WHERE token_hash = %s AND expires_at > now()
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(401, "Session expired. Sign in again.")
        return str(row[0])


@app.get("/v1/me")
def me(user_id: str = Depends(_user_from_bearer)):
    with db() as conn, conn.cursor() as cur:
        ent = _entitlements_row(cur, user_id)
    if ent is None:
        return {
            "valid": False,
            "user_id": user_id,
            "is_paid": False,
            "is_enterprise": False,
            "tier": "free",
            "expires_at": None,
        }
    return ent


@app.post("/v1/stripe/webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(default="")):
    payload = await request.body()
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(500, "Webhook secret not configured.")
    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, STRIPE_WEBHOOK_SECRET
        )
    except Exception as exc:
        raise HTTPException(400, f"Bad signature: {exc}") from exc

    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO stripe_events (event_id, type) VALUES (%s,%s) "
            "ON CONFLICT DO NOTHING",
            (event["id"], event["type"]),
        )
        if cur.rowcount == 0:
            return {"ok": True, "duplicate": True}

        obj = event["data"]["object"]
        if event["type"] == "checkout.session.completed":
            _apply_checkout(cur, obj)
        elif event["type"].startswith("customer.subscription"):
            _apply_subscription(cur, obj)
        conn.commit()
    return {"ok": True}


class ClaimIn(BaseModel):
    email: EmailStr
    password: str


@app.post("/v1/auth/claim")
def claim(body: ClaimIn):
    """First-time set password after paying via a Payment Link."""
    email = body.email.strip().lower()
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    pw = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, password_hash FROM users WHERE email_norm = %s",
            (email,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "No account for that email. Pay first, then claim.")
        if row[1]:
            raise HTTPException(409, "Password already set. Sign in instead.")
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (pw, row[0]),
        )
        conn.commit()
    return {"ok": True, "message": "Password set. Sign in on the app with this email."}


def _apply_checkout(cur, session: dict) -> None:
    if session.get("mode") not in (None, "subscription", "payment"):
        return
    email = (session.get("customer_details") or {}).get("email") or session.get("customer_email")
    customer = session.get("customer")
    if not email or not customer:
        return
    email_norm = email.strip().lower()
    cur.execute("SELECT id FROM users WHERE email_norm = %s", (email_norm,))
    row = cur.fetchone()
    if row:
        user_id = row[0]
        cur.execute(
            "UPDATE users SET stripe_customer_id = COALESCE(stripe_customer_id, %s) WHERE id = %s",
            (customer, user_id),
        )
    else:
        cur.execute(
            """
            INSERT INTO users (email, email_norm, display_name, stripe_customer_id)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (email, email_norm, email_norm.split("@")[0], customer),
        )
        user_id = cur.fetchone()[0]
    sub_id = session.get("subscription")
    if sub_id:
        try:
            sub = stripe.Subscription.retrieve(sub_id)
            _apply_subscription(cur, sub)
        except Exception:
            pass
    cur.execute(
        "SELECT id FROM organizations WHERE stripe_customer_id = %s",
        (customer,),
    )
    org = cur.fetchone()
    if org:
        cur.execute(
            """
            INSERT INTO memberships (org_id, user_id, role)
            VALUES (%s, %s, 'owner')
            ON CONFLICT DO NOTHING
            """,
            (org[0], user_id),
        )


def _apply_subscription(cur, sub: dict) -> None:
    customer = sub.get("customer")
    price = None
    qty = 1
    items = (sub.get("items") or {}).get("data") or []
    if items:
        price = (items[0].get("price") or {}).get("id")
        qty = int(items[0].get("quantity") or 1)
    cur.execute(
        "SELECT id, is_enterprise, seats_per_purchase FROM plans WHERE stripe_price_id = %s",
        (price,),
    )
    plan = cur.fetchone()
    plan_id = plan[0] if plan else "individual_month"
    is_ent = bool(plan[1]) if plan else False
    pack = int(plan[2]) if plan else 1
    period_end = sub.get("current_period_end")
    period_start = sub.get("current_period_start")
    end_ts = datetime.fromtimestamp(period_end, tz=timezone.utc) if period_end else None
    start_ts = datetime.fromtimestamp(period_start, tz=timezone.utc) if period_start else None
    status = sub.get("status") or "none"
    # Enterprise Stripe quantity = number of 10-seat packs.
    seat_limit = (qty * pack) if is_ent else 1

    cur.execute(
        "SELECT id FROM organizations WHERE stripe_customer_id = %s "
        "OR stripe_subscription_id = %s",
        (customer, sub.get("id")),
    )
    row = cur.fetchone()
    if row:
        cur.execute(
            """
            UPDATE organizations SET
                plan_id = %s,
                seat_limit = %s,
                stripe_customer_id = %s,
                stripe_subscription_id = %s,
                status = %s,
                current_period_start = %s,
                current_period_end = %s,
                cancel_at_period_end = %s,
                updated_at = now()
            WHERE id = %s
            """,
            (plan_id, seat_limit, customer, sub.get("id"), status,
             start_ts, end_ts, bool(sub.get("cancel_at_period_end")), row[0]),
        )
    else:
        cur.execute(
            """
            INSERT INTO organizations
                (name, plan_id, seat_limit, stripe_customer_id,
                 stripe_subscription_id, status, current_period_start,
                 current_period_end)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            ("Stripe customer", plan_id, seat_limit, customer,
             sub.get("id"), status, start_ts, end_ts),
        )
