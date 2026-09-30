"""
Minimal AutoQTO account API.

  POST /v1/auth/login          {email, password} -> {token, entitlements}
  GET  /v1/me                  Bearer token -> entitlements
  POST /v1/stripe/webhook      Stripe events
  GET  /v1/credit              Bearer -> {email, balance_usd}
  POST /v1/credit/debit        Bearer {usd,effort,tokens_in,tokens_out}
  POST /v1/credit/checkout     Bearer {pack_id} -> {checkout_url}

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
CREDIT_SUCCESS_URL = os.environ.get(
    "CREDIT_SUCCESS_URL",
    "https://kor-coding.github.io/AutoQTO-account/?credit=ok",
)
CREDIT_CANCEL_URL = os.environ.get(
    "CREDIT_CANCEL_URL",
    "https://kor-coding.github.io/AutoQTO-account/?credit=cancel",
)
# One-time AI packs: pack_id -> USD. Stripe Payment Links should charge the same.
CREDIT_PACKS = {
    "starter": 10.0,
    "studio": 50.0,
    "site": 150.0,
}
# Optional Stripe Price ids if you create Checkout Sessions instead of Payment Links.
CREDIT_PRICE_IDS = {
    "starter": os.environ.get("STRIPE_PRICE_STARTER", ""),
    "studio": os.environ.get("STRIPE_PRICE_STUDIO", ""),
    "site": os.environ.get("STRIPE_PRICE_SITE", ""),
}

stripe.api_key = STRIPE_SECRET_KEY
app = FastAPI(title="AutoQTO accounts")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"ok": True, "service": "autoqto-api"}


@app.get("/v1/health/db")
def health_db():
    try:
        with db() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return {"ok": True, "db": "up"}
    except Exception as exc:
        raise HTTPException(500, f"db: {type(exc).__name__}: {exc}") from exc


def db():
    return psycopg.connect(DATABASE_URL, connect_timeout=10)


_SCHEMA_READY = False


def _ensure_credit_schema(cur) -> None:
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    cur.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS ai_credit_usd numeric(12,4) NOT NULL DEFAULT 0"
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_credit_ledger (
            id            bigserial PRIMARY KEY,
            user_id       uuid,
            email         text,
            kind          text NOT NULL,
            usd           numeric(12,4) NOT NULL,
            effort        text,
            tokens_in     integer,
            tokens_out    integer,
            reason        text,
            stripe_ref    text,
            created_at    timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    _SCHEMA_READY = True


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
    if not stripe_signature:
        raise HTTPException(400, "Missing Stripe-Signature header.")
    try:
        raw_event = stripe.Webhook.construct_event(
            payload, stripe_signature, STRIPE_WEBHOOK_SECRET
        )
    except Exception as exc:
        print(f"webhook signature failed: {type(exc).__name__}: {exc}")
        raise HTTPException(400, f"Bad signature: {exc}") from exc
    event = _as_dict(raw_event)
    etype = event.get("type") or ""
    eid = event.get("id") or ""
    print(f"webhook ok: {etype} {eid}")
    try:
        with db() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO stripe_events (event_id, type) VALUES (%s,%s) "
                "ON CONFLICT DO NOTHING",
                (eid, etype),
            )
            obj = _as_dict((event.get("data") or {}).get("object") or {})
            if etype == "checkout.session.completed":
                _apply_checkout(cur, obj)
                _apply_ai_pack(cur, obj)
            elif etype.startswith("customer.subscription"):
                _apply_subscription(cur, obj)
            elif etype == "payment_intent.succeeded":
                _apply_ai_pack_from_intent(cur, obj)
            conn.commit()
    except Exception as exc:
        import traceback
        traceback.print_exc()
        print(f"webhook handler failed: {type(exc).__name__}: {exc}")
        raise HTTPException(500, f"handler: {type(exc).__name__}: {exc}") from exc
    return {"ok": True}


class RepairIn(BaseModel):
    session_id: str | None = None
    subscription_id: str | None = None


@app.post("/v1/admin/repair")
def repair(body: RepairIn, x_admin_key: str = Header(default="")):
    """Replay a paid Checkout/Subscription into Neon. Header X-Admin-Key = JWT_SECRET."""
    if not x_admin_key or x_admin_key != JWT_SECRET:
        raise HTTPException(401, "Bad admin key.")
    session = None
    sub = None
    if body.session_id:
        session = _as_dict(stripe.checkout.Session.retrieve(body.session_id))
    if body.subscription_id or (session and session.get("subscription")):
        sid = body.subscription_id or _id_of(session.get("subscription"))
        sub = stripe.Subscription.retrieve(sid)
    if session is None and sub is None:
        raise HTTPException(400, "Pass session_id or subscription_id.")
    with db() as conn, conn.cursor() as cur:
        if session:
            _apply_checkout(cur, session)
        elif sub:
            _apply_subscription(cur, sub)
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


def _as_dict(obj):
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    to_dict = getattr(obj, "to_dict_recursive", None) or getattr(obj, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return dict(obj)


def _id_of(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("id")
    return getattr(value, "id", None)


def _apply_checkout(cur, session: dict) -> None:
    session = _as_dict(session)
    if session.get("mode") not in (None, "subscription", "payment"):
        return
    details = _as_dict(session.get("customer_details"))
    email = details.get("email") or session.get("customer_email")
    customer = _id_of(session.get("customer"))
    if not email or not customer:
        print(f"checkout skipped: email={email!r} customer={customer!r}")
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
    sub_id = _id_of(session.get("subscription"))
    if sub_id:
        try:
            sub = stripe.Subscription.retrieve(sub_id)
            _apply_subscription(cur, sub)
        except Exception as exc:
            print(f"retrieve subscription {sub_id} failed: {exc}")
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
    sub = _as_dict(sub)
    customer = _id_of(sub.get("customer"))
    price = None
    qty = 1
    period_end = sub.get("current_period_end")
    period_start = sub.get("current_period_start")
    items = _as_dict(sub.get("items")).get("data") or []
    if items:
        item = _as_dict(items[0])
        price = _id_of(item.get("price"))
        qty = int(item.get("quantity") or 1)
        period_end = period_end or item.get("current_period_end")
        period_start = period_start or item.get("current_period_start")
    cur.execute(
        "SELECT id, is_enterprise, seats_per_purchase FROM plans WHERE stripe_price_id = %s",
        (price,),
    )
    plan = cur.fetchone()
    plan_id = plan[0] if plan else "individual_month"
    is_ent = bool(plan[1]) if plan else False
    pack = int(plan[2]) if plan else 1
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


class SetPasswordIn(BaseModel):
    email: EmailStr | None = None
    password: str
    session_id: str | None = None


@app.get("/v1/auth/checkout/{session_id}")
def checkout_email(session_id: str):
    try:
        session = _as_dict(stripe.checkout.Session.retrieve(session_id))
    except Exception as exc:
        raise HTTPException(404, f"Unknown checkout session: {exc}") from exc
    details = _as_dict(session.get("customer_details"))
    email = (details.get("email") or session.get("customer_email") or "").strip().lower()
    paid = session.get("payment_status") in ("paid", "no_payment_required")
    return {
        "email": email,
        "paid": paid,
        "status": session.get("status"),
        "mode": session.get("mode"),
    }


@app.post("/v1/auth/set-password")
def set_password(body: SetPasswordIn):
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    email = (body.email or "").strip().lower()
    session = None
    if body.session_id:
        try:
            session = _as_dict(stripe.checkout.Session.retrieve(body.session_id))
        except Exception as exc:
            raise HTTPException(400, f"Invalid checkout session: {exc}") from exc
        details = _as_dict(session.get("customer_details"))
        sess_email = (details.get("email") or session.get("customer_email") or "").strip().lower()
        if sess_email:
            email = sess_email
        if session.get("payment_status") not in ("paid", "no_payment_required"):
            raise HTTPException(402, "That checkout is not paid yet.")
        with db() as conn, conn.cursor() as cur:
            _apply_checkout(cur, session)
            conn.commit()
    if not email:
        raise HTTPException(400, "Email is required.")
    pw = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, password_hash FROM users WHERE email_norm = %s",
            (email,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                404,
                "No account for that email yet. Finish checkout first, or open this page from the Stripe confirmation link.",
            )
        if row[1] and not body.session_id:
            raise HTTPException(
                409,
                "Password already set. To reset it, open this page from the purchase confirmation (it includes a session id).",
            )
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (pw, row[0]),
        )
        conn.commit()
    return {"ok": True, "message": "Password saved. Open Auto QTO and sign in with this email."}


# ── AI credit (token wallet) ──────────────────────────────────────────────

class DebitIn(BaseModel):
    usd: float
    effort: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    reason: str | None = None


class CheckoutIn(BaseModel):
    pack_id: str


def _credit_of(cur, user_id) -> tuple[str, float]:
    _ensure_credit_schema(cur)
    cur.execute(
        "SELECT email_norm, COALESCE(ai_credit_usd, 0) FROM users WHERE id = %s",
        (user_id,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Unknown user.")
    return str(row[0] or ""), float(row[1] or 0)


def _add_credit(cur, user_id, email: str, usd: float, kind: str,
                stripe_ref: str = "", reason: str = "") -> float:
    _ensure_credit_schema(cur)
    cur.execute(
        "UPDATE users SET ai_credit_usd = COALESCE(ai_credit_usd, 0) + %s "
        "WHERE id = %s RETURNING ai_credit_usd",
        (usd, user_id),
    )
    row = cur.fetchone()
    bal = float(row[0]) if row else 0.0
    cur.execute(
        """
        INSERT INTO ai_credit_ledger
            (user_id, email, kind, usd, reason, stripe_ref)
        VALUES (%s,%s,%s,%s,%s,%s)
        """,
        (user_id, email, kind, usd, reason, stripe_ref),
    )
    return bal


@app.get("/v1/credit")
def credit_get(user_id: str = Depends(_user_from_bearer)):
    with db() as conn, conn.cursor() as cur:
        email, bal = _credit_of(cur, user_id)
    return {"email": email, "balance_usd": bal}


@app.post("/v1/credit/debit")
def credit_debit(body: DebitIn, user_id: str = Depends(_user_from_bearer)):
    usd = max(0.0, float(body.usd))
    with db() as conn, conn.cursor() as cur:
        _ensure_credit_schema(cur)
        email, bal = _credit_of(cur, user_id)
        if usd > bal + 1e-9:
            return {"ok": False, "balance_usd": bal, "blocked": True}
        cur.execute(
            "UPDATE users SET ai_credit_usd = COALESCE(ai_credit_usd, 0) - %s "
            "WHERE id = %s RETURNING ai_credit_usd",
            (usd, user_id),
        )
        new_bal = float(cur.fetchone()[0])
        cur.execute(
            """
            INSERT INTO ai_credit_ledger
                (user_id, email, kind, usd, effort, tokens_in, tokens_out, reason)
            VALUES (%s,%s,'debit',%s,%s,%s,%s,%s)
            """,
            (user_id, email, -usd, body.effort, body.tokens_in,
             body.tokens_out, body.reason),
        )
        conn.commit()
    return {"ok": True, "balance_usd": new_bal, "blocked": False}


@app.post("/v1/credit/checkout")
def credit_checkout(body: CheckoutIn, user_id: str = Depends(_user_from_bearer)):
    pack_id = (body.pack_id or "").strip().lower()
    if pack_id not in CREDIT_PACKS:
        raise HTTPException(400, "Unknown pack.")
    if not STRIPE_SECRET_KEY:
        raise HTTPException(500, "Stripe is not configured on the API.")
    usd = CREDIT_PACKS[pack_id]
    with db() as conn, conn.cursor() as cur:
        email, _bal = _credit_of(cur, user_id)
    price = CREDIT_PRICE_IDS.get(pack_id) or ""
    kwargs = dict(
        mode="payment",
        customer_email=email,
        client_reference_id=email,
        metadata={"kind": "ai_credit", "pack_id": pack_id, "usd": str(usd)},
        success_url=CREDIT_SUCCESS_URL,
        cancel_url=CREDIT_CANCEL_URL,
    )
    if price:
        kwargs["line_items"] = [{"price": price, "quantity": 1}]
    else:
        kwargs["line_items"] = [{
            "price_data": {
                "currency": "usd",
                "unit_amount": int(round(usd * 100)),
                "product_data": {"name": f"AutoQTO AI credit ({pack_id})"},
            },
            "quantity": 1,
        }]
    session = stripe.checkout.Session.create(**kwargs)
    return {"checkout_url": session.url, "pack_id": pack_id, "usd": usd}


def _user_by_email(cur, email: str):
    email_norm = (email or "").strip().lower()
    if not email_norm:
        return None, ""
    cur.execute("SELECT id FROM users WHERE email_norm = %s", (email_norm,))
    row = cur.fetchone()
    return (row[0] if row else None), email_norm


def _apply_ai_pack(cur, session: dict) -> None:
    session = _as_dict(session)
    meta = _as_dict(session.get("metadata"))
    if (meta.get("kind") or "") != "ai_credit" and session.get("mode") != "payment":
        return
    # Subscriptions already handled; only one-time AI packs.
    if session.get("mode") == "subscription":
        return
    if meta.get("kind") and meta.get("kind") != "ai_credit":
        return
    details = _as_dict(session.get("customer_details"))
    email = (
        details.get("email")
        or session.get("customer_email")
        or session.get("client_reference_id")
        or meta.get("email")
        or ""
    )
    cents = session.get("amount_total")
    usd = float(meta.get("usd") or 0) or (float(cents or 0) / 100.0)
    if usd <= 0:
        print(f"ai pack skipped: usd=0 session={session.get('id')}")
        return
    user_id, email_norm = _user_by_email(cur, email)
    if user_id is None:
        cur.execute(
            """
            INSERT INTO users (email, email_norm, display_name)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (email_norm, email_norm, email_norm.split("@")[0] if email_norm else "buyer"),
        )
        user_id = cur.fetchone()[0]
    _add_credit(
        cur, user_id, email_norm, usd, "stripe",
        stripe_ref=str(session.get("id") or ""),
        reason=f"pack {meta.get('pack_id') or ''}".strip(),
    )
    print(f"ai pack +${usd:.2f} -> {email_norm}")


def _apply_ai_pack_from_intent(cur, intent: dict) -> None:
    intent = _as_dict(intent)
    meta = _as_dict(intent.get("metadata"))
    if meta.get("kind") != "ai_credit":
        return
    email = meta.get("email") or ""
    usd = float(meta.get("usd") or 0) or (float(intent.get("amount") or 0) / 100.0)
    user_id, email_norm = _user_by_email(cur, email)
    if user_id is None or usd <= 0:
        return
    _add_credit(
        cur, user_id, email_norm, usd, "stripe",
        stripe_ref=str(intent.get("id") or ""),
        reason=f"pack {meta.get('pack_id') or ''}".strip(),
    )
