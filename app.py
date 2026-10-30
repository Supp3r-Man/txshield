"""TxShield API. Local only: `uvicorn app:app --port 8000`."""
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import engine
import policy as pol

ROOT = Path(__file__).parent
DB = ROOT / "txshield.db"
COOKIE = "txs_session"
TTL = 8 * 3600
USER_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
ph = PasswordHasher()
DUMMY = ph.hash("not-a-real-password")  # so unknown usernames cost the same as wrong passwords
HITS = {}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS policies (
  user_id INTEGER PRIMARY KEY REFERENCES users(id), body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), created_at INTEGER NOT NULL,
  verdict TEXT NOT NULL, title TEXT NOT NULL, result TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS analyses_user ON analyses(user_id, id DESC);
"""


def q(sql, args=(), one=False):
    con = sqlite3.connect(DB)
    try:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        cur = con.execute(sql, args)
        rows = cur.fetchone() if one else cur.fetchall()
        con.commit()
        return rows
    finally:
        con.close()


_con = sqlite3.connect(DB)
_con.executescript(SCHEMA)
_con.close()

app = FastAPI(title="TxShield", docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    r = await call_next(request)
    r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api"):
        r.headers["Cache-Control"] = "no-store"
    return r


# ---------- auth plumbing ----------

def limit(request: Request, n=8, per=60):
    key = request.client.host if request.client else "?"
    now = time.time()
    hits = [t for t in HITS.get(key, []) if now - t < per]
    if len(hits) >= n:
        raise HTTPException(429, "Too many attempts. Wait a minute.")
    HITS[key] = hits + [now]


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def auth(request: Request):
    token = request.cookies.get(COOKIE)
    row = q("SELECT s.user_id, s.csrf, s.expires_at, u.username FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ?", (sha(token),), one=True) if token else None
    if not row or row["expires_at"] < time.time():
        raise HTTPException(401, "Not signed in.")
    return row


def auth_write(request: Request):
    user = auth(request)
    sent = request.headers.get("x-csrf-token", "").encode()
    if not hmac.compare_digest(sent, user["csrf"].encode()):
        raise HTTPException(403, "Bad CSRF token.")
    return user


def start_session(uid, username):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    q("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
    q("INSERT INTO sessions(token_hash, user_id, csrf, expires_at) VALUES(?, ?, ?, ?)",
      (sha(token), uid, csrf, int(time.time()) + TTL))
    r = JSONResponse({"username": username, "csrf": csrf})
    r.set_cookie(COOKIE, token, httponly=True, samesite="strict", max_age=TTL, path="/")
    return r


class Creds(BaseModel):
    username: str
    password: str


def check_creds(c: Creds):
    if not USER_RE.match(c.username):
        raise HTTPException(422, "Username: 3-32 letters, numbers or underscores.")
    if not 10 <= len(c.password) <= 128:
        raise HTTPException(422, "Password: 10-128 characters.")


@app.post("/api/register")
def register(c: Creds, request: Request):
    limit(request)
    check_creds(c)
    try:
        q("INSERT INTO users(username, pw_hash, created_at) VALUES(?, ?, ?)", (c.username, ph.hash(c.password), int(time.time())))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That username is taken.")
    row = q("SELECT id FROM users WHERE username = ?", (c.username,), one=True)
    return start_session(row["id"], c.username)


@app.post("/api/login")
def login(c: Creds, request: Request):
    limit(request)
    check_creds(c)
    row = q("SELECT id, pw_hash FROM users WHERE username = ?", (c.username,), one=True)
    try:
        ph.verify(row["pw_hash"] if row else DUMMY, c.password)
        ok = row is not None
    except (VerificationError, InvalidHashError):
        ok = False
    if not ok:
        raise HTTPException(401, "Wrong username or password.")
    return start_session(row["id"], c.username)


@app.post("/api/logout")
def logout(request: Request, user=Depends(auth_write)):
    q("DELETE FROM sessions WHERE user_id = ?", (user["user_id"],))
    r = JSONResponse({"ok": True})
    r.delete_cookie(COOKIE, path="/")
    return r


@app.get("/api/me")
def me(user=Depends(auth)):
    return {"username": user["username"], "csrf": user["csrf"]}


# ---------- product ----------

def user_policy(uid):
    row = q("SELECT body FROM policies WHERE user_id = ?", (uid,), one=True)
    return json.loads(row["body"]) if row else pol.default()


class AnalyzeIn(BaseModel):
    text: str


@app.get("/api/fixtures")
def fixtures(user=Depends(auth)):
    return [{"id": f["id"], "label": f["label"], "category": f["category"], "title": f["title"],
             "payload": engine.payload_of(f)} for f in engine.FIXTURES]


@app.post("/api/analyze")
def analyze_route(body: AnalyzeIn, user=Depends(auth_write)):
    if len(body.text) > 20000:
        raise HTTPException(422, "Input is too long (20,000 characters max).")
    try:
        payload = json.loads(body.text)
    except (ValueError, RecursionError):
        raise HTTPException(400, "That isn't valid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(400, "Expected a JSON object.")
    try:
        res = engine.analyze(payload, engine.CTX, user_policy(user["user_id"]))
    except ValueError as e:
        raise HTTPException(400, str(e))
    uid = user["user_id"]
    q("INSERT INTO analyses(user_id, created_at, verdict, title, result) VALUES(?, ?, ?, ?, ?)",
      (uid, int(time.time()), res["verdict"], res["summary"][0][:140], json.dumps(res)))
    q("DELETE FROM analyses WHERE user_id = ? AND id NOT IN "
      "(SELECT id FROM analyses WHERE user_id = ? ORDER BY id DESC LIMIT 200)", (uid, uid))
    return res


@app.get("/api/history")
def history(user=Depends(auth)):
    rows = q("SELECT id, created_at, verdict, title FROM analyses WHERE user_id = ? ORDER BY id DESC LIMIT 100", (user["user_id"],))
    return [dict(r) for r in rows]


@app.get("/api/history/{aid}")
def history_one(aid: int, user=Depends(auth)):
    row = q("SELECT result FROM analyses WHERE id = ? AND user_id = ?", (aid, user["user_id"]), one=True)
    if not row:
        raise HTTPException(404, "No such entry.")
    return json.loads(row["result"])


@app.delete("/api/history")
def clear_history(user=Depends(auth_write)):
    q("DELETE FROM analyses WHERE user_id = ?", (user["user_id"],))
    return {"ok": True}


@app.get("/api/policy")
def get_policy(user=Depends(auth)):
    return {"policy": user_policy(user["user_id"]), "meta": pol.meta()}


@app.put("/api/policy")
def put_policy(body: dict, user=Depends(auth_write)):
    try:
        clean = pol.validate(body)
    except ValueError as e:
        raise HTTPException(422, str(e))
    q("INSERT INTO policies(user_id, body) VALUES(?, ?) ON CONFLICT(user_id) DO UPDATE SET body = excluded.body",
      (user["user_id"], json.dumps(clean)))
    return {"policy": clean}


@app.post("/api/policy/reset")
def reset_policy(user=Depends(auth_write)):
    q("DELETE FROM policies WHERE user_id = ?", (user["user_id"],))
    return {"policy": pol.default()}


app.mount("/", StaticFiles(directory=ROOT / "static", html=True), name="static")
