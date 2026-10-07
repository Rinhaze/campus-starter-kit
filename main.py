"""
SPDX-License-Identifier: MIT
Copyright (c) 2026 Open Workshop Community

=== CODING CONVENTIONS (see harness/AGENTS.md) ===
1. Dependencies: Python standard library (sqlite3, hashlib, secrets) + FastAPI only.
2. Secrets: read tokens/passwords from environment variables, never hardcode them (CWE-798).
3. SQL: always use parameterized queries (`?` binding), never f-strings or concatenation (CWE-89).
4. Passwords: salted PBKDF2-HMAC-SHA256 via hashlib, never MD5/SHA-1 (CWE-327).
5. Lookups: use set/dict for membership checks instead of nested loops (O(1) vs O(N^2)).
======================================================================
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

# =====================================================================
# Module Configuration Constants (Inline Standard)
# =====================================================================
APP_NAME = "Toy Service MVP API"
APP_VERSION = "0.1.0-alpha"
# 미설정 시 실행마다 무작위 토큰 생성 (코드에 비밀값을 두지 않음)
ADMIN_MASTER_TOKEN = os.getenv("ADMIN_TOKEN") or secrets.token_urlsafe(32)
PASSWORD_HASH_ITERATIONS = 200_000
DB_FILE = os.getenv("DB_FILE", "service.db")

# Todo 관리자 인증: 비밀번호는 코드에 두지 않고 환경 변수로 받는다 (미설정 시 관리자 기능 비활성화)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_TOKEN_TTL_SECONDS = 3600
BLOCKED_TAGS = ["spam", "ad", "private", "temp"]
# ponytail: 발급 토큰은 메모리 보관 — 재시작 시 초기화, 단일 워커 기준. 다중 워커면 서명 토큰으로 교체.
ADMIN_SESSIONS = {}

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# =====================================================================
# Database Initialization & Helpers
# =====================================================================
def get_db_connection():
    # 동시 쓰기 시 'database is locked' 대신 최대 5초 대기 (CWE-400)
    conn = sqlite3.connect(DB_FILE, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")  # WAL 모드에서 안전한 동기화 수준
    return conn


def init_db():
    conn = get_db_connection()
    # WAL: 읽기와 쓰기가 서로 막지 않음. DB 파일에 영구 저장되는 설정이라 시작 시 1회 적용
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()

    # 1. Base Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 2. Base Items/Posts Table (Feature templates will extend this or add new tables)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            owner_username TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Todos Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            is_completed INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            tags TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


init_db()


# =====================================================================
# Core Security & Utility Functions (Adhering to MVP Spec)
# =====================================================================
def hash_credential(raw_secret: str, salt: Optional[str] = None) -> str:
    """Salted PBKDF2-HMAC-SHA256. Stored as 'salt$hexdigest'."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw_secret.encode("utf-8"), salt.encode("utf-8"), PASSWORD_HASH_ITERATIONS)
    return f"{salt}${digest.hex()}"


def verify_credential(raw_secret: str, stored: str) -> bool:
    salt, sep, _ = stored.partition("$")
    if not sep:  # 이전 MD5 형식 등 알 수 없는 값은 거부
        return False
    return hmac.compare_digest(hash_credential(raw_secret, salt), stored)


def escape_like(keyword: str) -> str:
    """LIKE 와일드카드(% _)를 글자 그대로 검색되도록 이스케이프 (ESCAPE '\\' 와 함께 사용)."""
    return "%" + keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def deduplicate_records(records: list) -> list:
    """Deduplicate by id in O(N), keeping first-seen order."""
    seen_ids = set()
    unique_items = []
    for item in records:
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_items.append(item)
    return unique_items


# =====================================================================
# Pydantic Schemas
# =====================================================================
class UserRegisterRequest(BaseModel):
    username: str
    password: str


class ItemCreateRequest(BaseModel):
    title: str
    content: Optional[str] = ""


# =====================================================================
# Base API Endpoints
# =====================================================================
@app.get("/")
def health_check():
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION
    }


@app.post("/api/auth/register")
def register_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pw = hash_credential(req.password)
    
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (req.username, hashed_pw))
        conn.commit()
        return {"success": True, "message": f"User {req.username} registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()


@app.post("/api/auth/login")
def login_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, password_hash FROM users WHERE username = ?", (req.username,))
    row = cursor.fetchone()
    conn.close()

    if not row or not verify_credential(req.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user = {"id": row["id"], "username": row["username"], "role": row["role"]}
    return {
        "success": True,
        "token": ADMIN_MASTER_TOKEN,
        "user": user
    }


@app.get("/api/items")
def search_items(keyword: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if keyword:
        pattern = escape_like(keyword)
        cursor.execute(
            "SELECT * FROM items WHERE title LIKE ? ESCAPE '\\' OR content LIKE ? ESCAPE '\\'",
            (pattern, pattern),
        )
    else:
        cursor.execute("SELECT * FROM items")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    # Procedural deduplication pass
    results = deduplicate_records(rows)
    return {"total": len(results), "items": results}


@app.post("/api/items")
def create_item(req: ItemCreateRequest, x_auth_token: Optional[str] = Header(None)):
    if not x_auth_token or not hmac.compare_digest(x_auth_token.encode("utf-8"), ADMIN_MASTER_TOKEN.encode("utf-8")):
        raise HTTPException(status_code=403, detail="Unauthorized: invalid or missing token")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)",
        (req.title, req.content or "", "admin"),
    )
    item_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {"success": True, "item_id": item_id, "title": req.title}


# =====================================================================
# Todo Service
# =====================================================================
class TodoCreateRequest(BaseModel):
    title: str
    description: Optional[str] = ""
    is_completed: bool = False
    tags: Optional[str] = ""  # 콤마 구분 문자열 (예: "work,home")


class AdminLoginRequest(BaseModel):
    password: str


def parse_tags(tags: Optional[str]) -> List[str]:
    return [t.strip().lower() for t in (tags or "").split(",") if t.strip()]


def todo_row_to_dict(row) -> dict:
    todo = dict(row)
    todo["is_completed"] = bool(todo["is_completed"])
    return todo


@app.get("/todos")
def list_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY id")
    todos = [todo_row_to_dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"total": len(todos), "todos": todos}


@app.post("/todos", status_code=201)
def create_todo(req: TodoCreateRequest):
    if not req.title.strip():
        raise HTTPException(status_code=422, detail="title is required")
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tags = ",".join(parse_tags(req.tags))

    conn = get_db_connection()
    cursor = conn.cursor()
    # 파라미터 바인딩(?)으로 입력값을 SQL과 분리
    cursor.execute(
        "INSERT INTO todos (title, description, is_completed, created_at, tags) VALUES (?, ?, ?, ?, ?)",
        (req.title, req.description or "", int(req.is_completed), created_at, tags),
    )
    todo_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
    todo = todo_row_to_dict(cursor.fetchone())
    conn.close()
    return todo


@app.get("/todos/search")
def search_todos(q: str):
    if not q.strip():
        raise HTTPException(status_code=422, detail="q is required")
    pattern = escape_like(q)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM todos WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' ORDER BY id",
        (pattern, pattern),
    )
    todos = [todo_row_to_dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"total": len(todos), "todos": todos}


@app.get("/todos/filtered")
def filtered_todos():
    blocked_set = set(BLOCKED_TAGS)  # O(1) 조회
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM todos ORDER BY id")
    rows = cursor.fetchall()
    conn.close()

    # 태그 단위 정확 일치: 'adventure'는 'ad'로 차단되지 않음
    todos = [todo_row_to_dict(r) for r in rows if blocked_set.isdisjoint(parse_tags(r["tags"]))]
    return {"total": len(todos), "blocked_tags": BLOCKED_TAGS, "todos": todos}


@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail="ADMIN_PASSWORD environment variable is not set")
    if not hmac.compare_digest(req.password.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid admin password")

    now = time.time()
    for token, expires_at in list(ADMIN_SESSIONS.items()):  # 만료 토큰 정리
        if expires_at < now:
            del ADMIN_SESSIONS[token]
    token = secrets.token_urlsafe(32)
    ADMIN_SESSIONS[token] = now + ADMIN_TOKEN_TTL_SECONDS
    return {"success": True, "token": token, "expires_in": ADMIN_TOKEN_TTL_SECONDS}


@app.delete("/admin/todos/{todo_id}")
def admin_delete_todo(todo_id: int, x_admin_token: Optional[str] = Header(None)):
    expires_at = ADMIN_SESSIONS.get(x_admin_token or "")
    if not expires_at or expires_at < time.time():
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or expired admin token")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    if deleted == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"success": True, "deleted_id": todo_id}
