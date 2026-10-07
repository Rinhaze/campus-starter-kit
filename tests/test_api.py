import sqlite3

import pytest
from fastapi.testclient import TestClient

import main

ADMIN_TOKEN = "test-admin-token"
ADMIN_PASSWORD = "test-admin-password"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """테스트마다 빈 DB와 고정 관리자 자격 증명을 사용한다."""
    monkeypatch.setattr(main, "DB_FILE", str(tmp_path / "test.db"))
    monkeypatch.setattr(main, "ADMIN_MASTER_TOKEN", ADMIN_TOKEN)
    monkeypatch.setattr(main, "ADMIN_PASSWORD", ADMIN_PASSWORD)
    main.ADMIN_SESSIONS.clear()
    main.init_db()
    return TestClient(main.app)


def admin_session(client):
    return client.post("/admin/login", json={"password": ADMIN_PASSWORD}).json()["token"]


# ---------- 기본 CRUD ----------
def test_todo_create_and_list(client):
    res = client.post("/todos", json={"title": "장보기", "description": "우유", "tags": " Home, Work "})
    assert res.status_code == 201
    todo = res.json()
    assert todo["title"] == "장보기"
    assert todo["is_completed"] is False
    assert todo["tags"] == "home,work"
    assert todo["created_at"]

    listed = client.get("/todos").json()
    assert listed["total"] == 1
    assert listed["todos"][0]["id"] == todo["id"]


def test_todo_search_matches_title_and_description(client):
    client.post("/todos", json={"title": "보고서 작성", "description": "월간"})
    client.post("/todos", json={"title": "운동", "description": "보고서 이후"})
    client.post("/todos", json={"title": "독서"})
    titles = [t["title"] for t in client.get("/todos/search", params={"q": "보고서"}).json()["todos"]]
    assert titles == ["보고서 작성", "운동"]


def test_filtered_excludes_blocked_tags_by_exact_match(client):
    client.post("/todos", json={"title": "clean", "tags": "work,adventure"})
    client.post("/todos", json={"title": "spam", "tags": "SPAM"})
    client.post("/todos", json={"title": "secret", "tags": "home,private"})
    titles = [t["title"] for t in client.get("/todos/filtered").json()["todos"]]
    assert titles == ["clean"]


def test_admin_login_and_delete(client):
    todo = client.post("/todos", json={"title": "지울 항목"}).json()
    token = admin_session(client)
    res = client.delete(f"/admin/todos/{todo['id']}", headers={"X-Admin-Token": token})
    assert res.status_code == 200
    assert client.get("/todos").json()["total"] == 0
    assert client.delete(f"/admin/todos/{todo['id']}", headers={"X-Admin-Token": token}).status_code == 404


def test_user_register_login_and_item_flow(client):
    assert client.post("/api/auth/register", json={"username": "alice", "password": "pw-1234"}).status_code == 200
    assert client.post("/api/auth/register", json={"username": "alice", "password": "other"}).status_code == 400
    login = client.post("/api/auth/login", json={"username": "alice", "password": "pw-1234"}).json()
    assert login["user"]["username"] == "alice"
    assert "password_hash" not in login["user"]

    item = client.post("/api/items", json={"title": "50% 할인", "content": "x"}, headers={"X-Auth-Token": login["token"]})
    assert item.status_code == 200
    assert client.get("/api/items", params={"keyword": "%"}).json()["total"] == 1
    assert client.get("/api/items", params={"keyword": "zzz"}).json()["total"] == 0


# ---------- SQL Injection 방어 ----------
@pytest.mark.parametrize("payload", ["' OR '1'='1", "'; DROP TABLE todos; --", "%' OR 1=1 --"])
def test_sql_injection_payloads_are_treated_as_plain_text(client, payload):
    client.post("/todos", json={"title": "정상 항목"})

    assert client.get("/todos/search", params={"q": payload}).json()["total"] == 0
    assert client.get("/api/items", params={"keyword": payload}).json()["total"] == 0
    assert client.post("/api/auth/login", json={"username": payload, "password": payload}).status_code == 401

    # 공격 문자열을 그대로 저장해도 테이블이 유지되고 값도 그대로 남는다
    saved = client.post("/todos", json={"title": payload}).json()
    assert saved["title"] == payload
    assert client.get("/todos").json()["total"] == 2


# ---------- 잘못된 관리자 토큰 거부 ----------
@pytest.mark.parametrize("headers", [{}, {"X-Admin-Token": "wrong"}, {"X-Admin-Token": ADMIN_TOKEN}])
def test_admin_delete_rejects_invalid_token(client, headers):
    todo = client.post("/todos", json={"title": "보호 대상"}).json()
    # ADMIN_TOKEN(아이템 API용 마스터 토큰)도 로그인 세션 토큰이 아니므로 거부
    assert client.delete(f"/admin/todos/{todo['id']}", headers=headers).status_code == 401
    assert client.get("/todos").json()["total"] == 1


def test_admin_login_rejects_wrong_password(client):
    assert client.post("/admin/login", json={"password": "wrong"}).status_code == 401


def test_admin_login_disabled_without_password(client, monkeypatch):
    monkeypatch.setattr(main, "ADMIN_PASSWORD", None)
    assert client.post("/admin/login", json={"password": "anything"}).status_code == 503


def test_admin_session_expires(client, monkeypatch):
    token = admin_session(client)
    main.ADMIN_SESSIONS[token] = 0  # 만료 처리
    todo = client.post("/todos", json={"title": "x"}).json()
    assert client.delete(f"/admin/todos/{todo['id']}", headers={"X-Admin-Token": token}).status_code == 401


@pytest.mark.parametrize("headers", [{}, {"X-Auth-Token": "wrong"}])
def test_create_item_rejects_invalid_master_token(client, headers):
    assert client.post("/api/items", json={"title": "x"}, headers=headers).status_code == 403


# ---------- 유효하지 않은 입력 방어 ----------
@pytest.mark.parametrize("body", [{"title": ""}, {"title": "   "}, {}, {"title": None}])
def test_create_todo_rejects_invalid_title(client, body):
    assert client.post("/todos", json=body).status_code == 422
    assert client.get("/todos").json()["total"] == 0


@pytest.mark.parametrize("params", [{"q": ""}, {"q": "   "}, {}])
def test_search_rejects_empty_keyword(client, params):
    assert client.get("/todos/search", params=params).status_code == 422


# ---------- 보안/성능 유틸 ----------
def test_password_hash_is_salted_and_verifiable():
    first, second = main.hash_credential("pw"), main.hash_credential("pw")
    assert first != second  # 매번 다른 salt
    assert main.verify_credential("pw", first)
    assert not main.verify_credential("nope", first)
    assert not main.verify_credential("pw", "5f4dcc3b5aa765d61d8327deb882cf99")  # 예전 MD5 형식 거부


def test_deduplicate_records_keeps_first_seen_order():
    records = [{"id": 2}, {"id": 1}, {"id": 2, "dup": True}, {"id": 3}, {"id": 1}]
    assert main.deduplicate_records(records) == [{"id": 2}, {"id": 1}, {"id": 3}]


def test_database_uses_wal_mode(client):
    conn = sqlite3.connect(main.DB_FILE)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        conn.close()
