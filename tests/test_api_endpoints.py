"""
AuthGuard Test Suite: End-to-End API Workflows
==============================================
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.base import init_db


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_check_endpoint(client):
    res = client.get("/api/admin/health")
    assert res.status_code in (200, 401)


def test_user_registration_and_login_flow(client):
    reg_payload = {
        "username": "tester_security_user",
        "email": "tester@example.com",
        "password": "SecureTestPassword123!",
        "role": "auditor",
    }
    # Register
    res_reg = client.post("/api/auth/register", json=reg_payload)
    assert res_reg.status_code in (200, 400)  # 400 if already exists

    # Login
    login_payload = {
        "username": "tester_security_user",
        "password": "SecureTestPassword123!",
    }
    res_login = client.post("/api/auth/login", json=login_payload)
    assert res_login.status_code == 200
    assert "authguard_session" in res_login.cookies


def test_dashboard_stats_endpoint(client):
    # Login as seeded admin
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "AdminPass123!"})
    assert login_res.status_code == 200

    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "assessments" in data
    assert "findings" in data
    assert "module_coverage" in data


def test_target_creation_and_listing(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "AdminPass123!"})

    target_payload = {
        "name": "Staging Auth Cluster",
        "base_url": "http://127.0.0.1:8001",
        "approved_hostnames": ["127.0.0.1"],
        "permitted_endpoints": ["/login", "/verify-otp"],
        "authorization_proof": "TEST_SIGNED_TICKET_999",
    }
    res = client.post("/api/targets", json=target_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["hostname"] == "127.0.0.1"

    # List targets
    res_list = client.get("/api/targets")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1
