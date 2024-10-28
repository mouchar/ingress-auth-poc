from fastapi.testclient import TestClient

import base64
import os
import pytest

# Initialize the FastAPI test client
# client = TestClient(app)
os.environ["CONFIG_FILE"] = "src/acl.yaml"

@pytest.fixture(name="client")
def get_client():
    from auth_svc.main import app

    client = TestClient(app)
    return client


# Utility function to create a valid Bearer token
def create_bearer_token(username: str, id: str = "b", secret: str = "c"):
    token = f"{username}:{id}:{secret}"
    return "Bearer " + base64.b64encode(token.encode("utf-8")).decode("utf-8")

# Test for a valid username and valid IP (should return 200)
def test_auth_api_token_success(client: TestClient):
    token = create_bearer_token("twoips")
    headers = {
        "Authorization": token,
        "x-real-ip": "1.2.3.4",
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access granted"}

# Test for a valid username but an IP outside allowed CIDRs (should return 403)
def test_auth_ip_unauthorized(client: TestClient):
    token = create_bearer_token("twoips")
    headers = {
        "Authorization": token,
        "x-real-ip": "8.8.8.8",  # Not in 1.2.3.0/24 or 10.0.0.0/8
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied"}

# Test for a valid token but missing the `x-real-ip` header (should return 403)
def test_auth_missing_ip_header(client: TestClient):
    token = create_bearer_token("user1")
    headers = {
        "Authorization": token,
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Missing x-real-ip header"}

# Test for missing or invalid Authorization header (should return 403)
def test_auth_missing_authorization_header(client: TestClient):
    headers = {
        "x-real-ip": "1.2.3.4",
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Unauthenticated access allowed"}

# Test for an invalid bearer token (bad base64 format) (should return 200)
def test_auth_invalid_token_format(client: TestClient):
    headers = {
        "Authorization": "Bearer badtoken==",
        "x-real-ip": "1.2.3.4",
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access granted"}

# Test for a valid token but username not found in config (should return 200)
def test_auth_username_not_found(client: TestClient):
    token = create_bearer_token("unknown_user")
    headers = {
        "Authorization": token,
        "x-real-ip": "1.2.3.4",
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access granted"}

# Test for unprotected path (should return 200)
def test_auth_unprotected_path(client: TestClient):
    headers = {
        "x-original-url": "https://www.example.com/unprotected/path",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access allowed for all users"}

# Test if any user can access unprotected path with token from different IP (should return 200)
def test_auth_unprotected(client: TestClient):
    token = create_bearer_token("twoips")  # restricted user
    headers = {
        "Authorization": token,
        "x-real-ip": "9.9.9.9",  # not allowed IP
        "x-original-url": "https://www.example.com/unprotected/path",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access allowed for all users"}

# Test for unprotected host (should return 200)
def test_auth_unprotected_host(client: TestClient):
    headers = {
        "x-original-url": "https://www.unprotected.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access allowed for all users"}

# Test if user with limited token id can access protected path (should return 200)
def test_auth_limited_token_id(client: TestClient):
    token = create_bearer_token("specific", "important")
    headers = {
        "Authorization": token,
        "x-real-ip": "1.2.3.4",
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access granted"}

# Test if user with limited token id can not access protected path (should return 403)
def test_auth_limited_token_id_wrong_ip(client: TestClient):
    token = create_bearer_token("specific", "important")
    headers = {
        "Authorization": token,
        "x-real-ip": "9.9.9.9",
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied"}

# Test if user with limited token id and different token id can access protected path (should return 200)
def test_auth_limited_token_id_different(client: TestClient):
    token = create_bearer_token("specific", "another")
    headers = {
        "Authorization": token,
        "x-real-ip": "1.2.3.4",
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access granted"}

# Test if user with JWT token containing allowed sub claims can access protected path from correct IP (should return 200)
def test_auth_jwt_token_allowed_ip(client: TestClient):
    # { "sub": "jwtuser@example.com", "name": "JWT User", "iat": 1516239022 }
    token = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqd3R1c2VyQGV4YW1wbGUuY29tIiwibmFtZSI6I" +
            "kpXVCBVc2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.WvoX-QNkLIeIAzbNMWEtOY2zjh673zZT2mB1IldwRXA")
    headers = {
        "Authorization": "Bearer " + token,
        "x-real-ip": "6.7.8.4",
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    print(response.json())
    assert response.status_code == 200
    assert response.json() == {"status": "Access granted"}

# Test if user with JWT token containing allowed sub claims can't access protected path from wrong IP (should return 403)
def test_auth_jwt_token_wrong_ip(client: TestClient):
    # { "sub": "jwtuser@example.com", "name": "JWT User", "iat": 1516239022 }
    token = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqd3R1c2VyQGV4YW1wbGUuY29tIiwibmFtZSI6I" +
             "kpXVCBVc2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.WvoX-QNkLIeIAzbNMWEtOY2zjh673zZT2mB1IldwRXA")
    headers = {
        "Authorization": "Bearer " + token,
        "x-real-ip": "1.1.1.1", # not allowed IP
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied"}

# Test if user with invalid JWT token can't access protected path from correct IP (should return 200)
def test_auth_jwt_invalid_token(client: TestClient):
    # { "dummy": "invalid@example.com", "name": "JWT User", "iat": 1516239022 }
    token  = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkdW1teSI6Imp3dHVzZXJAZXhhbXBsZS5jb20iLCJuYW1l" +
              "IjoiSldUIFVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.97-yTEuyU8AO1csl-Owi_BIBxnia6q3W9I9X-WmZCcU")
    headers = {
        "Authorization": "Bearer " + token,
        "x-real-ip": "1.1.1.1", # not allowed IP
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access granted"}

# Test if user with valid JWT token but unknown sub claim can access protected path (should return 200)
def test_auth_jwt_token_unknown_sub(client: TestClient):
    # { "sub": "jwtuser@example.com", "name": "JWT User", "iat": 1516239022 }
    token = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpbnZhbGlkQGV4YW1wbGUuY29tIiwibmFtZSI6I" +
             "kpXVCBVc2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.zt8zGCuHbKRY-UEJxlmkRbKSVCf6AzZO4m2wbC9WfAU")
    headers = {
        "Authorization": "Bearer " + token,
        "x-real-ip": "1.1.1.1", # not allowed IP
        "x-original-url": "https://www.example.com/api/test",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access granted"}

# Test for missing x-original-url header
def test_auth_missing_original_url(client: TestClient):
    token = create_bearer_token("user1")
    headers = {
        "Authorization": token,
        "x-real-ip": "1.2.3.4",
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 400
    assert response.json() == {"detail": "Missing x-original-url header"}

# Test for /healthz endpoint
def test_healthz(client: TestClient):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}