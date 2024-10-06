from fastapi.testclient import TestClient
from auth_svc.main import app
import base64

# Initialize the FastAPI test client
client = TestClient(app)

# Sample ACL data for tests
acl_data = {
    "user1": ["1.2.3.0/24", "10.0.0.0/8"],
    "user2": ["192.168.0.0/20"],
    "user3": []
}

# Utility function to create a valid Bearer token
def create_bearer_token(username: str):
    token = f"{username}:b:c"
    return "Bearer " + base64.b64encode(token.encode("utf-8")).decode("utf-8")

# Test for a valid username and valid IP (should return 200)
def test_auth_success():
    token = create_bearer_token("user1")
    headers = {
        "Authorization": token,
        "x-real-ip": "1.2.3.4"
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "Access granted"}

# Test for a valid username but an IP outside allowed CIDRs (should return 401)
def test_auth_ip_unauthorized():
    token = create_bearer_token("user1")
    headers = {
        "Authorization": token,
        "x-real-ip": "8.8.8.8"  # Not in 1.2.3.0/24 or 10.0.0.0/8
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Access denied"}

# Test for a valid token but missing the `x-real-ip` header (should return 401)
def test_auth_missing_ip_header():
    token = create_bearer_token("user1")
    headers = {
        "Authorization": token
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Missing x-real-ip header"}

# Test for missing or invalid Authorization header (should return 401)
def test_auth_missing_authorization_header():
    headers = {
        "x-real-ip": "1.2.3.4"
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing Authorization header"}

# Test for an invalid bearer token (bad base64 format) (should return 401)
def test_auth_invalid_token_format():
    headers = {
        "Authorization": "Bearer badtoken==",
        "x-real-ip": "1.2.3.4"
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token or username not found"}

# Test for a valid token but username not found in acl.yaml (should return 401)
def test_auth_username_not_found():
    token = create_bearer_token("invalid_user")
    headers = {
        "Authorization": token,
        "x-real-ip": "1.2.3.4"
    }
    response = client.get("/auth", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token or username not found"}
