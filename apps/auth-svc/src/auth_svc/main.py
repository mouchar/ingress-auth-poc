from fastapi import FastAPI, Request, HTTPException
import base64
import logging
import yaml
import ipaddress

IP_HEADER = "x-real-ip"

app = FastAPI()

# Load ACL file into memory
with open("acl.yaml", "r") as f:
    acl_data = yaml.safe_load(f)

def decode_bearer_token(token: str):
    # Remove "Bearer " prefix and decode token
    try:
        # Add surplus padding so we can handle tokens sent without proper padding
        token_data = base64.b64decode(token + "==").decode('utf-8')
        # Split token and return username (first field)
        return token_data.split(":")[0]
    except Exception:
        return None

def check_ip_in_cidr(client_ip: str, cidr_list: list) -> bool:
    # Check if the client IP belongs to any CIDR range in the list
    for cidr in cidr_list:
        if ipaddress.ip_address(client_ip) in ipaddress.ip_network(cidr):
            return True
    return False

# Will be used as liveness/readiness probe
@app.get("/healthz")
async def readiness():
    return {"status": "ok"}

@app.get("/auth")
async def auth(request: Request):
    # log headers to console
    print(request.headers)
    # 1. Get the Authorization header and extract the Bearer token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid or missing Authorization header")

    # Extract the token part from "Bearer <token>"
    bearer_token = auth_header[len("Bearer "):]

    # 2. Decode the Bearer token and extract the username
    username = decode_bearer_token(bearer_token)
    if not username or username not in acl_data:
        raise HTTPException(status_code=401, detail="Invalid token or username not found")

    # 3. Get the original client IP from the header
    client_ip = request.headers.get(IP_HEADER)
    if not client_ip:
        raise HTTPException(status_code=401, detail=f"Missing {IP_HEADER} header")

    # 4. Lookup the username in acl.yaml and check the IP against allowed CIDRs
    allowed_cidrs = acl_data.get(username, [])
    if check_ip_in_cidr(client_ip, allowed_cidrs):
        # 5. If the client IP matches one of the allowed CIDRs, return 200
        return {"status": "Access granted"}
    else:
        # If no CIDR matches, deny access
        raise HTTPException(status_code=401, detail="Access denied")

class EndpointFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage().find("/healthz") == -1

# Filter out /healthz endpoint from logs
logging.getLogger("uvicorn.access").addFilter(EndpointFilter())

# Uvicorn entry point to start the service
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
