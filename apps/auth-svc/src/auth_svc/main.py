import base64
import ipaddress
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Literal
from urllib.parse import urlsplit

import jwt
import uvicorn
# import uvicorn.logging
from fastapi import FastAPI, HTTPException, Request
from fastapi.datastructures import Headers
from pydantic import IPvAnyAddress

from .config import Jwt, JwtUser, MatchResult, Token, TokenUser, load_config
import os
IP_HEADER = "x-real-ip"
URL_HEADER = "x-original-url"

CONFIG_FILE = os.environ.get("CONFIG_FILE", "acl.yaml")
config = load_config(Path(CONFIG_FILE))


host_lookup = {rule.host: rule.users for rule in config.spec.rules}

def parse_jwt_token(raw_token: str) -> Jwt | None:
    """
    Attempt to parse a raw JWT token.

    Returns a `Jwt` object if parsing is successful, or `None` otherwise.
    """
    try:
        # payload = json.loads(raw_token)
        claims = jwt.decode(raw_token, options={"verify_signature": False})
        return Jwt(**claims)
    except Exception:
        return None


def parse_api_token(raw_token: str) -> Token | None:
    """
    Parses a raw API token.

    The token is expected to be a base64-encoded string with fields
    separated by colons. It attempts to decode the token, extract
    the username and ID, and return a Token object with these values.

    Returns:
        A `Token` object if parsing is successful, or `None` if the
        token is invalid or not properly formatted.
    """
    try:
        # Add surplus padding so we can handle tokens sent without proper padding
        token_data = base64.b64decode(raw_token + "==").decode("utf-8")
        # Split token and return username (first field)
        user, id, _ = token_data.split(":")
        return Token(name=user, id=id)
    except Exception:
        return None


def parse_bearer_token(raw_token: str) -> Token | Jwt | None:
    """
    Parse a bearer token. Returns:
     * a Token if it is plain api token, or
     * a Jwt if it is a JWT token, or
     * None if it is invalid, or not a token at all
    """

    token = parse_api_token(raw_token)
    return token or parse_jwt_token(raw_token)


def parse_url(headers: Headers) -> tuple[str, str] | tuple[None, Literal[""]]:
    """
    Parse the URL from the request header
    """
    url = headers.get(URL_HEADER)
    if not url:
        return None, ""
    parsed_url = urlsplit(url)
    host = parsed_url.netloc
    return host, parsed_url.path


def match_user(
    user: Token | Jwt,
    users: List[TokenUser | JwtUser],
    client_ip: IPvAnyAddress,
) -> bool:
    for user_rule in users:
        if isinstance(user_rule, TokenUser) and isinstance(user, Token):
            match_result = user_rule.match(user, client_ip)
        elif isinstance(user_rule, JwtUser) and isinstance(user, Jwt):
            match_result = user_rule.match(user, client_ip)
        else:
            continue
        match match_result:
            case MatchResult.ALLOW:
                return True
            case MatchResult.DENY:
                return False
            case MatchResult.NOTFOUND:
                continue
    # User was not found in rules, allow access
    return True


class EndpointFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage().find("/healthz") == -1


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger = logging.getLogger("uvicorn.access")
    logger.addFilter(EndpointFilter())
    yield


app = FastAPI(lifespan=lifespan, openapi_url=None)


# Will be used as liveness/readiness probe
@app.get("/healthz")
async def readiness():
    return {"status": "ok"}


@app.get("/auth")
async def auth(request: Request):
    host, path = parse_url(request.headers)
    if not host:
        raise HTTPException(status_code=400, detail=f"Missing {URL_HEADER} header")
    # fast path: pass for unprotected hosts
    if host not in host_lookup.keys():
        return {"status": "Access allowed for all users"}

    # fast path: pass for unprotected paths
    protected = False
    for rule_path in config.spec.protectedPathMatches:
        if rule_path.match(path):
            protected = True

    if not protected:
        return {"status": "Access allowed for all users"}

    # Get the Authorization header and extract the Bearer token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"status": "Unauthenticated access allowed"}

    # Extract the token part from "Bearer <token>"
    bearer_token = auth_header[len("Bearer ") :]

    # Get the original client IP from the header
    client_ip_raw = request.headers.get(IP_HEADER)
    if not client_ip_raw:
        raise HTTPException(status_code=403, detail=f"Missing {IP_HEADER} header")

    client_ip = ipaddress.ip_address(client_ip_raw)

    # Decode the Bearer token, get proper user type and check properties and IP address
    usertoken = parse_bearer_token(bearer_token)
    if not usertoken:
        # Let app handle this error
        return {"status": "Access granted"}
    if not match_user(usertoken, host_lookup[host], client_ip):
        raise HTTPException(status_code=403, detail="Access denied")
    return {"status": "Access granted"}


# Uvicorn entry point to start the service
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)  # pragma: no cover
