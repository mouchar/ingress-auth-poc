from __future__ import annotations
from enum import Enum
import ipaddress
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, IPvAnyAddress, IPvAnyNetwork
import yaml

class MatchResult(Enum):
    ALLOW = 0
    DENY = 1
    NOTFOUND = 2

class Token(BaseModel):
    name: str
    id: Optional[str] = None

    def match(self, token: Token) -> MatchResult:
        if self.name != token.name:
            return MatchResult.NOTFOUND
        if self.id is not None and self.id != token.id:
            return MatchResult.NOTFOUND
        else:
            return MatchResult.ALLOW

class Jwt(BaseModel):
    sub: str

    def match(self, token: Jwt) -> MatchResult:
        return MatchResult.ALLOW if self.sub == token.sub else MatchResult.NOTFOUND

class TokenUser(BaseModel):
    cidrs: List[IPvAnyNetwork]
    token: Token

    def match(self, checked: Token, client_ip: IPvAnyAddress) -> MatchResult:
        token_match = self.token.match(checked)
        if token_match == MatchResult.NOTFOUND:
            return MatchResult.NOTFOUND

        # Check if checked user IP is in the user's CIDR list
        for cidr in self.cidrs:
            if client_ip in ipaddress.ip_network(cidr):
                return MatchResult.ALLOW
        return MatchResult.DENY

class JwtUser(BaseModel):
    cidrs: List[IPvAnyNetwork]
    jwt: Jwt

    def match(self, checked: Jwt, client_ip: IPvAnyAddress) -> MatchResult:
        if self.jwt.match(checked) == MatchResult.NOTFOUND:
            return MatchResult.NOTFOUND

        # Check if checked user IP is in the user's CIDR list
        for cidr in self.cidrs:
            if client_ip in ipaddress.ip_network(cidr):
                return MatchResult.ALLOW
        return MatchResult.DENY

class Rule(BaseModel):
    host: str
    users: List[TokenUser|JwtUser]

class Spec(BaseModel):
    protectedPrefixes: List[str]
    rules: List[Rule]

class ConfigV1(BaseModel):
    apiVersion: int = 1
    spec: Spec

def load_config(config_file: Path) -> ConfigV1:
    with open(config_file, "r") as f:
        raw_config = yaml.safe_load(f)
        config = ConfigV1.model_validate(raw_config)
        return config
