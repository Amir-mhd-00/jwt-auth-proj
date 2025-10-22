from pydantic import BaseModel
from typing import Optional

class RegisterRequest(BaseModel):
    username: str
    password: str
    gmail: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenRequest(BaseModel):
    refresh_token: str
