from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials
from psycopg2.extras import RealDictCursor
import jwt, bcrypt
from app.db import get_db_connection
from app.models import RegisterRequest, LoginRequest, TokenRequest
from app.utils import create_tokens, get_client_ip, rate_limiter, require_role, get_current_key
from app.config import redis_client, ALGORITHM

router = APIRouter(prefix="", tags=["Auth"])

@router.post("/register")
def register(data: RegisterRequest):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s", (data.username,))
    existing_user = cur.fetchone()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    cur.execute("INSERT INTO users (username, password, gmail) VALUES (%s, %s, %s)", (data.username, hashed, data.gmail))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": f"User '{data.username}' registered successfully!"}

@router.post("/login", dependencies=[Depends(rate_limiter())])
def login(request: Request, data: LoginRequest):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s", (data.username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not bcrypt.checkpw(data.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token, refresh_token = create_tokens(request, data.username)
    return {"access_token": access_token, "refresh_token": refresh_token}


@router.get("/admin-only", dependencies=[Depends(rate_limiter())])
def admin_only(payload = Depends(require_role(["admin"]))):
    return {"message": f"Welcome Admin {payload['sub']}"}

@router.post("/refresh", dependencies=[Depends(rate_limiter())])
def refresh(request: Request, data: TokenRequest):
    try:
        _, Skey = get_current_key()
        payload = jwt.decode(data.refresh_token, Skey, algorithms=["HS512"])
        username = payload["sub"]
        access_token, refresh_token = create_tokens(request, username)
        return {"access_token": access_token, "refresh_token": refresh_token}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends()):
    _, Skey = get_current_key()
    payload = jwt.decode(credentials.credentials, Skey, algorithms=[ALGORITHM])
    jti = payload.get("jti")
    if jti:
        redis_client.delete(f"access:{jti}")
        redis_client.delete(f"refresh:{jti}")
    return {"message": "Logout completed."}
