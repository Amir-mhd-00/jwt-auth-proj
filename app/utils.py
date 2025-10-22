from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import hashlib, jwt, redis, time, uuid, bcrypt
from datetime import timedelta
from app.config import redis_client, ALGORITHM
from app.db import get_db_connection
from psycopg2.extras import RealDictCursor

security = HTTPBearer()

# --------------------- IP HANDLING ---------------------
def get_client_ip(request: Request):
    xff = request.headers.get("X-Forwarded-For")
    ip = xff if xff else request.client.host
    return hashlib.sha256(ip.encode()).hexdigest()

# --------------------- KEYS ----------------------------
def create_new_key(expiration_seconds=120):
    key_id = str(uuid.uuid4())
    key_value = str(uuid.uuid4()) 
    redis_client.setex(f"jwt_key:{key_id}", expiration_seconds, key_value)
    redis_client.set("jwt_current_key", key_id)
    return key_id, key_value

def get_current_key():
    key_id = redis_client.get("jwt_current_key")
    if not key_id:
        return create_new_key()
    key_id = key_id.decode()
    key_value = redis_client.get(f"jwt_key:{key_id}")
    if not key_value:
        return create_new_key()
    return key_id, key_value.decode()

# --------------------- JWT -----------------------------
def create_tokens(request: Request, username: str):
    from app.db import get_db_connection
    ACCESS_TOKEN_EXPIRE_SECONDS = 30  
    REFRESH_TOKEN_EXPIRE_SECONDS = 60

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    client_ip = get_client_ip(request)
    jti = str(uuid.uuid4())
    kid, Skey = get_current_key()
    role = user["role"]

    access_payload = {
        "sub": username,
        "role": role,
        "exp": int(time.time()) + ACCESS_TOKEN_EXPIRE_SECONDS,
        "ip": client_ip,
        "jti": jti,
        "type": "access"
    }
    refresh_payload = {
        "sub": username,
        "exp": int(time.time()) + REFRESH_TOKEN_EXPIRE_SECONDS,
        "ip": client_ip,
        "jti": jti,
        "type": "refresh"
    }

    access_token = jwt.encode(access_payload, Skey, algorithm=ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, Skey, algorithm="HS512")

    redis_client.setex(f"access:{jti}", ACCESS_TOKEN_EXPIRE_SECONDS, access_token)
    redis_client.setex(f"refresh:{jti}", REFRESH_TOKEN_EXPIRE_SECONDS, refresh_token)

    return access_token, refresh_token

# --------------------- DECORATORS ----------------------
def require_role(required_roles: list[str]):
    def wrapper(credentials: HTTPAuthorizationCredentials = Depends(security)):
        _, Skey = get_current_key()
        try:
            payload = jwt.decode(credentials.credentials, Skey, algorithms=[ALGORITHM])
            user_role = payload.get("role")
            if user_role not in required_roles:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
    return wrapper

def rate_limiter(limit: int = 5, period: int = 60):
    def wrapper(request: Request):
        client_ip = get_client_ip(request)
        key = f"ratelimit:{client_ip}:{request.url.path}"

        current = redis_client.get(key)
        if current is None:
            redis_client.setex(key, period, 1)
        else:
            current = int(current)
            if current >= limit:
                raise HTTPException(status_code=429, detail="Too many requests")
            redis_client.incr(key)
    return wrapper
