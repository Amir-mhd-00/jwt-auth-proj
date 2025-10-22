from fastapi import APIRouter, Request, Depends,HTTPException
from fastapi.security import HTTPAuthorizationCredentials
import jwt
from app.utils import rate_limiter, get_current_key
from app.config import ALGORITHM

router = APIRouter(
    prefix="/users",
    tags=["users"]
)

@router.get("/protected", dependencies=[Depends(rate_limiter())])
def protected(request: Request, credentials: HTTPAuthorizationCredentials = Depends()):
    try:
        _, Skey = get_current_key()
        payload = jwt.decode(credentials.credentials, Skey, algorithms=[ALGORITHM])
        return {"message": f"Hello {payload['sub']}, token valid!"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
