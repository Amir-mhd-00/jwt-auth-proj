from fastapi import APIRouter, Depends
from app.auth.auth_bearer import JWTBearer

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)

@router.get("/protected", dependencies=[Depends(rate_limiter())])
def protected(request: Request, credentials: HTTPAuthorizationCredentials = Depends()):
    _, Skey = get_current_key()
    payload = jwt.decode(credentials.credentials, Skey, algorithms=[ALGORITHM])
    return {"message": f"Hello {payload['sub']}, token valid!"}
