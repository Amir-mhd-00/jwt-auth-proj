from fastapi import APIRouter, Depends
from app.auth.auth_bearer import JWTBearer

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)

# Move your existing 'protected' route here
@router.get("/protected")
def protected_route(token: str = Depends(JWTBearer())):
    return {"message": "This is a protected route"}
