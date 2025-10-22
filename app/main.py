from fastapi import FastAPI
from app.routes import auth, users  

app = FastAPI(title="JWT Authentication API")

app.include_router(auth.router)
app.include_router(users.router)

@app.get("/")
def root():
    return {"message": "Server is running!"}
