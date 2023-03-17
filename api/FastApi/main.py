from fastapi import FastAPI
from routers import authentication

app = FastAPI()

app.include_router(authentication.router)


@app.post("/login")
def login():
    return "jwt-auth-api"