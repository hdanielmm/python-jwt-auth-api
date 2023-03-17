from datetime import datetime, timedelta
from fastapi import Depends, APIRouter, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt

ALGORITHM = "HS256"
ACCESS_TOKEN_DURATION = 5
SECRET = "cualquiercosaymuchomejorsiestaencriptada" #secreto

router = APIRouter(prefix="/jwt")

oauth2 = OAuth2PasswordBearer(tokenUrl="login")

crypt = CryptContext(schemes=["bcrypt"])

class User(BaseModel):
    username: str
    email: str
    disabled: bool

class UserDB(User):
    password: str

users_db = {
    "danieldev": {
        "username": "danieldev",
        "email": "danieldev@email.com",
        'disabled': False,
        "password": "$2a$12$F119kYaKDB3931ctIQ6kK.ZeG2A1o7e4aew7oQsvlFMFQWOucrIfm", #123
    },
    "cristinadev": {
        "username": "cristinadev",
        "email": "cristinadev@email.com",
        'disabled': False,
        "password": "$2a$12$SINYP751.ZRv8DkU9WBAze2E7QlNDednLEXrOit8jRi/UUolkM71W", #456
    }
}

def search_user_db(username: str):
    if username in users_db:
        return UserDB(**users_db[username])
    
def search_user(username: str):
    if username in users_db:
        return User(**users_db[username])

def auth_user(token: str = Depends(oauth2)):
    error_401 = HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    try:
        username = jwt.decode(token, SECRET, algorithms=[ALGORITHM]).get("sub")

        if username is None:
            raise error_401
        
    except JWTError:
        raise error_401
    
    return search_user(username)

def current_user(user: User = Depends(auth_user)):
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User disabled"
        )
    
    return user

@router.post("/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    error_400 = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect user"
    )
    
    user_db = users_db.get(form.username)

    if not user_db:
        raise error_400

    user = search_user_db(form.username)
    
    if not crypt.verify(form.password, user.password):
        raise error_400

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_DURATION)
    access_token = {"sub": user.username, "exp": expire}

    return {"access_token": jwt.encode(access_token, SECRET, algorithm=ALGORITHM), "token_type": "bearer"}

@router.get("/user/me")
def me(current_user: User = Depends(auth_user)):
    return current_user