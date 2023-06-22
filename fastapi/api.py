from pydantic import BaseModel
from fastapi import FastAPI
from datetime import timedelta, datetime
from typing import List, Optional
import uuid
import requests
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
from fastapi.middleware.cors import CORSMiddleware
# from secrets_1 import secrets
from repertorio import Repertorio
from fastapi import FastAPI, APIRouter, Query, HTTPException, status, Depends, Header, BackgroundTasks
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer
from fastapi.exceptions import RequestValidationError
# from pydantic import BaseModel
import psycopg2
from psycopg2 import extras
from fastapi.middleware.cors import CORSMiddleware
import bcrypt
from enum import Enum
import jwt as jwt_lib
import redis


class User(BaseModel):
    email: str
    password: str
    permissions: str


class Slots(BaseModel):
    slotNumber: int
    day: str


def get_db_connection():
    conn = psycopg2.connect(
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    try:
        yield conn
    finally:
        conn.close()


app = FastAPI()


TOKEN_EXPIRATION_SECONDS = 60 * 60  # 1 hour
TOKEN_EXPIRATION_SECONDS_REMEMBER_ME = 60 * 60 * 24 * 30  # 1 month

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


# Allow requests from all origins
origins = ['*']

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# this is used to extract email and password from the auth headers
login_security = HTTPBasic()


# helpers

def get_current_user(Authorization: str = Header(None)):
    if not Authorization:
        raise HTTPException(
            status_code=400, detail="Authorization header missing")
    try:
        bearer, token = Authorization.split(" ")
        if bearer != "Bearer":
            raise HTTPException(
                status_code=400, detail="Authorization header invalid")

        # instead of trying to decode, we will just check if the token is in the logged in users cache
        # payload = jwt_lib.decode(token, "secret", algorithms=["HS256"])

        user_id = redis_client.get(token)
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        redis_client.expire(token, TOKEN_EXPIRATION_SECONDS_REMEMBER_ME)

        return int(user_id)
    except KeyError as e:
        raise HTTPException(status_code=400, detail="Token is invalid")


def verify_password(email: str, password: str, conn=Depends(get_db_connection)):
    cur = conn.cursor()

    # try to find the email from the SQL database, if it exists get password and compare
    cur.execute("SELECT password, type FROM users where email = %s", [email])
    res = cur.fetchone()
    if res == None:
        return None

    hashed_password = res[0]
    account_type = res[1]

    if bcrypt.checkpw(password.encode(), hashed_password.encode()):
        return User(email=email, password=password, permissions=account_type)
    else:
        return None


def create_access_token(data: dict, secret: str, algorithm: str = 'HS256', expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()

    to_encode.update({'unique_id': str(uuid.uuid4())})

    encoded_jwt = jwt_lib.encode(to_encode, secret, algorithm=algorithm)
    return encoded_jwt

# API ENDPOINTS


@app.post("/login")
def login(credentials: HTTPBasicCredentials = Depends(login_security), conn=Depends(get_db_connection)):
    name = credentials.username
    password = credentials.password

    cur = conn.cursor()
    user = verify_password(name, password, conn)

    if not user:
        raise HTTPException(
            status_code=400, detail="Incorrect username or password")
    access_token = create_access_token({}, "secret")

    cur.execute("SELECT user_id FROM users where name = %s", [name])
    res = cur.fetchone()
    userid = res[0]

    redis_client.set(access_token, userid,
                     ex=TOKEN_EXPIRATION_SECONDS_REMEMBER_ME)
    return {"access_token": access_token, "user_id": userid}
