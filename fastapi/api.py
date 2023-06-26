from pydantic import BaseModel
from fastapi import FastAPI
from datetime import timedelta, datetime
from typing import List, Optional
import uuid
import requests
from fastapi.middleware.cors import CORSMiddleware
# from repertorio import Repertorio
from fastapi import FastAPI, APIRouter, Query, HTTPException, status, Depends, Header, BackgroundTasks
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
import psycopg2
from psycopg2 import sql
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


class Slot(BaseModel):
    slotNumber: int
    date: str


def get_db_connection():
    conn = psycopg2.connect(
        database='bandsoc_db',
        user='postgres',
        password='68&kh50C5W31',
        host='bandsoc-db.cfflfq6deazw.eu-west-2.rds.amazonaws.com',
        port='5432',
    )
    try:
        yield conn
    finally:
        conn.close()

app = FastAPI()


TOKEN_EXPIRATION_SECONDS = 60 * 60  # 1 hour
TOKEN_EXPIRATION_SECONDS_REMEMBER_ME = 60 * 60 * 24 * 30  # 1 month

# redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
redis_client = {}

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

        user_id = redis_client.get(token)
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        # redis_client.expire(token, TOKEN_EXPIRATION_SECONDS_REMEMBER_ME)
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
    
    # hased password is stored in hex in the db, so we convert it to byte string
    hashed_password = bytes.fromhex(hashed_password[2:])
    account_type = res[1]
    
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        return User(email=email, password=password, permissions=account_type)
    else:
        return None


def create_access_token(data: dict, secret: str, algorithm: str = 'HS256', expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()

    to_encode.update({'unique_id': str(uuid.uuid4())})

    encoded_jwt = jwt_lib.encode(to_encode, secret, algorithm=algorithm)

    return encoded_jwt

# --------------------------------- API ENDPOINTS ---------------------------------- #

# ----------- GET ENDPOINTS ----------- #

@app.get("/")
def root():
    return "working"

@app.get("/get_current_week")
def get_current_week(conn=Depends(get_db_connection)):
    cur = conn.cursor()
    try:
        cur.execute("select * from current_week")
        
        return cur.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/get_time_to_slot")
def get_time_to_slot(conn=Depends(get_db_connection)):
    cur = conn.cursor()
    try:
        cur.execute("select * from slot_to_time")
        
        return cur.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))  

@app.get("/get_user_credits")
def get_user_credits(user_id: int = Depends(get_current_user), conn=Depends(get_db_connection)):
    cur = conn.cursor()
    try:
        cur.execute("SELECT credits from users WHERE user_id = %s", [user_id])
        user_credits = cur.fetchone()
        print(user_credits[0])
        return user_credits[0]
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        cur.close()

@app.post("/login")
def login(credentials: HTTPBasicCredentials = Depends(login_security), conn=Depends(get_db_connection)):
    email = credentials.username
    password = credentials.password

    cur = conn.cursor()
    user = verify_password(email, password, conn)
    if not user:
        raise HTTPException(
            status_code=400, detail="Incorrect username or password")
    access_token = create_access_token({}, "secret")

    cur.execute("SELECT user_id FROM users where email = %s", [email])
    res = cur.fetchone()
    user_id = res[0]

    # redis_client.set(access_token, user_id,
    #                 ex=TOKEN_EXPIRATION_SECONDS_REMEMBER_ME)
    redis_client[access_token] = user_id
    return {"access_token": access_token, "user_id": user_id}

@app.post("/logout")
def logout(Authorization: str = Header(None)):
    if not Authorization:
        raise HTTPException(
            status_code=400, detail="Authorization header missing")

    bearer, token = Authorization.split(" ")
    if bearer != "Bearer":
        raise HTTPException(
            status_code=400, detail="Authorization header invalid")

    # # instead of trying to decode, we will just check if the token is in the logged in users cache
    # # payload = jwt_lib.decode(token, "secret", algorithms=["HS256"])
    # if redis_client.exists(token):
    #     # Remove the token from Redis
    #     redis_client.delete(token)
    #     return {"message": "Successfully logged out"}
    # else:
    #     raise HTTPException(status_code=400, detail="Token not found")
    
    if redis_client.get(token) is None:
        return {'message':'you are not signed in', 'redis':redis_client}
    
    redis_client.pop(token,None)
    return {'message':'signed out successfully'}


# ----------- POST ENDPOINTS ----------- #


@app.post("/create_account")
def create_account(credentials: HTTPBasicCredentials = Depends(login_security), conn=Depends(get_db_connection)):
    cur = conn.cursor()

    email = credentials.username
    password = credentials.password
    

    # converting password to array of bytes
    byte_password = password.encode()

    # Hashing the password, saving this to db
    hashed_password = bcrypt.hashpw(byte_password, bcrypt.gensalt())

    cur.execute("INSERT INTO users (email, full_name, password, credits, type) VALUES (%s, %s, %s, %s, %s)",(email,'need to add name later', hashed_password, 0, 'regular'))
    conn.commit()
    cur.execute("SELECT * FROM users where email = %s", [email])
    res = cur.fetchone()
    user_id = res[0]

    # redis_client.set(access_token, user_id,
                    # ex=TOKEN_EXPIRATION_SECONDS_REMEMBER_ME)
    # return {"access_token": access_token, "user_id": user_id}
    return {'message':'success', 'user_id':user_id, 'user':res}




@app.post("/book/{date}/{slot}")
def book(date: str, slot: int, Authorization: str = Header(None), conn=Depends(get_db_connection), user_id: int =Depends(get_current_user)):
    cur = conn.cursor()

    try:
        cur.execute(
            sql.SQL("SELECT credits,name FROM users WHERE user_id = %s"), (user_id,))
        user_credits, username = cur.fetchone()
        

        if user_credits <= 0:
            raise HTTPException(status_code=400, detail="Insufficient credits")

        cur.execute(sql.SQL("BEGIN"))
        cur.execute(sql.SQL(
            "UPDATE users SET credits = credits - 1 WHERE user_id = %s"), (user_id,))
        cur.execute(sql.SQL(
            "INSERT into booking_history (date_of_booking, slot_booked, user_id) VALUES (%s, %s, %s)"), (date, slot, user_id))
        cur.execute(sql.SQL("UPDATE current_week SET {} = %s WHERE current_day = %s").format(
            sql.Identifier(slot)), (username, date))
        cur.execute(sql.SQL("COMMIT"))

    except Exception as e:
        cur.execute(sql.SQL("ROLLBACK"))
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        cur.close()

