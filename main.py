import json, os
from typing import Union
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates
from passlib.context import  CryptContext
from jose import jwt
from datetime import datetime, timedelta

templates = Jinja2Templates(directory="templates")

app = FastAPI()

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "mysecretkey")
ACCESS_TOKEN_EXPIRE_MINUTES = 3

pwd_context=CryptContext(schemes=["bcrypt"],deprecated="auto")
def  get_password_hash(password):
    return pwd_context.hash(password)
# password verify
def verify_password(plain_password,hashed_password):
    return pwd_context.verify(plain_password,hashed_password)

def verify_token(authorization: str = Header()):
    try:
        scheme, token = authorization.split(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=403, detail="Invalid authentication scheme")
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded_token
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Signature has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_user(user):
    with open('./users/sample.json') as data_user:
        users = json.load(data_user)
    if user in users:
        return users[user]
    return {}

# @app.get("/")
# async def root():
#     return {"message": "Hello World"}
@app.post("/callback")
def home(request: Request, token: str = None):
    if token:
        return templates.TemplateResponse('index.html', {'request': request})
    else:
        return templates.TemplateResponse('login.html', {'request': request, 'redirect': 'url'})
    
@app.get('/login/', response_class=HTMLResponse)
def login(req: Request):
    return templates.TemplateResponse('login.html', {'request': req})
@app.post('/login/')
def login(request: Request, username: str = Form(), password: str = Form()):
    user = get_user(username)
    if not len(user):
        return templates.TemplateResponse('login.html', {'request': request, 'msg': 'User Invalid'})
    if not verify_password(password, user['password']):
        return templates.TemplateResponse('login.html', {'request': request, 'msg': 'Incorrect username or password'})
        # raise HTTPException(status_code=401, detail="Incorrect username or password")
    del user['password']
    print(user)
    expiration = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = user
    payload['exp'] = expiration
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    ckan_url = os.environ.get('CKAN_URL', 'localhost:5000')
    return templates.TemplateResponse('index.html', {'request': request, 'ckan_url': ckan_url, 'token': token})
    # return {'token': token}

@app.get('/user/getinfo')
def info(token: str = Depends(verify_token)):
    return {'token_payload': token}