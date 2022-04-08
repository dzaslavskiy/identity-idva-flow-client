import json
import logging
import time
from http import HTTPStatus
from typing import Optional
from uuid import UUID
import secrets

import jwt
import requests
from aiohttp import ClientError, ClientSession
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from requests import Request as RRequest
from requests.auth import HTTPBasicAuth
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette_prometheus import PrometheusMiddleware, metrics

from flow_client import settings

app = FastAPI()

security = HTTPBasic()

app.add_middleware(SessionMiddleware, secret_key="!secret")

app.add_middleware(PrometheusMiddleware)
app.add_route("/metrics/", metrics)

logging.getLogger().setLevel(logging.INFO)

#config = Config('.env')  # read config from .env file
oauth = OAuth()

oauth.register(
    name='google',
    client_id='...',
    client_secret='...',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile'
    }
)

# @app.get('/')
# async def homepage(request: Request):
#     user = request.session.get('user')
#     if user:
#         data = json.dumps(user)
#         html = (
#             f'<pre>{data}</pre>'
#             '<a href="/flow">flow</a>'
#             '<a href="/logout">logout</a>'
#         )
#         return HTMLResponse(html)
#     return HTMLResponse('<a href="/login">login</a>')

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, settings.USERNAME)
    correct_password = secrets.compare_digest(credentials.password, settings.PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.get('/')
async def homepage(username: str = Depends(get_current_username)):
    html = (
        f'<pre>hello?</pre>'
        '<a href="/flow">flow</a></br>'
        '<a href="/logout">logout</a>'
    )
    return HTMLResponse(html)


@app.get('/login')
async def login(request: Request):
    redirect_uri = request.url_for('auth')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get('/auth')
async def auth(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as error:
        return HTMLResponse(f'<h1>{error.error}</h1>')
    user = token.get('userinfo')
    if user:
        request.session['user'] = dict(user)
    return RedirectResponse(url='/')

@app.get('/logout')
async def logout(request: Request):
    request.session.pop('user', None)
    return RedirectResponse(url='/')

@app.get('/flow')
async def flow():

    STATE = "H5hNTZGm6vo1-02OaA51nGnBaoJM58WdHWhUh1AspKk"
    epoch_time = int(time.time()) + 60

    jwt_data = {
        "iss": "http://127.0.0.100:8088",
        "aud": settings.FLOW_ISSUER,
        "response_type": "code",
        "client_id": settings.FLOW_CLIENT_ID,
        "scope": "openid profile",
        "state": STATE,
        "redirect_uri": settings.FLOW_REDIRECT_URI,
        "nonce": "M58WdHWhUh1AspK",
        "exp": epoch_time
    }

    encoded_jwt = jwt.encode(jwt_data, settings.FLOW_PRIVATE_KEY, algorithm="RS256")
    
    try:
        decode = jwt.decode(encoded_jwt, settings.FLOW_PUBLIC_KEY, audience=settings.FLOW_ISSUER, algorithms=["RS256"])
        print(decode)
    except jwt.ExpiredSignatureError:
        print("expired!!!!")
    
    query = {
        "response_type": "code",
        "client_id": settings.FLOW_CLIENT_ID,
        "scope": "openid profile",
        "state": STATE,
        "redirect_uri": settings.FLOW_REDIRECT_URI,
        "nonce": "M58WdHWhUh1AspK",
        "request": encoded_jwt,
    }
    p = RRequest('GET', settings.FLOW_URL, params=query).prepare()
    
    return RedirectResponse(url=p.url, status_code=302)
