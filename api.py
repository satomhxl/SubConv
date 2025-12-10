#!/usr/bin/env python3
# coding=utf-8

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.requests import Request
from fastapi.responses import FileResponse, Response, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from typing import Optional
from pydantic import BaseModel

import httpx
import hashlib
import hmac
import time
import os
import secrets

import yaml

from urllib.parse import urlencode
import argparse
from pathlib import Path
import re

DISALLOW_ROBOTS = True  # Block search engines by default

# Password protection configuration
ACCESS_PASSWORD = os.getenv("ACCESS_PASSWORD", "")  # Read from environment variable
PASSWORD_ENABLED = bool(ACCESS_PASSWORD)  # Enable password protection if set
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))  # Secret key for token generation

"""
main routine
"""
if __name__ == "__main__":
    from modules import config_template
    # generate config file
    class GenerateConfigAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            yaml.SafeDumper.ignore_aliases = lambda *args : True
            if values == "default":
                with open("config.yaml", "w", encoding="utf-8") as f:
                    f.write(yaml.safe_dump(config_template.template_default, allow_unicode=True, sort_keys=False))
            elif values == "zju":
                with open("config.yaml", "w", encoding="utf-8") as f:
                    f.write(yaml.safe_dump(config_template.template_zju, allow_unicode=True, sort_keys=False))
            parser.exit()

    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", "-P", type=int, default=8080, help="port of the api, default: 8080")
    parser.add_argument("--host", "-H", type=str, default="0.0.0.0", help="host of the api, default: 0.0.0.0")
    parser.add_argument("--version", "-V", action="version", version="version: v2.0.0")
    parser.add_argument("--generate-config", "-G", type=str, choices=("default", "zju"), action=GenerateConfigAction, help="generate a default config file")
    args = parser.parse_args()

    # init config
    from modules import config

    # Debug
    # uvicorn.run("api:app", host=args.host, port=args.port, reload=True)
    # Production
    print("host:", args.host)
    print("port:", args.port)
    if DISALLOW_ROBOTS:
        print("robots: Disallow")
    else:
        print("robots: Allow")
    module_name = __name__.split(".")[0]
    uvicorn.run(module_name+":app", host=args.host, port=args.port, workers=4, proxy_headers=True, forwarded_allow_ips="*")


"""
FastAPI App
"""
from modules import pack
from modules import parse
from modules.convert import converter
from modules import config


# Pydantic models for authentication
class AuthRequest(BaseModel):
    password: str

class AuthResponse(BaseModel):
    success: bool
    token: Optional[str] = None
    message: str


# Authentication functions
def generate_access_token(password: str) -> str:
    """Generate a secure access token using HMAC-SHA256"""
    timestamp = str(int(time.time()))
    message = f"{password}:{timestamp}"
    token = hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{token}:{timestamp}"


def verify_access_token(token: str) -> bool:
    """Verify the access token"""
    if not PASSWORD_ENABLED:
        return True  # No password protection, allow access
    
    if not token:
        return False
    
    try:
        token_hash, timestamp = token.split(":")
        message = f"{ACCESS_PASSWORD}:{timestamp}"
        expected_token = hmac.new(
            SECRET_KEY.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(token_hash, expected_token)
    except (ValueError, AttributeError):
        return False


def verify_password(password: str) -> bool:
    """Verify the provided password"""
    if not PASSWORD_ENABLED:
        return True  # No password protection
    return hmac.compare_digest(password, ACCESS_PASSWORD)


# Dependency for protected routes
async def verify_auth(x_access_token: Optional[str] = Header(None, alias="X-Access-Token")):
    """Dependency to verify authentication for protected routes"""
    if not PASSWORD_ENABLED:
        return True  # No password protection enabled
    
    if not x_access_token or not verify_access_token(x_access_token):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Invalid or missing access token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return True


def length(sth):
    if sth is None:
        return 0
    else:
        return len(sth)

app = FastAPI()


# Authentication endpoint
@app.post("/auth/verify", response_model=AuthResponse)
async def auth_verify(auth_request: AuthRequest):
    """Verify password and return access token"""
    if not PASSWORD_ENABLED:
        return AuthResponse(
            success=True,
            token="",
            message="Password protection is not enabled"
        )
    
    if verify_password(auth_request.password):
        token = generate_access_token(auth_request.password)
        return AuthResponse(
            success=True,
            token=token,
            message="Authentication successful"
        )
    else:
        return AuthResponse(
            success=False,
            message="Invalid password"
        )


@app.get("/auth/check")
async def auth_check(x_access_token: Optional[str] = Header(None, alias="X-Access-Token")):
    """Check if the current token is valid"""
    if not PASSWORD_ENABLED:
        return JSONResponse(content={"valid": True, "password_enabled": False})
    
    is_valid = verify_access_token(x_access_token)
    return JSONResponse(content={"valid": is_valid, "password_enabled": True})


# mainpage
app.mount("/static", StaticFiles(directory="static"), name="static")
@app.get("/")
async def mainpage():
    return FileResponse("static/index.html")

# /robots.txt
@app.get("/robots.txt")
async def robots():
    if DISALLOW_ROBOTS:
        return Response(content="User-agent: *\nDisallow: /", media_type="text/plain")
    else:
        return Response(status_code=404)

# subscription to proxy-provider
@app.get("/provider")
async def provider(request: Request, auth: bool = Depends(verify_auth)):
    headers = {'Content-Type': 'text/yaml;charset=utf-8'}
    url = request.query_params.get("url")
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers={'User-Agent': 'v2rayn'})
        if resp.status_code < 200 or resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        result = await parse.parseSubs(resp.text)
    return Response(content=result, headers=headers)

    
# subscription converter api
@app.get("/sub")
async def sub(request: Request, auth: bool = Depends(verify_auth)):
    args = request.query_params
    # get interval
    if "interval" in args:
        interval = args["interval"]
    else:
        interval = "1800"

    short = args.get("short")

    # get proxyrule
    notproxyrule = args.get("npr")


    # get the url of original subscription
    url = args.get("url")
    url = re.split(r"[|\n]", url)
    # remove empty lines
    tmp = list(filter(lambda x: x!="", url)) 
    url = []
    urlstandalone = []
    for i in tmp:
        if (i.startswith("http://") or i.startswith("https://")) and not i.startswith("https://t.me/"):
                url.append(i)
        else:
            urlstandalone.append(i)
    urlstandalone = "\n".join(urlstandalone)
    if len(url) == 0:
        url = None
    if len(urlstandalone) == 0:
        urlstandalone = None

    urlstandby = args.get("urlstandby")
    urlstandbystandalone = None
    if urlstandby:
        urlstandby = re.split(r"[|\n]", urlstandby)
        tmp = list(filter(lambda x: x!="", urlstandby))
        urlstandby = []
        urlstandbystandalone = []
        for i in tmp:
            if (i.startswith("http://") or i.startswith("https://")) and not i.startswith("https://t.me/"):
                urlstandby.append(i)
            else:
                urlstandbystandalone.append(i)
        urlstandbystandalone = "\n".join(urlstandbystandalone)
        if len(urlstandby) == 0:
            urlstandby = None
        if len(urlstandbystandalone) == 0:
            urlstandbystandalone = None
        
    if urlstandalone:
        urlstandalone = await converter.ConvertsV2Ray(urlstandalone)
    if urlstandbystandalone:
        urlstandbystandalone = await converter.ConvertsV2Ray(urlstandbystandalone)

    async with httpx.AsyncClient() as client:
        # get original headers
        headers = {'Content-Type': 'text/yaml;charset=utf-8'}
        # if there's only one subscription, return userinfo
        if length(url) == 1:
            resp = await client.head(url[0], headers={'User-Agent': request.headers['User-Agent']})
            if resp.status_code < 200 or resp.status_code >= 400:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            elif resp.status_code >= 300 and resp.status_code < 400:
                while resp.status_code >= 300 and resp.status_code < 400:
                    url[0] = resp.headers['Location']
                    resp = await client.head(url[0], headers={'User-Agent': request.headers['User-Agent']})
                    if resp.status_code < 200 or resp.status_code >= 400:
                        raise HTTPException(status_code=resp.status_code, detail=resp.text)
            originalHeaders = resp.headers
            if 'subscription-userinfo' in originalHeaders:  # containing info about ramaining flow
                headers['subscription-userinfo'] = originalHeaders['subscription-userinfo']
            if 'Content-Disposition' in originalHeaders:  # containing filename
                headers['Content-Disposition'] = originalHeaders['Content-Disposition'].replace("attachment", "inline")

        content = []  # the proxies of original subscriptions
        if url is not None:
            for i in range(len(url)):
                # the test of response
                respText = (await client.get(url[i], headers={'User-Agent': 'v2rayn'})).text
                content.append(await parse.parseSubs(respText))
                url[i] = "{}provider?{}".format(request.base_url, urlencode({"url": url[i]}))
    if len(content) == 0:
        content = None
    if urlstandby:
        for i in range(len(urlstandby)):
            urlstandby[i] = "{}provider?{}".format(request.base_url, urlencode({"url": urlstandby[i]}))

    # get the domain or ip of this api to add rule for this
    domain = re.search(r"([^:]+)(:\d{1,5})?", request.url.hostname).group(1)
    # generate the subscription
    result = await pack.pack(url=url, urlstandalone=urlstandalone, urlstandby=urlstandby,urlstandbystandalone=urlstandbystandalone, content=content, interval=interval, domain=domain, short=short, notproxyrule=notproxyrule, base_url=request.base_url)
    return Response(content=result, headers=headers)

# proxy
@app.get("/proxy")
async def proxy(request: Request, url: str, auth: bool = Depends(verify_auth)):
    # check if url is in whitelist
    is_whitelisted = False
    for rule in config.configInstance.RULESET:
        if rule[1] == url:
            is_whitelisted = True
            break
    if not is_whitelisted:
        raise HTTPException(status_code=403, detail="Forbidden: URL not in whitelist")
    # file was big so use stream
    async def stream():
        async with httpx.AsyncClient() as client:
            async with client.stream("GET", url, headers={'User-Agent':request.headers['User-Agent']}) as resp:
                yield resp.status_code
                yield resp.headers
                if resp.status_code < 200 or resp.status_code >= 400:
                    yield await resp.aread()
                    return
                async for chunk in resp.aiter_bytes():
                    yield chunk
    streamResp = stream()
    status_code = await streamResp.__anext__()
    headers = await streamResp.__anext__()
    if status_code < 200 or status_code >= 400:
        raise HTTPException(status_code=status_code, detail=await streamResp.__anext__())
    return StreamingResponse(streamResp, media_type=headers['Content-Type'])

# static files
@app.get("/{path:path}")
async def index(path):
    if Path("static/"+path).exists():
        return FileResponse("static/"+path)
    else:
        raise HTTPException(status_code=404, detail="Not Found")
