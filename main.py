from fastapi import FastAPI, Depends, HTTPException, Request, Form, status, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from interfaces.api import router as task_router
from jose import jwt, JWTError
import httpx
import os
import json
from urllib.parse import urljoin, parse_qs, urlparse
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from pydantic import BaseModel

app = FastAPI(title="To-Do List")
app.include_router(task_router)

class TodoBase(BaseModel):
    title: str
    description: str
    completed: bool
    created_at: str

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # فقط دامنه فرانت‌اند
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],  # اضافه کردن Authorization
)

AUTHENTIK_ISSUER = os.getenv("AUTHENTIK_ISSUER", "http://34.57.98.21:80/application/o/fast-api-dashboard/")
AUTHENTIK_AUTHORIZATION_URL = os.getenv("AUTHENTIK_AUTHORIZATION_URL", "http://34.57.98.21:80/application/o/authorize/")
AUTHENTIK_TOKEN_URL = os.getenv("AUTHENTIK_TOKEN_URL", "http://34.57.98.21:80/application/o/token/")
AUTHENTIK_API_BASE = "http://34.57.98.21:80/api/v3/"
AUTHENTIK_JWKS_URL = f"{AUTHENTIK_ISSUER}jwks/"
CLIENT_ID = os.getenv("CLIENT_ID", "0kDGte5FD7g7sxB5sNJqiTfE0puDJf5mubxWi44W")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "D2CZZ0pN2WQdXHYXZd4BjCLzmY5zJSKWagYxYBjLgNIMchvoYHnhUfMHfpENP94rv4VZmjdCxHpHCk8Ns1GzIhSpW8Eq5DOhWiRSluoq3I35D7oFEZ78WnSQVo4MpUYL")
API_TOKEN = os.getenv("API_TOKEN", "EykQzKFlAUGSyAXapXL7H9kpf4IOfPathnXkJYpza9jnuq61TuGj1DHrbzpr")

templates = Jinja2Templates(directory="templates")
todos_db = []

async def get_jwks():
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(AUTHENTIK_JWKS_URL)
        response.raise_for_status()
        return response.json()

async def get_current_user(
    access_token: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None)
):
    token = None
    if access_token:
        token = access_token
    elif authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1]
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        jwks = await get_jwks()
        payload = jwt.decode(
            token,
            jwks,
            algorithms=[" moving to separate service, the cookie set by the backend (`http://35.225.173.123:8000`) may not be accessible to the frontend (`http://35.225.173.123:5174`) due to browser same-origin policies or `SameSite` restrictions.

@app.get("/", response_class=HTMLResponse)
async def root(request: Request, current_user: dict | None = Depends(get_current_user)):
    if current_user:
        return RedirectResponse(url="http://35.225.173.123:5174")
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def handle_login(request: Request, email: str = Form(...), password: str = Form(...)):
    redirect_uri = "http://35.225.173.123:8000/auth/callback"
    print(f"Redirect URI: {redirect_uri}")

    async with httpx.AsyncClient(timeout=30.0, cookies=None, follow_redirects=True) as client:
        init_response = await client.get(f"{AUTHENTIK_API_BASE}flows/executor/fast-login/")
        if 'authentik_session' not in client.cookies:
            return templates.TemplateResponse("login.html", {"request": request, "error": "Failed to initiate login flow."})

        csrf_token = client.cookies.get("authentik_csrf")
        headers = {"Content-Type": "application/json", "Referer": "http://34.57.98.21:80/"}
        if csrf_token:
            headers["X-CSRFToken"] = csrf_token

        ident_payload = {"component": "ak-stage-identification", "uid_field": email, "password": password}
        await client.post(f"{AUTHENTIK_API_BASE}flows/executor/fast-login/", json=ident_payload, headers=headers)

        login_payload = {"component": "ak-stage-user-login", "remember_me": True}
        login_response = await client.post(f"{AUTHENTIK_API_BASE}flows/executor/fast-login/", json=login_payload, headers=headers)

        if login_response.json().get("component") != "xak-flow-redirect":
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password."})

        scopes = "openid profile email"
        auth_params = f"response_type=code&client_id={CLIENT_ID}&redirect_uri={redirect_uri}&scope={scopes.replace(' ', '%20')}"
        auth_response = await client.get(f"{AUTHENTIK_AUTHORIZATION_URL}?{auth_params}")
        print(f"Auth Response URL: {auth_response.url}")

        parsed_url = urlparse(str(auth_response.url))
        query_params = parse_qs(parsed_url.query)
        code = query_params.get("code", [None])[0]
        print(f"Extracted Code: {code}")

        if not code:
            return templates.TemplateResponse("login.html", {"request": request, "error": "Failed to get authorization code."})

        token_response = await client.post(
            AUTHENTIK_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uri": redirect_uri,
                "code": code
            }
        )

        if token_response.status_code != 200:
            return templates.TemplateResponse("login.html", {"request": request, "error": f"Token exchange failed: {token_response.text}"})

        access_token = token_response.json().get("access_token")
        print(f"Access Token: {access_token}")

        response = RedirectResponse(url="http://35.225.173.123:5174", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="access_token", value=access_token, httponly=True, samesite="lax", secure=False, path="/")  # اضافه کردن path="/"
        print(f"Redirecting to: http://35.225.173.123:5174")
        return response

@app.get("/auth/callback")
async def auth_callback():
    return {"status": "ok"}

@app.get("/tasks/", response_model=List[TodoBase])
async def get_tasks(current_user: dict = Depends(get_current_user)):
    return todos_db

@app.post("/tasks/")
async def create_task(todo: TodoBase, current_user: dict = Depends(get_current_user)):
    todo_dict = todo.dict()
    todo_dict["id"] = len(todos_db) + 1
    todo_dict["created_at"] = "2025-07-17T15:00:00Z"
    todos_db.append(todo_dict)
    return todo_dict

@app.put("/tasks/{id}/toggle-complete")
async def toggle_complete(id: int, current_user: dict = Depends(get_current_user)):
    for todo in todos_db:
        if todo["id"] == id:
            todo["completed"] = not todo["completed"]
            return {"message": "Toggle successful", "todo": todo}
    raise HTTPException(status_code=404, detail="Todo not found")

@app.delete("/tasks/{id}")
async def delete_task(id: int, current_user: dict = Depends(get_current_user)):
    global todos_db
    todos_db = [todo for todo in todos_db if todo["id"] != id]
    return {"message": "Todo deleted"}

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def handle_registration(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    name: str = Form(...),
    password: str = Form(...),
    password_repeat: str = Form(...),
):
    if password != password_repeat:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Passwords do not match"})

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            user_creation_response = await client.post(
                f"{AUTHENTIK_API_BASE}core/users/",
                json={"username": username, "email": email, "name": name, "is_active": True, "type": "internal"},
                headers={"Authorization": f"Bearer {API_TOKEN}"},
            )
            user_creation_response.raise_for_status()
            user_id = user_creation_response.json().get('pk')

            password_response = await client.post(
                f"{AUTHENTIK_API_BASE}core/users/{user_id}/set_password/",
                json={"password": password},
                headers={"Authorization": f"Bearer {API_TOKEN}"},
            )
            password_response.raise_for_status()
        except httpx.HTTPStatusError as e:
            return templates.TemplateResponse("register.html", {"request": request, "error": f"Registration failed: {e.response.text}"})
        except httpx.ReadTimeout:
            return templates.TemplateResponse("register.html", {"request": request, "error": "Timeout connecting to Authentik server."})

    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie("access_token", path="/")
    return response