from fastapi import FastAPI, Depends, HTTPException, Request, Form, status, Cookie, Header
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from interfaces.api import router as task_router
from jose import jwt, JWTError
import httpx
import os
import json
from urllib.parse import parse_qs, urlparse
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from pydantic import BaseModel
import logging

# --- Basic Setup ---
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(title="To-Do List")
app.include_router(task_router)

class TodoBase(BaseModel):
    title: str
    description: str
    completed: bool
    created_at: str

# CORS configuration for localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentik configuration
AUTHENTIK_ISSUER = os.getenv("AUTHENTIK_ISSUER", "http://34.57.98.21/application/o/fast-api-dashboard/")
AUTHENTIK_AUTHORIZATION_URL = os.getenv("AUTHENTIK_AUTHORIZATION_URL", "http://34.57.98.21/application/o/authorize/")
AUTHENTIK_TOKEN_URL = os.getenv("AUTHENTIK_TOKEN_URL", "http://34.57.98.21/application/o/token/")
AUTHENTIK_API_BASE = "http://34.57.98.21/api/v3/"
AUTHENTIK_JWKS_URL = f"{AUTHENTIK_ISSUER}jwks/"
CLIENT_ID = os.getenv("CLIENT_ID", "0kDGte5FD7g7sxB5sNJqiTfE0puDJf5mubxWi44W")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "D2CZZ0pN2WQdXHYXZd4BjCLzmY5zJSKWagYxYBjLgNIMchvoYHnhUfMHfpENP94rv4VZmjdCxHpHCk8Ns1GzIhSpW8Eq5DOhWiRSluoq3I35D7oFEZ78WnSQVo4MpUYL")
API_TOKEN = os.getenv("API_TOKEN", "EykQzKFlAUGSyAXapXL7H9kpf4IOfPathnXkJYpza9jnuq61TuGj1DHrbzpr")

templates = Jinja2Templates(directory="templates")
todos_db = []

async def get_jwks():
    """Fetches the JSON Web Key Set from Authentik."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(AUTHENTIK_JWKS_URL)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPStatusError, json.JSONDecodeError) as e:
            logger.error(f"Failed to get or parse JWKS: {e}")
            raise HTTPException(status_code=502, detail="Could not retrieve signing keys from provider.")

async def get_current_user(
    access_token: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None)
):
    """Validates the access token from cookie or Authorization header."""
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
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=AUTHENTIK_ISSUER,
        )
        return payload
    except JWTError as e:
        logger.error(f"JWT validation failed: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

@app.get("/", response_class=HTMLResponse)
async def root(request: Request, current_user: dict | None = Depends(get_current_user)):
    """Redirects to frontend if logged in, otherwise to login."""
    if current_user:
        return RedirectResponse(url="http://localhost:5174")
    return RedirectResponse(url="http://localhost:5174/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Serves the fallback login page (Jinja2)."""
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def handle_login(request: Request, email: str = Form(...), password: str = Form(...)):
    """Handles the login flow via Authentik."""
    redirect_uri = "http://35.225.173.123:8000/auth/callback"
    logger.debug(f"Redirect URI: {redirect_uri}")

    async with httpx.AsyncClient(timeout=30.0, cookies=None, follow_redirects=True) as client:
        # Start fast-login flow
        init_response = await client.get(f"{AUTHENTIK_API_BASE}flows/executor/fast-login/")
        logger.debug(f"Init response: {init_response.json()}")
        if 'authentik_session' not in client.cookies:
            logger.error("Failed to initiate login flow: No session cookie received")
            return templates.TemplateResponse("login.html", {"request": request, "error": "Failed to initiate login flow."})

        csrf_token = client.cookies.get("authentik_csrf")
        headers = {"Content-Type": "application/json", "Referer": f"{AUTHENTIK_ISSUER}"}
        if csrf_token:
            headers["X-CSRFToken"] = csrf_token
            logger.debug(f"CSRF Token: {csrf_token}")

        # Submit credentials
        ident_payload = {"component": "ak-stage-identification", "uid_field": email, "password": password}
        logger.debug(f"Identification payload: {ident_payload}")
        ident_response = await client.post(
            f"{AUTHENTIK_API_BASE}flows/executor/fast-login/",
            json=ident_payload,
            headers=headers
        )
        logger.debug(f"Identification response: {ident_response.json()}")

        if ident_response.json().get("component") == "ak-stage-identification":
            logger.error(f"Identification failed: {ident_response.json().get('response_errors')}")
            return {"error": f"Invalid credentials: {ident_response.json().get('response_errors')}"}

        # Confirm login
        login_payload = {"component": "ak-stage-user-login", "remember_me": True}
        logger.debug(f"Login payload: {login_payload}")
        login_response = await client.post(
            f"{AUTHENTIK_API_BASE}flows/executor/fast-login/",
            json=login_payload,
            headers=headers
        )
        logger.debug(f"Login response: {login_response.json()}")

        if login_response.json().get("component") != "xak-flow-redirect":
            logger.error(f"Login failed: {login_response.json()}")
            return {"error": "Invalid username or password."}

        # Start OIDC flow
        scopes = "openid profile email"
        auth_params = f"response_type=code&client_id={CLIENT_ID}&redirect_uri={redirect_uri}&scope={scopes.replace(' ', '%20')}"
        auth_response = await client.get(f"{AUTHENTIK_AUTHORIZATION_URL}?{auth_params}")
        logger.debug(f"Auth Response URL: {auth_response.url}")

        # Check for consent screen
        if "/if/flow/" in str(auth_response.url):
            logger.error("OIDC flow interrupted by consent screen. Configure implicit consent in Authentik.")
            return {"error": "Login failed: User consent required. See server logs."}

        # Extract authorization code
        parsed_url = urlparse(str(auth_response.url))
        query_params = parse_qs(parsed_url.query)
        code = query_params.get("code", [None])[0]
        logger.debug(f"Extracted Code: {code}")

        if not code:
            logger.error("Failed to get authorization code")
            return {"error": "Failed to get authorization code."}

        # Exchange code for token
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
            logger.error(f"Token exchange failed: {token_response.text}")
            return {"error": f"Token exchange failed: {token_response.text}"}

        access_token = token_response.json().get("access_token")
        logger.debug(f"Access Token: {access_token}")

        # Set cookie and redirect to frontend
        response = RedirectResponse(url="http://localhost:5174", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            samesite="lax",
            secure=False,  # Set to True in production with HTTPS
            path="/",
            domain="localhost"
        )
        logger.debug("Redirecting to: http://localhost:5174")
        return response

@app.get("/auth/callback")
async def auth_callback():
    """Dummy endpoint for OIDC redirect URI."""
    return {"status": "ok"}

@app.get("/tasks/", response_model=List[TodoBase])
async def get_tasks(current_user: dict = Depends(get_current_user)):
    """Returns the list of tasks."""
    return todos_db

@app.post("/tasks/")
async def create_task(todo: TodoBase, current_user: dict = Depends(get_current_user)):
    """Creates a new task."""
    todo_dict = todo.dict()
    todo_dict["id"] = len(todos_db) + 1
    todo_dict["created_at"] = "2025-07-17T15:00:00Z"
    todos_db.append(todo_dict)
    return todo_dict

@app.put("/tasks/{id}/toggle-complete")
async def toggle_complete(id: int, current_user: dict = Depends(get_current_user)):
    """Toggles the completion status of a task."""
    for todo in todos_db:
        if todo["id"] == id:
            todo["completed"] = not todo["completed"]
            return {"message": "Toggle successful", "todo": todo}
    raise HTTPException(status_code=404, detail="Todo not found")

@app.delete("/tasks/{id}")
async def delete_task(id: int, current_user: dict = Depends(get_current_user)):
    """Deletes a task."""
    global todos_db
    todos_db = [todo for todo in todos_db if todo["id"] != id]
    return {"message": "Todo deleted"}

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Serves the fallback registration page (Jinja2)."""
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
    """Handles user registration via Authentik API."""
    if password != password_repeat:
        return {"error": "Passwords do not match"}

    authentik_base_url = AUTHENTIK_ISSUER.split("/application/")[0]
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            user_creation_response = await client.post(
                f"{authentik_base_url}/api/v3/core/users/",
                json={"username": username, "email": email, "name": name, "is_active": True, "type": "internal"},
                headers={"Authorization": f"Bearer {API_TOKEN}"},
            )
            user_creation_response.raise_for_status()
            user_id = user_creation_response.json().get('pk')

            password_response = await client.post(
                f"{authentik_base_url}/api/v3/core/users/{user_id}/set_password/",
                json={"password": password},
                headers={"Authorization": f"Bearer {API_TOKEN}"},
            )
            password_response.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(f"Registration failed: {e.response.text}")
            return {"error": f"Registration failed: {e.response.text}"}
        except httpx.ReadTimeout:
            logger.error("Timeout connecting to Authentik server")
            return {"error": "Timeout connecting to Authentik server."}

    return RedirectResponse(url="http://localhost:5174/login", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout():
    """Logs out the user by clearing the cookie."""
    response = RedirectResponse(url="http://localhost:5174/login")
    response.delete_cookie("access_token", path="/", domain="localhost")
    return response