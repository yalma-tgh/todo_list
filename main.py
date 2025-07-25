from fastapi import FastAPI, Depends, HTTPException, Request, Form, status, Cookie, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
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
import time

# --- Basic Setup ---
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(title="To-Do List")
app.include_router(task_router)


# Explicitly set debug mode to True here for testing - change to False for production
DEBUG_AUTH_MODE = True  # os.getenv("DEBUG_AUTH_MODE", "false").lower() == "true"

# Add more debug info at startup
if DEBUG_AUTH_MODE:
    logger.warning("=== RUNNING IN DEBUG AUTH MODE - TOKEN VERIFICATION DISABLED ===")
    logger.warning("=== THIS MODE SHOULD NOT BE USED IN PRODUCTION ===")
else:
    logger.info("Running in normal authentication mode with full JWT verification")


# Create a middleware version of the authentication that's more permissive
# for debugging purposes
async def get_current_user_debug(
    access_token: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None)
):
    """Debug version of user validation with relaxed checks."""
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1]
    elif access_token:
        token = access_token
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Parse token without validation
        token_parts = token.split('.')
        if len(token_parts) < 2:
            raise HTTPException(status_code=401, detail="Invalid token format")
        
        import base64
        import json
        
        # Decode payload without verification
        padded = token_parts[1] + '=' * (-len(token_parts[1]) % 4)  # Add padding if needed
        payload_bytes = base64.urlsafe_b64decode(padded)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        # Only check expiration
        if payload.get("exp") and payload["exp"] < time.time():
            raise HTTPException(status_code=401, detail="Token has expired")
        
        logger.warning("DEBUG MODE: Using unverified token payload")
        return payload
    except Exception as e:
        logger.error(f"Debug token validation failed: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


# Helper function to choose the right auth dependency based on mode
def get_auth_dependency():
    if DEBUG_AUTH_MODE:
        logger.warning("RUNNING IN DEBUG AUTH MODE - DO NOT USE IN PRODUCTION")
        return get_current_user_debug
    else:
        return get_current_user

class TodoBase(BaseModel):
    title: str
    description: str
    completed: bool
    created_at: str

# CORS configuration for localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://35.225.173.123:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentik configuration
AUTHENTIK_ISSUER = os.getenv("AUTHENTIK_ISSUER", "http://34.57.98.21/application/o/fast-api-dashboard/").rstrip("/") + "/"
AUTHENTIK_AUTHORIZATION_URL = os.getenv("AUTHENTIK_AUTHORIZATION_URL", "http://34.57.98.21/application/o/authorize/")
AUTHENTIK_TOKEN_URL = os.getenv("AUTHENTIK_TOKEN_URL", "http://34.57.98.21/application/o/token/")
AUTHENTIK_API_BASE = "http://34.57.98.21/api/v3/"
AUTHENTIK_JWKS_URL = f"{AUTHENTIK_ISSUER}jwks/"
CLIENT_ID = os.getenv("CLIENT_ID", "0kDGte5FD7g7sxB5sNJqiTfE0puDJf5mubxWi44W")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "D2CZZ0pN2WQdXHYXZd4BjCLzmY5zJSKWagYxYBjLgNIMchvoYHnhUfMHfpENP94rv4VZmjdCxHpHCk8Ns1GzIhSpW8Eq5DOhWiRSluoq3I35D7oFEZ78WnSQVo4MpUYL")
API_TOKEN = os.getenv("API_TOKEN", "EykQzKFlAUGSyAXapXL7H9kpf4IOfPathnXkJYpza9jnuq61TuGj1DHrbzpr")

# Add startup logging
logger.info(f"AUTHENTIK_ISSUER: {AUTHENTIK_ISSUER}")
logger.info(f"AUTHENTIK_JWKS_URL: {AUTHENTIK_JWKS_URL}")
logger.info(f"CLIENT_ID: {CLIENT_ID}")
logger.info(f"DEBUG_AUTH_MODE: {DEBUG_AUTH_MODE}")

if DEBUG_AUTH_MODE:
    logger.warning("RUNNING IN DEBUG AUTH MODE - TOKEN VERIFICATION IS RELAXED")
    logger.warning("DO NOT USE THIS SETTING IN PRODUCTION")

templates = Jinja2Templates(directory="templates")
todos_db = []

# Global cache for JWKS
_JWKS_CACHE = {"keys": None, "expiry": 0}
_JWKS_CACHE_TTL = 3600  # 1 hour

async def get_jwks():
    """Fetches the JSON Web Key Set from Authentik with caching."""
    global _JWKS_CACHE
    
    # Return cached JWKS if still valid
    current_time = time.time()
    if _JWKS_CACHE["keys"] and current_time < _JWKS_CACHE["expiry"]:
        logger.debug("Using cached JWKS")
        return _JWKS_CACHE["keys"]
    
    logger.debug(f"Fetching JWKS from {AUTHENTIK_JWKS_URL}")
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(AUTHENTIK_JWKS_URL)
            response.raise_for_status()
            jwks = response.json()
            
            # Verify we have a valid JWKS format
            if "keys" not in jwks:
                logger.error(f"Invalid JWKS format: {jwks}")
                raise HTTPException(status_code=502, detail="Invalid JWKS format from provider")
                
            logger.debug(f"JWKS fetched successfully with {len(jwks['keys'])} keys")
            
            # Cache the result
            _JWKS_CACHE["keys"] = jwks
            _JWKS_CACHE["expiry"] = current_time + _JWKS_CACHE_TTL
            
            return jwks
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to get JWKS (HTTP error): {e.response.status_code} - {e.response.text}")
            raise HTTPException(status_code=502, detail=f"Could not retrieve signing keys: HTTP error {e.response.status_code}")
        except httpx.RequestError as e:
            logger.error(f"Failed to get JWKS (request error): {str(e)}")
            raise HTTPException(status_code=502, detail=f"Could not retrieve signing keys: {str(e)}")
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse JWKS: {str(e)}")
            raise HTTPException(status_code=502, detail="Could not parse signing keys from provider.")

async def get_current_user(
    access_token: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None)
):
    """Validates the access token from cookie or Authorization header."""
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1]
        logger.debug("Token extracted from Authorization header")
    elif access_token:
        token = access_token
        logger.debug("Token extracted from cookie")
    
    if not token:
        logger.error("No token found in request")
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        logger.debug("Fetching JWKS from provider")
        jwks = await get_jwks()
        valid_issuers = [
            AUTHENTIK_ISSUER,
            AUTHENTIK_ISSUER.rstrip('/')
        ]
        
        # Log token details for debugging
        logger.debug(f"Valid issuers: {valid_issuers}")
        logger.debug(f"CLIENT_ID: {CLIENT_ID}")
        logger.debug(f"JWKS URL: {AUTHENTIK_JWKS_URL}")
        
        # Add more detailed logging and disable some validations for troubleshooting
        # This is temporary for debugging purposes
        try:
            # First try with all validations enabled
            payload = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=CLIENT_ID,
                issuer=valid_issuers,
                options={"leeway": 30}  # Increased leeway for clock skew
            )
            logger.debug("Token validation succeeded with full validation")
            return payload
        except JWTError as full_validation_error:
            logger.error(f"Full validation failed: {str(full_validation_error)}")
            
            # Try with relaxed issuer validation - common source of problems
            try:
                logger.debug("Attempting validation with relaxed issuer check")
                payload = jwt.decode(
                    token,
                    jwks,
                    algorithms=["RS256"],
                    audience=CLIENT_ID,
                    options={"verify_iss": False, "leeway": 30}
                )
                logger.warning("Token validation succeeded with relaxed issuer validation")
                return payload
            except JWTError as issuer_error:
                logger.error(f"Issuer-relaxed validation failed: {str(issuer_error)}")
                
                # As a last resort, try with minimal validation
                try:
                    logger.debug("Attempting validation with minimal checks")
                    payload = jwt.decode(
                        token,
                        jwks,
                        algorithms=["RS256"],
                        options={
                            "verify_aud": False,
                            "verify_iss": False,
                            "verify_exp": True,
                            "leeway": 30
                        }
                    )
                    logger.warning("Token validation succeeded with minimal validation")
                    # Log what would have failed
                    if "iss" in payload:
                        logger.debug(f"Token issuer: {payload['iss']}")
                    if "aud" in payload:
                        logger.debug(f"Token audience: {payload['aud']}")
                    return payload
                except JWTError as minimal_error:
                    logger.error(f"Even minimal validation failed: {str(minimal_error)}")
                    raise
    except JWTError as e:
        logger.error(f"JWT validation failed. Error: {e}")
        # Log the first part of the token for debugging (don't log full token in production)
        if token:
            token_parts = token.split('.')
            if len(token_parts) >= 2:
                import base64
                import json
                try:
                    header = json.loads(base64.urlsafe_b64decode(token_parts[0] + '==').decode('utf-8'))
                    logger.debug(f"Token header: {header}")
                    payload_part = json.loads(base64.urlsafe_b64decode(token_parts[1] + '==').decode('utf-8'))
                    logger.debug(f"Token payload issuer: {payload_part.get('iss')}")
                    logger.debug(f"Token payload audience: {payload_part.get('aud')}")
                    logger.debug(f"Token payload expiration: {payload_part.get('exp')}")
                except Exception as decode_error:
                    logger.error(f"Error decoding token parts: {decode_error}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

@app.get("/", response_class=HTMLResponse)
async def root(request: Request, current_user: dict | None = Depends(get_auth_dependency())):
    """Redirects to frontend if logged in, otherwise to login."""
    if current_user:
        return RedirectResponse(url="http://35.225.173.123:5174")
    return RedirectResponse(url="http://35.225.173.123:5174/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Serves the fallback login page (Jinja2)."""
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def handle_login(request: Request, email: str = Form(...), password: str = Form(...)):
    """Handles the login flow via Authentik and returns an access token."""
    redirect_uri = "http://35.225.173.123:8000/auth/callback"
    logger.debug(f"Redirect URI: {redirect_uri}")

    async with httpx.AsyncClient(timeout=30.0, cookies=None, follow_redirects=True) as client:
        # Start fast-login flow
        init_response = await client.get(f"{AUTHENTIK_API_BASE}flows/executor/fast-login/")
        logger.debug(f"Init response: {init_response.json()}")
        if 'authentik_session' not in client.cookies:
            logger.error("Failed to initiate login flow: No session cookie received")
            raise HTTPException(status_code=500, detail="Failed to initiate login flow.")

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
            raise HTTPException(status_code=401, detail=f"Invalid credentials: {ident_response.json().get('response_errors')}")

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
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        # Start OIDC flow
        scopes = "openid profile email"
        auth_params = f"response_type=code&client_id={CLIENT_ID}&redirect_uri={redirect_uri}&scope={scopes.replace(' ', '%20')}"
        auth_response = await client.get(f"{AUTHENTIK_AUTHORIZATION_URL}?{auth_params}")
        logger.debug(f"Auth Response URL: {auth_response.url}")

        # Check for consent screen
        if "/if/flow/" in str(auth_response.url):
            logger.error("OIDC flow interrupted by consent screen. Configure implicit consent in Authentik.")
            raise HTTPException(status_code=500, detail="Login failed: User consent required. See server logs.")

        # Extract authorization code
        parsed_url = urlparse(str(auth_response.url))
        query_params = parse_qs(parsed_url.query)
        code = query_params.get("code", [None])[0]
        logger.debug(f"Extracted Code: {code}")

        if not code:
            logger.error("Failed to get authorization code")
            raise HTTPException(status_code=500, detail="Failed to get authorization code.")

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
            raise HTTPException(status_code=500, detail=f"Token exchange failed: {token_response.text}")

        access_token = token_response.json().get("access_token")
        logger.debug(f"Access Token: {access_token}")

        return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/callback")
async def auth_callback():
    """Dummy endpoint for OIDC redirect URI."""
    return {"status": "ok"}

@app.get("/tasks/", response_model=List[TodoBase])
async def get_tasks(current_user: dict = Depends(get_auth_dependency())):
    """Returns the list of tasks."""
    return todos_db

@app.post("/tasks/")
async def create_task(todo: TodoBase, current_user: dict = Depends(get_auth_dependency())):
    """Creates a new task."""
    todo_dict = todo.dict()
    todo_dict["id"] = len(todos_db) + 1
    todo_dict["created_at"] = "2025-07-17T15:00:00Z"
    todos_db.append(todo_dict)
    return todo_dict

@app.put("/tasks/{id}/toggle-complete")
async def toggle_complete(id: int, current_user: dict = Depends(get_auth_dependency())):
    """Toggles the completion status of a task."""
    for todo in todos_db:
        if todo["id"] == id:
            todo["completed"] = not todo["completed"]
            return {"message": "Toggle successful", "todo": todo}
    raise HTTPException(status_code=404, detail="Todo not found")

@app.delete("/tasks/{id}")
async def delete_task(id: int, current_user: dict = Depends(get_auth_dependency())):
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
        raise HTTPException(status_code=400, detail="Passwords do not match")

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
            raise HTTPException(status_code=e.response.status_code, detail=f"Registration failed: {e.response.json().get('detail', e.response.text)}")
        except httpx.ReadTimeout:
            logger.error("Timeout connecting to Authentik server")
            raise HTTPException(status_code=504, detail="Timeout connecting to Authentik server.")

    return {"message": "Registration successful! You can now log in."}

@app.get("/logout")
async def logout():
    """Logs out the user by clearing the cookie."""
    response = JSONResponse(content={"message": "Logout successful"})
    response.delete_cookie("access_token", path="/", domain="localhost")
    return response

@app.get("/debug/token")
async def debug_token(request: Request, authorization: str | None = Header(default=None)):
    """Debug endpoint to check token details."""
    if not authorization or not authorization.startswith("Bearer "):
        return {"error": "No valid authorization header found"}
    
    token = authorization.split("Bearer ")[1]
    token_parts = token.split('.')
    if len(token_parts) < 2:
        return {"error": "Invalid JWT format"}
    
    try:
        import base64
        import json
        
        # Decode header
        header_bytes = base64.urlsafe_b64decode(token_parts[0] + '==')
        header = json.loads(header_bytes.decode('utf-8'))
        
        # Decode payload
        payload_bytes = base64.urlsafe_b64decode(token_parts[1] + '==')
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        # Check if JWKS endpoint is accessible
        jwks_status = "Unknown"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                jwks_response = await client.get(AUTHENTIK_JWKS_URL)
                jwks_status = f"OK ({jwks_response.status_code})" if jwks_response.ok else f"Error ({jwks_response.status_code})"
        except Exception as e:
            jwks_status = f"Error: {str(e)}"
        
        return {
            "token_format": "Valid JWT format",
            "header": header,
            "payload_info": {
                "iss": payload.get("iss"),
                "sub": payload.get("sub"),
                "aud": payload.get("aud"),
                "exp": payload.get("exp"),
                "iat": payload.get("iat"),
                "current_time": int(time.time()),
                "time_until_expiry": payload.get("exp", 0) - int(time.time()) if payload.get("exp") else None
            },
            "authentik_config": {
                "issuer": AUTHENTIK_ISSUER,
                "jwks_url": AUTHENTIK_JWKS_URL,
                "jwks_status": jwks_status,
                "client_id": CLIENT_ID
            },
            "validation_check": {
                "issuer_match": payload.get("iss") == AUTHENTIK_ISSUER or payload.get("iss") == AUTHENTIK_ISSUER.rstrip('/'),
                "audience_match": payload.get("aud") == CLIENT_ID,
                "token_expired": payload.get("exp", 0) < time.time() if payload.get("exp") else None
            }
        }
    except Exception as e:
        return {"error": f"Failed to decode token: {str(e)}"}

@app.get("/debug/token-test")
async def test_token(request: Request, authorization: str | None = Header(default=None)):
    """Test endpoint that accepts any token without JWKS validation."""
    if not authorization or not authorization.startswith("Bearer "):
        return {"error": "No valid authorization header found"}
    
    token = authorization.split("Bearer ")[1]
    
    try:
        # Just decode without verification
        token_parts = token.split('.')
        if len(token_parts) < 2:
            return {"error": "Invalid token format"}
            
        import base64
        import json
        
        # Parse header
        header_bytes = base64.urlsafe_b64decode(token_parts[0] + '==')
        header = json.loads(header_bytes.decode('utf-8'))
        
        # Parse payload
        padded = token_parts[1] + '=' * (-len(token_parts[1]) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        return {
            "status": "Token parsed successfully (without validation)",
            "header": header,
            "payload_summary": {
                "sub": payload.get("sub"),
                "exp": payload.get("exp"),
                "iat": payload.get("iat"),
                "iss": payload.get("iss"),
                "aud": payload.get("aud")
            },
            "user_info": {
                "email": payload.get("email"),
                "username": payload.get("preferred_username"),
                "name": payload.get("name")
            }
        }
    except Exception as e:
        logger.error(f"Token test error: {e}")
        return {"error": f"Failed to parse token: {str(e)}"}

