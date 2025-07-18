# interfaces/api.py
from fastapi import APIRouter, HTTPException, Depends
from schemas.task import TaskCreate, TaskUpdate, TaskResponse
from application.use_cases import TaskUseCases
from infrastructure.database import Database
from datetime import datetime
from typing import List
import logging

# کد Authentik رو اضافه می‌کنیم
from jose import jwt, JWTError
import httpx
import os
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()
db = Database()
use_cases = TaskUseCases(db)

# تنظیمات Authentik
AUTHENTIK_ISSUER = os.getenv("AUTHENTIK_ISSUER", "http://34.57.98.21/application/o/fast-api-dashboard/")
AUTHENTIK_JWKS_URL = f"{AUTHENTIK_ISSUER}jwks/"
CLIENT_ID = os.getenv("CLIENT_ID", "0kDGte5FD7g7sxB5sNJqiTfE0puDJf5mubxWi44W")

async def get_jwks():
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(AUTHENTIK_JWKS_URL)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPStatusError, json.JSONDecodeError) as e:
            logger.error(f"Failed to get or parse JWKS: {e}")
            raise HTTPException(status_code=502, detail="Could not retrieve signing keys from provider.")

async def get_current_user(access_token: str | None = Depends(lambda: None)):  # موقتاً بدون کوکی
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        jwks = await get_jwks()
        payload = jwt.decode(
            access_token,
            jwks,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=AUTHENTIK_ISSUER,
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/tasks/", response_model=TaskResponse)
async def create_task(task: TaskCreate, current_user: dict = Depends(get_current_user)):
    created_task = use_cases.create_task(task.title, task.description, current_user["sub"])
    created_at_str = created_task.created_at.strftime("%b %d, %Y")
    return TaskResponse(
        id=created_task.id,
        title=created_task.title,
        description=created_task.description,
        completed=created_task.completed,
        created_at=created_at_str
    )

@router.get("/tasks/", response_model=List[TaskResponse])
async def get_all_tasks(current_user: dict = Depends(get_current_user)):
    tasks = use_cases.get_all_tasks(current_user["sub"])
    return [
        TaskResponse(
            id=task.id,
            title=task.title,
            description=task.description,
            completed=task.completed,
            created_at=task.created_at.strftime("%b %d, %Y")
        ) for task in tasks
    ]

@router.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(task_id: int, current_user: dict = Depends(get_current_user)):
    task = use_cases.get_task(task_id, current_user["sub"])
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    created_at_str = task.created_at.strftime("%b %d, %Y")
    return TaskResponse(
        id=task.id,
        title=task.title,
        description=task.description,
        completed=task.completed,
        created_at=created_at_str
    )

@router.put("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(task_id: int, task: TaskUpdate, current_user: dict = Depends(get_current_user)):
    updated_task = use_cases.update_task(task_id, task.title, task.description, task.completed, current_user["sub"])
    if not updated_task:
        raise HTTPException(status_code=404, detail="Task not found")
    created_at_str = updated_task.created_at.strftime("%b %d, %Y")
    return TaskResponse(
        id=updated_task.id,
        title=updated_task.title,
        description=updated_task.description,
        completed=updated_task.completed,
        created_at=created_at_str
    )

@router.delete("/tasks/{task_id}")
async def delete_task(task_id: int, current_user: dict = Depends(get_current_user)):
    if not use_cases.delete_task(task_id, current_user["sub"]):
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deleted"}

@router.put("/tasks/{task_id}/toggle-complete", response_model=TaskResponse)
async def toggle_task_completion(task_id: int, current_user: dict = Depends(get_current_user)):
    task = use_cases.get_task(task_id, current_user["sub"])
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    logger.info(f"Toggling task {task_id}: current completed = {task.completed}")
    new_completed = not task.completed
    updated_task = use_cases.update_task(task_id, completed=new_completed, user_id=current_user["sub"])
    if not updated_task:
        raise HTTPException(status_code=500, detail="Failed to toggle task completion")
    logger.info(f"Task {task_id} toggled to completed = {updated_task.completed}")
    created_at_str = updated_task.created_at.strftime("%b %d, %Y")
    return TaskResponse(
        id=updated_task.id,
        title=updated_task.title,
        description=updated_task.description,
        completed=updated_task.completed,
        created_at=created_at_str
    )