from fastapi import APIRouter, HTTPException
from schemas.task import TaskCreate, TaskUpdate, TaskResponse
from application.use_cases import TaskUseCases
from infrastructure.database import Database
from datetime import datetime
from typing import List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()
db = Database()
use_cases = TaskUseCases(db)

@router.post("/tasks/", response_model=TaskResponse)
async def create_task(task: TaskCreate):
    created_task = use_cases.create_task(task.title, task.description)
    created_at_str = created_task.created_at.strftime("%b %d, %Y")
    return TaskResponse(
        id=created_task.id,
        title=created_task.title,
        description=created_task.description,
        completed=created_task.completed,
        created_at=created_at_str
    )

@router.get("/tasks/", response_model=List[TaskResponse])
async def get_all_tasks():
    tasks = use_cases.get_all_tasks()
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
async def get_task(task_id: int):
    task = use_cases.get_task(task_id)
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
async def update_task(task_id: int, task: TaskUpdate):
    updated_task = use_cases.update_task(task_id, task.title, task.description, task.completed)
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
async def delete_task(task_id: int):
    if not use_cases.delete_task(task_id):
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deleted"}

@router.put("/tasks/{task_id}/toggle-complete", response_model=TaskResponse)
async def toggle_task_completion(task_id: int):
    task = use_cases.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    logger.info(f"Toggling task {task_id}: current completed = {task.completed}")
    new_completed = not task.completed
    updated_task = use_cases.update_task(task_id, completed=new_completed)
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