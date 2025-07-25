from typing import List, Optional
from domain.entities import Task
from infrastructure.database import Database

class TaskUseCases:
    def __init__(self, db: Database):
        self.db = db

    def create_task(self, title: str, description: Optional[str] = None, user_id: str = "dummy-user-id") -> Task:
        task = Task(title=title, description=description)
        return self.db.create_task(task, user_id)

    def get_task(self, task_id: int, user_id: str = "dummy-user-id") -> Optional[Task]:
        return self.db.get_task_by_id(task_id, user_id)

    def get_all_tasks(self, user_id: str = "dummy-user-id") -> List[Task]:
        return self.db.get_all_tasks(user_id)

    def update_task(self, task_id: int, title: Optional[str] = None, description: Optional[str] = None, completed: Optional[bool] = None, user_id: str = "dummy-user-id") -> Optional[Task]:
        task = self.get_task(task_id, user_id)
        if not task:
            return None
        updated_task = Task(
            id=task.id,
            title=title if title is not None else task.title,
            description=description if description is not None else task.description,
            completed=completed if completed is not None else task.completed,
            created_at=task.created_at
        )
        return self.db.update_task(task_id, updated_task, user_id)

    def delete_task(self, task_id: int, user_id: str = "dummy-user-id") -> bool:
        return self.db.delete_task(task_id, user_id)