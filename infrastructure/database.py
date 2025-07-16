import sqlite3
from typing import List, Optional
from domain.entities import Task
from datetime import datetime

class Database:
    def __init__(self, db_name: str = "todo.db"):
        self.db_name = db_name
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    completed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def create_task(self, task: Task) -> Task:
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO tasks (title, description, completed, created_at) VALUES (?, ?, ?, ?)",
                (task.title, task.description or None, 1 if task.completed else 0, task.created_at.isoformat())
            )
            conn.commit()
            task.id = cursor.lastrowid
            return task

    def get_task_by_id(self, task_id: int) -> Optional[Task]:
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, description, completed, created_at FROM tasks WHERE id = ?", (task_id,))
            row = cursor.fetchone()
            if row:
                return Task(
                    id=row[0],
                    title=row[1],
                    description=row[2],
                    completed=bool(row[3]),
                    created_at=datetime.fromisoformat(row[4])
                )
            return None

    def get_all_tasks(self) -> List[Task]:
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, description, completed, created_at FROM tasks")
            rows = cursor.fetchall()
            return [
                Task(
                    id=row[0],
                    title=row[1],
                    description=row[2],
                    completed=bool(row[3]),
                    created_at=datetime.fromisoformat(row[4])
                ) for row in rows
            ]

    def update_task(self, task_id: int, updated_task: Task) -> Optional[Task]:
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE tasks SET title = ?, description = ?, completed = ? WHERE id = ?",
                (
                    updated_task.title if updated_task.title is not None else None,
                    updated_task.description if updated_task.description is not None else None,
                    1 if updated_task.completed else 0,
                    task_id
                )
            )
            conn.commit()
            if cursor.rowcount > 0:
                return self.get_task_by_id(task_id)
            return None

    def delete_task(self, task_id: int) -> bool:
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.commit()
            return cursor.rowcount > 0