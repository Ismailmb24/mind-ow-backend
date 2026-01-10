from datetime import datetime, timezone

from sqlmodel import SQLModel, Field
from uuid import UUID, uuid4
from enum import Enum

class Priority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class TaskType(Enum):
    WORK = "work"
    PERSONAL = "personal"
    OTHER = "other"

def now():
    return datetime.now(timezone.utc)

class TaskBase(SQLModel):
    title: str
    description: str | None = None
    completed: bool = Field(default=False)
    task_type: str = Field(default=TaskType.PERSONAL.value)
    priority: Priority = Field(default=Priority.MEDIUM.value)  # e.g., low, medium, high
    due_date: str | None = None  # ISO format date string
    created_at: datetime | None = Field(default_factory=now, nullable=False)  # ISO format date string
    updated_at: datetime | None = Field(default_factory=now, nullable=False)  # ISO format date string

class Task(TaskBase, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)

    user_id: UUID = Field(foreign_key="user.id")

class TaskCreate(TaskBase):
    pass

class TaskPublic(TaskBase):
    id: UUID

class TaskUpdate(SQLModel):
    title: str | None = None
    description: str | None = None
    completed: bool | None = None
    task_type: str | None = None
    priority: Priority | None = None
    due_date: str | None = None
    updated_at: str | None = None  # ISO format date string
