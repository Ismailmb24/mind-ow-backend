from sqlmodel import SQLModel, Field, Relationship
from uuid import UUID, uuid4
from enum import Enum
from datetime import datetime, timezone

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


# User model

# User status enumeration
class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    BANNED = "banned"
    DELETED = "deleted"

# User authentication enumeration
class UserRoleEnum(str, Enum):
    USER = "user"
    ADMIN = "admin"
    OWNER = "owner"

class UserBase(SQLModel):
    # identification fields
    email: str = Field(unique=True, index=True)
    email_verified_at: datetime | None = None

    # profile fields
    username: str | None = None
    full_name: str | None = None
    bio: str | None = None
    avatar_url: str | None = None
    
    # status fields
    status: StatusEnum = Field(default=StatusEnum.ACTIVE)

    # Authorization fields
    role: UserRoleEnum = Field(default=UserRoleEnum.USER)  # e.g., user, admin

    #meta data
    created_at: datetime | None = Field(default_factory=now, nullable=False)  # ISO format date string
    updated_at: datetime | None = Field(default_factory=now, nullable=False)  # ISO format date string


class User(UserBase, table=True):
    id: UUID | None = Field(default_factory=uuid4, primary_key=True)
    hashed_password: str

    refresh_tokes: list["RefreshToken"] = Relationship(back_populates="user")

class UserCreate(UserBase):
    password: str

class UserPublic(UserBase):
    id: UUID

#token models
class Token(SQLModel):
    access_token: str
    token_type: str

class TokenData(SQLModel):
    user_id: str | None = None

class RefreshToken(SQLModel, table=True):
    id: UUID | None = Field(default_factory=uuid4, primary_key=True)
    token: str
    expired_at: datetime

    user_id: UUID = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="refresh_tokes")