from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, HTTPException, status

from sqlmodel import Session, select
from ..models import TaskCreate, TaskPublic, Task, TaskUpdate
from ..dependencies import get_session

router = APIRouter(
    prefix="/tasks",
    tags=["tasks"]
)


@router.post("/", response_model=TaskPublic)
async def tasks(task: TaskCreate, session: Annotated[Session, Depends(get_session)]):
    db_task = Task.model_validate(task)
    session.add(db_task)
    session.commit()
    session.refresh(db_task)

    return TaskPublic.model_validate(db_task.model_dump())


@router.get("/", response_model=list[TaskPublic])
async def get_tasks(session: Annotated[Session, Depends(get_session)], skip: int = 0, limit: Annotated[int, Query(le=100)] = 100):
    statement = select(Task).offset(skip).limit(limit)
    tasks = session.exec(statement).all()

    return tasks


@router.patch("/{task_id}", response_model=TaskPublic)
async def update_task(session: Annotated[Session, Depends(get_session)], task_id: UUID, task: TaskUpdate):
    db_task = session.get(Task, task_id)
    if not db_task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Hero not found")
    task_data = task.model_dump(exclude_unset=True)
    db_task.sqlmodel_update(task_data)
    session.add(db_task)
    session.commit()
    session.refresh(db_task)

    return db_task
