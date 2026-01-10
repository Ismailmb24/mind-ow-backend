from datetime import datetime

from sqlmodel import Session, select

from app.models.models import User
from app.models.task import Task
from app.utils.tier import CAPABILITIES, resolve_user_tier
from sqlalchemy import func
from fastapi import HTTPException

def check_project_limit(user: User, session: Session):
    """Check if the user can create a new project based on their tier."""
    tier = resolve_user_tier(user)
    max_projects = CAPABILITIES[tier]["max_projects"]

    if max_projects == 999:
        return
    
    project_count = session.exec(
            select(func.count()).select_from(Task).where(Task.user_id == user.id)
    )

    if project_count >= max_projects:
        raise HTTPException(status_code=403, detail="Project limit reached. Upgrade your plan to create more projects.")