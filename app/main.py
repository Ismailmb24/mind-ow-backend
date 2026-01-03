"""Main module for the To-Do application."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import create_db_and_tables
from app.routers import tasks, users, auth

ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

app = FastAPI(
    title="MindOw API",
    description="Smart task manager app"
)


# startup events
@app.on_event("startup")
def on_startup():
    """Statup event function."""
    create_db_and_tables()

#middleware cors
origins = [
    "http://localhost:3000",
    "http://localhost"
]

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# routers
app.include_router(tasks.router)
app.include_router(users.router)
app.include_router(auth.router)


@app.get("/")
def read_root():
    """Root endpoint."""
    return {"message": "Welcome to the To-Do API!"}