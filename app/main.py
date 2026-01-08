"""Main module for the To-Do application."""

from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis

from app.config import settings
from app.database import create_db_and_tables
from app.routers import tasks, users, auth

ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for FastAPI app."""
    # Startup code can be added here
    create_db_and_tables()
    try:
        redis_connection = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

        redis_connection.ping()
        print("Connected to Redis successfully!")

        app.state.redis = redis_connection
        await FastAPILimiter.init(redis_connection)

    except Exception as e:
        print(f"Failed to connect to Redis: {e}")

        raise e 

    yield
    # Shutdown code can be added here

    print("Shutting down Redis connection...")
    await app.state.redis.close()

app = FastAPI(
    title="MindOw API",
    description="Smart task manager app",
    lifespan=lifespan
)
  

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
def main(_:None = Depends(RateLimiter(times=5, seconds=60))):
    """Root endpoint."""
    return {"message": "Welcome to the To-Do API!"}