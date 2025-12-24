from sqlmodel import create_engine, SQLModel
from .config import settings

connect_args = {"check_same_thread": False}
engine = create_engine(settings.DATABASE_URL, echo=True, connect_args=connect_args)

#create databse and tables
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)