from sqlmodel import create_engine, SQLModel
from .config import settings

engine = create_engine(settings.DATABASE_URL, echo=True)

#create databse and tables
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)