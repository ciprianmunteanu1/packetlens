from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import create_engine

# Create database engine, Base class and session maker
engine = create_engine("sqlite:///packets.db", echo=True)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Function to create session and yield it to FastApi endpoints
def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()