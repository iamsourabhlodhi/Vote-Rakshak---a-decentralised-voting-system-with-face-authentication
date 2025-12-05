# backend/models.py
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.mysql import LONGBLOB
import urllib.parse

# ---------------- DB CONFIG ----------------
MYSQL_USER = "root"
MYSQL_PASSWORD = "@2318S"
MYSQL_HOST = "127.0.0.1"
MYSQL_PORT = "3306"
MYSQL_DB = "decentralised_voting"

encoded_password = urllib.parse.quote_plus(MYSQL_PASSWORD)
DATABASE_URL = (
    f"mysql+pymysql://{MYSQL_USER}:{encoded_password}@"
    f"{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
)

Base = declarative_base()

# ---------------- MODELS ----------------

class Admin(Base):
    __tablename__ = "admin"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(300), nullable=False)

    # FIXED → Now supports full-size face embedding (150 KB+)
    face_encoding = Column(LONGBLOB, nullable=False)


class Voter(Base):
    __tablename__ = "voters"

    id = Column(Integer, primary_key=True, autoincrement=True)
    enrollment = Column(String(50), unique=True, nullable=False)
    name = Column(String(100), nullable=False)

    # FIXED → Now supports full-size encoding for all voters
    face_encoding = Column(LONGBLOB, nullable=True)


# ---------------- ENGINE + SESSION ----------------

engine = create_engine(DATABASE_URL, echo=False)

# Create tables if not exist
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()

print("✅ DB Ready")
