from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import os
from dotenv import load_dotenv
import html
TOKEN_TYPE = os.getenv("TOKEN_TYPE", "bearer")
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY не найден в .env файле")

ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data.db")

app = FastAPI(
    title="Secure REST API",
    description="Защищенный REST API для лабораторной работы",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

security = HTTPBearer()

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Publication(Base):
    __tablename__ = "publications"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    author_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    username: str
    password: str

class PublicationCreate(BaseModel):
    title: str = Field(..., max_length=255)
    content: str
    
    @validator('title', 'content')
    def escape_html(cls, v):
        """Защита от XSS - экранирование HTML"""
        return html.escape(v)

class PublicationUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=255)
    content: Optional[str] = None
    
    @validator('title', 'content')
    def escape_html(cls, v):
        if v:
            return html.escape(v)
        return v

class PublicationOut(BaseModel):
    id: int
    title: str
    content: str
    author_id: int
    created_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный токен",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    return user

@app.post("/auth/register", response_model=dict)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Пользователь уже существует")
    
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return {"message": "Пользователь создан", "user_id": db_user.id}

@app.post("/auth/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Неверные учетные данные")
    
    token = create_access_token(data={"sub": db_user.username})
    return Token(access_token=token, token_type=TOKEN_TYPE)

@app.get("/api/data", response_model=List[PublicationOut])
def get_publications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    publications = db.query(Publication).all()
    return publications

@app.get("/api/data/{id}", response_model=PublicationOut)
def get_publication(
    id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    publication = db.query(Publication).filter(Publication.id == id).first()
    if not publication:
        raise HTTPException(status_code=404, detail="Публикация не найдена")
    return publication

@app.post("/api/data", response_model=PublicationOut)
def create_publication(
    publication: PublicationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_publication = Publication(
        title=publication.title,
        content=publication.content,
        author_id=current_user.id
    )
    db.add(db_publication)
    db.commit()
    db.refresh(db_publication)
    return db_publication

@app.patch("/api/data/{id}", response_model=PublicationOut)
def update_publication(
    id: int,
    publication_update: PublicationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_publication = db.query(Publication).filter(Publication.id == id).first()
    if not db_publication:
        raise HTTPException(status_code=404, detail="Публикация не найдена")
    
    if db_publication.author_id != current_user.id:
        raise HTTPException(status_code=403, detail="Нет прав на редактирование")
    
    update_data = publication_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_publication, field, value)
    
    db.commit()
    db.refresh(db_publication)
    return db_publication

@app.delete("/api/data/{id}")
def delete_publication(
    id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    publication = db.query(Publication).filter(
        Publication.id == id,
        Publication.author_id == current_user.id
    ).first()
    
    if not publication:
        raise HTTPException(status_code=404, detail="Публикация не найдена")
    
    db.delete(publication)
    db.commit()
    return {"message": "Публикация удалена"}

@app.get("/cleaner")
def cleaner_status():
    return {"status": "Сервис очистки доступен"}

@app.post("/cleaner")
def start_cleaner(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    cutoff_date = datetime.utcnow() - timedelta(days=30)
    result = db.query(Publication).filter(Publication.created_at < cutoff_date).delete()
    db.commit()
    return {"message": f"Удалено {result} старых публикаций"}

@app.delete("/cleaner")
def stop_cleaner():
    return {"message": "Очистка остановлена"}

@app.get("/healthcheck")
def healthcheck():
    return {"status": "ok", "timestamp": datetime.utcnow()}

@app.get("/")
def root():
    return {
        "message": "Secure REST API",
        "documentation": "/docs",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=8000)
