# information-security-lab-1

Лабораторная работа №1 по "Информационной безопасности" - Разработка защищенного REST API с интеграцией в CI/CD

## Стек проекта

Язык: `Python`/`FastAPI`

Менеджер пакетов: `pip`

## Разработанный API

Подробная openapi документация доступна по `/redoc` или `/docs`

### Регистрация - `POST /auth/register`

```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/auth/register' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "string",
  "password": "string"
}'
```

### Авторизация `POST /auth/login`

```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/auth/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "string",
  "password": "string"
}'
```

### `/api/data` - REST-ful endpoint-ы для CRUD операций с объектами Publication

#### `GET /api/data`

```bash
curl -X 'GET' \
  'http://127.0.0.1:8000/api/data' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer '
```

#### `POST /api/data`

```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/api/data' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer ' \
  -H 'Content-Type: application/json' \
  -d '{
  "title": "string",
  "content": "string"
}'
```

#### `GET /api/data/{id}`

```bash
curl -X 'GET' \
  'http://127.0.0.1:8000/api/data/1' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer '
```

#### `PATCH /api/data/{id}`

```bash
curl -X 'PATCH' \
  'http://127.0.0.1:8000/api/data/1' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer ' \
  -H 'Content-Type: application/json' \
  -d '{
  "title": "string",
  "content": "string"
}'
```

#### `DELETE /api/data/{id}`

```bash
curl -X 'DELETE' \
  'http://127.0.0.1:8000/api/data/1' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer '
```

### `/cleaner` – RESTful endpoint-ы для управления процессом удаления старых публикаций

#### `GET /cleaner`

```bash
curl -X 'GET' \
  'http://127.0.0.1:8000/cleaner' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer '
```

#### `POST /cleaner`

```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/cleaner' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer '
```

#### `DELETE /cleaner`

```bash
curl -X 'DELETE' \
  'http://127.0.0.1:8000/cleaner' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer '
```

## Реализованные меры защиты

### Аутентификация на основе JWT токенов

Реализовано через библиотеку `python-jose`.

```python
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
```

### Хэширование паролей

Пароли хэшируются с помощью библиотеки `passlib` и алгоритма `argon2`.

```python
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
```

### Защита от SQL-инъекций

Используется ORM `SQLAlchemy` с параметризованными запросами.

```python
def get_user_by_username(username: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    return user
```

### Защита от XSS

Используются валидируемые схемы данных `Pydantic` с экранированием HTML

```python
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
```

## Отчёт bandit
<img width="1146" height="569" alt="image" src="https://github.com/user-attachments/assets/20be7df5-2102-4ef6-96d0-58a99ef47604" />

## Отчёт OWASP Dependency Check
<img width="1120" height="991" alt="image" src="https://github.com/user-attachments/assets/32b13a7d-79ea-4a07-8ba2-8b5b9d89bd3b" />

