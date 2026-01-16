FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN ls -laR
RUN cat main.py | head -5
CMD ls && uvicorn main:app --host 0.0.0.0 --port 8000