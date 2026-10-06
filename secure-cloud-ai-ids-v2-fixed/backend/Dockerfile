FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app \
    SECRET_KEY=change-this-secret-key \
    ALGORITHM=HS256 \
    ACCESS_TOKEN_EXPIRE_MINUTES=120 \
    DATABASE_URL=sqlite:////app/data/sql_app.db

RUN python3 app/ml/train.py

RUN mkdir -p /app/data
EXPOSE 8000

CMD ["sh", "-c", "python3 app/db/init_db.py && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
