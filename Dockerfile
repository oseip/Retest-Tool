FROM python:3.13-slim

WORKDIR /app

# Install dependencies first (cached layer — only rebuilds when requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source and frontend
COPY src/ ./src/
COPY frontend/ ./frontend/

# config/ is intentionally NOT copied — it is mounted at runtime so credentials
# are never baked into the image.

EXPOSE 8000

CMD ["uvicorn", "src.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000"]
