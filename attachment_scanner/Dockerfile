FROM python:3.10-slim

WORKDIR /app

# Install system dependencies (needed for yara and other analyzers)
RUN apt-get update && apt-get install -y \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8007

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8007"]
