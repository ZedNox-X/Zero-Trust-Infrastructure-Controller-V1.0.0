FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml README.md ./
COPY controller ./controller
COPY policies ./policies
RUN pip install --no-cache-dir . && adduser --disabled-password --gecos '' app
USER app
EXPOSE 8000
CMD ["uvicorn","controller.main:app","--host","0.0.0.0","--port","8000"]
