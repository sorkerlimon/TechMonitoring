FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy only application code (see .dockerignore for build-context exclusions)
COPY app.py database.py mail_send.py notification.py report_pdf.py report_settings.py techlog.py weekly_report.py ./
COPY static ./static

RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "3", "--threads", "2", "--timeout", "60", "app:app"]
