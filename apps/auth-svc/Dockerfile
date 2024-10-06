FROM python:3.12-slim

RUN pip install uv
WORKDIR /app
COPY requirements.lock .
RUN uv pip install --no-cache --system -r requirements.lock
COPY acl.yaml src ./

EXPOSE 8000
USER nobody
CMD ["uvicorn", "auth_svc.main:app", "--host", "0.0.0.0", "--port", "8000"]
