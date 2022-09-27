from unittest import result
from celery import Celery
from app.config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND

celery = Celery(
    "celery_app",
    broker=CELERY_BROKER_URL,
    result=CELERY_RESULT_BACKEND,
    include=[
        "app.celery_worker.psifos.tasks",
        "app.celery_worker.psifos_auth.tasks"
    ]
)
