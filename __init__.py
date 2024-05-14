import asyncio

from fastapi import APIRouter
from loguru import logger

from lnbits.db import Database
from lnbits.helpers import template_renderer
from lnbits.tasks import create_permanent_unique_task

db = Database("ext_nostrnip5")

nostrnip5_static_files = [
    {
        "path": "/nostrnip5/static",
        "name": "nostrnip5_static",
    }
]

nostrnip5_ext: APIRouter = APIRouter(prefix="/nostrnip5", tags=["nostrnip5"])


def nostrnip5_renderer():
    return template_renderer(["nostrnip5/templates"])


from .tasks import wait_for_paid_invoices
from .views import *  # noqa: F401,F403
from .views_api import *  # noqa: F401,F403


scheduled_tasks: list[asyncio.Task] = []

def nostrnip5_stop():
    for task in scheduled_tasks:
        try:
            task.cancel()
        except Exception as ex:
            logger.warning(ex)

def nostrnip5_start():
    task = create_permanent_unique_task("ext_nostrnip5", wait_for_paid_invoices)
    scheduled_tasks.append(task)
