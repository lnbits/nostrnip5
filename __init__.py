import asyncio

from fastapi import APIRouter

from lnbits.db import Database
from lnbits.helpers import template_renderer
from lnbits.tasks import catch_everything_and_restart

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


def nostrnip5_start():
    loop = asyncio.get_event_loop()
    loop.create_task(catch_everything_and_restart(wait_for_paid_invoices))


from .views import *  # noqa: F401,F403
from .views_api import *  # noqa: F401,F403
