from http import HTTPStatus
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from lnbits.core.models import User
from lnbits.decorators import check_user_exists
from lnbits.helpers import template_renderer

from .crud import (
    get_address,
    get_domain_public_data,
)
from .helpers import format_amount
from .models import AddressStatus
from .services import get_identifier_status

templates = Jinja2Templates(directory="templates")

nostrnip5_generic_router: APIRouter = APIRouter()


def nostrnip5_renderer():
    return template_renderer(["nostrnip5/templates"])


@nostrnip5_generic_router.get("/", response_class=HTMLResponse)
async def index(request: Request, user: User = Depends(check_user_exists)):
    return nostrnip5_renderer().TemplateResponse(
        "nostrnip5/index.html", {"request": request, "user": user.dict()}
    )


# @nostrnip5_generic_router.get("/signup/{domain}", response_class=HTMLResponse)
# async def index(request: Request, user: User = Depends(check_user_exists)):
#     return nostrnip5_renderer().TemplateResponse(
#         "nostrnip5/domain.html", {"request": request, "user": user.dict()}
#     )


@nostrnip5_generic_router.get("/signup/{domain_id}", response_class=HTMLResponse)
async def signup(request: Request, domain_id: str, identifier: Optional[str] = None):
    domain_public_data = await get_domain_public_data(domain_id)

    if not domain_public_data:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Domain does not exist."
        )

    if identifier:
        status = await get_identifier_status(domain_id, identifier)
        identifier_cost = (
            format_amount(status.price, status.currency) if status.available else ""
        )
    else:
        status = AddressStatus(available=True)
        identifier_cost = ""

    return nostrnip5_renderer().TemplateResponse(
        "nostrnip5/signup.html",
        {
            "request": request,
            "domain_id": domain_id,
            "domain": domain_public_data,
            "identifier": identifier,
            "identifier_cost": identifier_cost,
            "identifier_available": status.available,
        },
    )


@nostrnip5_generic_router.get(
    "/rotate/{domain_id}/{address_id}", response_class=HTMLResponse
)
async def rotate(request: Request, domain_id: str, address_id: str):
    domain = await get_domain_public_data(domain_id)
    address = await get_address(domain_id, address_id)

    if not domain:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Domain does not exist."
        )

    if not address:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Address does not exist."
        )

    return nostrnip5_renderer().TemplateResponse(
        "nostrnip5/rotate.html",
        {
            "request": request,
            "domain_id": domain_id,
            "domain": domain,
            "address_id": address_id,
            "address": address,
        },
    )
