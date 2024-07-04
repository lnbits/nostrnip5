from http import HTTPStatus
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Query, Request, Response
from lnbits.core.models import User, WalletTypeInfo
from lnbits.core.services import create_invoice
from lnbits.db import Filters, Page
from lnbits.decorators import (
    check_admin,
    check_user_exists,
    get_key_type,
    optional_user_id,
    parse_filters,
    require_admin_key,
)
from lnbits.helpers import generate_filter_params_openapi
from loguru import logger
from starlette.exceptions import HTTPException

from .crud import (
    activate_address,
    create_domain_internal,
    create_settings,
    delete_address,
    delete_domain,
    get_addresses,
    get_addresses_for_owner,
    get_domain,
    get_domain_by_id,
    get_identifier_ranking,
    get_settings,
    rotate_address,
    update_domain_internal,
    update_identifier_ranking,
)
from .helpers import (
    http_try_except,
    normalize_identifier,
    owner_id_from_user_id,
    validate_pub_key,
)
from .models import (
    Address,
    AddressFilters,
    AddressStatus,
    CreateAddressData,
    CreateDomainData,
    EditDomainData,
    IdentifierRanking,
    Nip5Settings,
    RotateAddressData,
)
from .services import (
    check_address_payment,
    create_address,
    get_identifier_status,
    get_user_addresses,
    get_user_addresses_paginated,
    get_user_domains,
    refresh_buckets,
    update_identifiers,
)

nostrnip5_api_router: APIRouter = APIRouter()

address_filters = parse_filters(AddressFilters)


@http_try_except
@nostrnip5_api_router.get("/api/v1/domains", status_code=HTTPStatus.OK)
async def api_domains(
    all_wallets: bool = Query(None), wallet: WalletTypeInfo = Depends(get_key_type)
):
    domains = await get_user_domains(wallet.wallet.user, wallet.wallet.id, all_wallets)

    return [domain.dict() for domain in domains]


@http_try_except
@nostrnip5_api_router.get("/api/v1/addresses", status_code=HTTPStatus.OK)
async def api_get_addresses(
    all_wallets: bool = Query(None), wallet: WalletTypeInfo = Depends(get_key_type)
):
    addresses = await get_user_addresses(
        wallet.wallet.user, wallet.wallet.id, all_wallets
    )

    return [address.dict() for address in addresses]


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/addresses/paginated",
    name="Addresses List",
    summary="get paginated list of addresses",
    response_description="list of addresses",
    openapi_extra=generate_filter_params_openapi(AddressFilters),
    response_model=Page[Address],
    status_code=HTTPStatus.OK,
)
async def api_get_addresses_paginated(
    all_wallets: bool = Query(None),
    filters: Filters = Depends(address_filters),
    wallet: WalletTypeInfo = Depends(get_key_type),
):
    page = await get_user_addresses_paginated(
        wallet.wallet.user, wallet.wallet.id, all_wallets, filters
    )

    return page


@http_try_except
@nostrnip5_api_router.get("/api/v1/addresses/user", status_code=HTTPStatus.OK)
async def api_get_user_addresses(
    user_id: Optional[str] = Depends(optional_user_id),
):
    if not user_id:
        raise HTTPException(HTTPStatus.UNAUTHORIZED)

    owner_id = owner_id_from_user_id(user_id)
    assert owner_id
    return [address.dict() for address in await get_addresses_for_owner(owner_id)]


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}",
    status_code=HTTPStatus.OK,
)
async def api_get_domaint(domain_id: str, w: WalletTypeInfo = Depends(get_key_type)):
    domain = await get_domain(domain_id, w.wallet.id)
    assert domain, "Domain does not exist."
    return domain


@http_try_except
@nostrnip5_api_router.post("/api/v1/domain", status_code=HTTPStatus.CREATED)
async def api_create_domain(
    data: CreateDomainData, wallet: WalletTypeInfo = Depends(get_key_type)
):

    return await create_domain_internal(wallet_id=wallet.wallet.id, data=data)


@http_try_except
@nostrnip5_api_router.put("/api/v1/domain", status_code=HTTPStatus.OK)
async def api_update_domain(
    data: EditDomainData, wallet: WalletTypeInfo = Depends(get_key_type)
):

    return await update_domain_internal(wallet_id=wallet.wallet.id, data=data)


@http_try_except
@nostrnip5_api_router.delete(
    "/api/v1/domain/{domain_id}", status_code=HTTPStatus.CREATED
)
async def api_domain_delete(
    domain_id: str,
    w: WalletTypeInfo = Depends(require_admin_key),
):
    deleted = await delete_domain(domain_id, w.wallet.id)

    return deleted


@http_try_except
@nostrnip5_api_router.delete(
    "/api/v1/address/{domain_id}/{address_id}", status_code=HTTPStatus.GONE
)
async def api_delete_address(
    domain_id: str,
    address_id: str,
    w: WalletTypeInfo = Depends(require_admin_key),
):
    # make sure the address belongs to the user
    domain = await get_domain(domain_id, w.wallet.id)
    assert domain, "Domain does not exist."

    return await delete_address(domain_id, address_id)


@http_try_except
@nostrnip5_api_router.put(
    "/api/v1/domain/{domain_id}/address/{address_id}/activate",
    status_code=HTTPStatus.OK,
)
async def api_activate_address(
    domain_id: str,
    address_id: str,
    w: WalletTypeInfo = Depends(require_admin_key),
):
    # make sure the address belongs to the user
    domain = await get_domain(domain_id, w.wallet.id)
    assert domain, "Domain does not exist."

    return await activate_address(domain_id, address_id)


@http_try_except
@nostrnip5_api_router.put(
    "/api/v1/domain/{domain_id}/address/{address_id}/rotate",
    status_code=HTTPStatus.OK,
)
async def api_address_rotate(
    domain_id: str,
    address_id: str,
    post_data: RotateAddressData,
    user_id: Optional[str] = Depends(optional_user_id),
):
    # todo: improve checks

    post_data.pubkey = validate_pub_key(post_data.pubkey)

    # todo: owner id
    await rotate_address(domain_id, address_id, post_data.pubkey)

    return True


@http_try_except
@nostrnip5_api_router.post(
    "/api/v1/domain/{domain_id}/address", status_code=HTTPStatus.CREATED
)
async def api_address_create(
    address_data: CreateAddressData,
    domain_id: str,
    user_id: Optional[str] = Depends(optional_user_id),
):

    # make sure the address belongs to the user
    domain = await get_domain_by_id(address_data.domain_id)
    assert domain, "Domain does not exist."

    assert address_data.domain_id == domain_id, "Domain ID missmatch"
    address, price_in_sats = await create_address(domain, address_data, user_id)

    payment_hash, payment_request = await create_invoice(
        wallet_id=domain.wallet,
        amount=price_in_sats,
        memo=f"Payment for NIP-05 for {address_data.local_part}@{domain.domain}",
        extra={
            "tag": "nostrnip5",
            "domain_id": domain_id,
            "address_id": address.id,
        },
    )

    return {
        "payment_hash": payment_hash,
        "payment_request": payment_request,
        "address_id": address.id,
    }


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}/payments/{payment_hash}", status_code=HTTPStatus.OK
)
async def api_check_address_payment(domain_id: str, payment_hash: str):
    paid = await check_address_payment(domain_id, payment_hash)
    return {"paid": paid}


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}/search", status_code=HTTPStatus.OK
)
async def api_search_identifier(
    domain_id: str, q: Optional[str] = None
) -> AddressStatus:

    if not q:
        return AddressStatus(identifier="")

    domain = await get_domain_by_id(domain_id)
    assert domain, "Unknown domain id."

    return await get_identifier_status(domain, q)


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}/nostr.json", status_code=HTTPStatus.OK
)
async def api_get_nostr_json(
    response: Response, domain_id: str, name: str = Query(None)
):
    addresses = [address.dict() for address in await get_addresses(domain_id)]
    output = {}

    for address in addresses:
        local_part = address.get("local_part")
        if not local_part:
            continue
        local_part = normalize_identifier(local_part)

        if address.get("active") is False:
            continue

        if name and normalize_identifier(name) != local_part:
            continue

        output[local_part] = address.get("pubkey")

    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET,OPTIONS"

    return {"names": output}


@http_try_except
@nostrnip5_api_router.put(
    "/api/v1/domain/ranking/{bucket}",
    status_code=HTTPStatus.OK,
)
async def api_refresh_identifier_ranking(
    bucket: int,
    user: User = Depends(check_admin),
):
    owner_id = owner_id_from_user_id("admin" if user.admin else user.id)
    nip5_settings = await get_settings(owner_id)

    assert nip5_settings.cloudflare_access_token, "Missing CloudFlare access token."

    headers = {"Authorization": f"Bearer {nip5_settings.cloudflare_access_token}"}
    ranking_url = "https://api.cloudflare.com/client/v4/radar/datasets?limit=12&datasetType=RANKING_BUCKET"
    dataset_url = "https://api.cloudflare.com/client/v4/radar/datasets"

    async with httpx.AsyncClient(headers=headers) as client:
        await refresh_buckets(client, ranking_url, dataset_url, bucket)


@http_try_except
@nostrnip5_api_router.patch(
    "/api/v1/domain/ranking/{bucket}",
    dependencies=[Depends(check_admin)],
    status_code=HTTPStatus.OK,
)
async def api_add_identifier_ranking(
    bucket: int,
    request: Request,
):
    identifiers = (await request.body()).decode("utf-8").splitlines()
    logger.info(f"Updating {len(identifiers)} rankings.")

    await update_identifiers(identifiers, bucket)

    logger.info(f"Updated {len(identifiers)} rankings.")

    return {"count": len(identifiers)}


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/ranking/search",
    dependencies=[Depends(check_admin)],
    status_code=HTTPStatus.OK,
)
async def api_domain_search_address(
    q: Optional[str] = None,
) -> Optional[IdentifierRanking]:

    if not q:
        return None
    return await get_identifier_ranking(q)


@http_try_except
@nostrnip5_api_router.put(
    "/api/v1/ranking",
    dependencies=[Depends(check_admin)],
    status_code=HTTPStatus.OK,
)
async def api_domain_update_ranking(
    identifier_ranking: IdentifierRanking,
) -> Optional[IdentifierRanking]:

    return await update_identifier_ranking(
        identifier_ranking.name, identifier_ranking.rank
    )


##################################### SETTINGS #####################################
@http_try_except
@nostrnip5_api_router.post(
    "/api/v1/settings",
    status_code=HTTPStatus.OK,
)
@nostrnip5_api_router.put(
    "/api/v1/settings",
    status_code=HTTPStatus.OK,
)
async def api_settings_create_or_update(
    settings: Nip5Settings,
    user: User = Depends(check_user_exists),
):
    owner_id = owner_id_from_user_id("admin" if user.admin else user.id)
    await create_settings(owner_id, settings)


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/settings",
    status_code=HTTPStatus.OK,
)
async def api_get_settings(
    user: User = Depends(check_user_exists),
) -> Nip5Settings:
    owner_id = owner_id_from_user_id("admin" if user.admin else user.id)
    nip5_settings = await get_settings(owner_id)
    return nip5_settings
