from http import HTTPStatus
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Query, Request, Response
from lnbits.core.crud import get_wallets
from lnbits.core.models import SimpleStatus, User, WalletTypeInfo
from lnbits.core.services import create_invoice
from lnbits.db import Filters, Page
from lnbits.decorators import (  # type: ignore[attr-defined]
    check_admin,
    check_user_exists,
    get_key_type,
    optional_user_id,  # pyright: ignore [reportAttributeAccessIssue]
    parse_filters,
    require_admin_key,
)
from lnbits.helpers import generate_filter_params_openapi
from loguru import logger
from starlette.exceptions import HTTPException

from .crud import (
    create_domain_internal,
    create_settings,
    delete_address,
    delete_address_by_id,
    delete_domain,
    get_active_address_by_local_part,
    get_address,
    get_domain,
    get_domain_by_id,
    get_identifier_ranking,
    get_settings,
    rotate_address,
    update_address,
    update_domain_internal,
    update_identifier_ranking,
)
from .helpers import (
    http_try_except,
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
    UpdateAddressData,
)
from .services import (
    activate_address,
    check_address_payment,
    create_address,
    get_identifier_status,
    get_reimburse_wallet_id,
    get_user_addresses,
    get_user_addresses_paginated,
    get_user_domains,
    get_valid_addresses_for_owner,
    refresh_buckets,
    update_identifiers,
)

nostrnip5_api_router: APIRouter = APIRouter()

address_filters = parse_filters(AddressFilters)


##################################### DOMAINS #####################################


@http_try_except
@nostrnip5_api_router.get("/api/v1/domains", status_code=HTTPStatus.OK)
async def api_domains(
    all_wallets: bool = Query(None), wallet: WalletTypeInfo = Depends(get_key_type)
):
    domains = await get_user_domains(wallet.wallet.user, wallet.wallet.id, all_wallets)

    return [domain.dict() for domain in domains]


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}",
    status_code=HTTPStatus.OK,
)
async def api_get_domains(domain_id: str, w: WalletTypeInfo = Depends(get_key_type)):
    domain = await get_domain(domain_id, w.wallet.id)
    assert domain, "Domain does not exist."
    return domain


@http_try_except
@nostrnip5_api_router.post("/api/v1/domain", status_code=HTTPStatus.CREATED)
async def api_create_domain(
    data: CreateDomainData, wallet: WalletTypeInfo = Depends(require_admin_key)
):

    return await create_domain_internal(wallet_id=wallet.wallet.id, data=data)


@http_try_except
@nostrnip5_api_router.put("/api/v1/domain", status_code=HTTPStatus.OK)
async def api_update_domain(
    data: EditDomainData, wallet: WalletTypeInfo = Depends(require_admin_key)
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
    # make sure the address belongs to the user
    deleted = await delete_domain(domain_id, w.wallet.id)

    return SimpleStatus(success=deleted, message="Deleted")


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}/nostr.json", status_code=HTTPStatus.OK
)
async def api_get_nostr_json(
    response: Response, domain_id: str, name: str = Query(None)
):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET,OPTIONS"

    if not name:
        return {"names": {}, "relays": {}}

    address = await get_active_address_by_local_part(domain_id, name)

    if not address:
        return {"names": {}, "relays": {}}

    return {
        "names": {address.local_part: address.pubkey},
        "relays": {address.pubkey: address.config.relays},
    }


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}/search", status_code=HTTPStatus.OK
)
async def api_search_identifier(
    domain_id: str, q: Optional[str] = None, years: Optional[int] = None
) -> AddressStatus:

    if not q:
        return AddressStatus(identifier="")

    domain = await get_domain_by_id(domain_id)
    assert domain, "Unknown domain id."

    return await get_identifier_status(domain, q, years or 1)


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}/payments/{payment_hash}", status_code=HTTPStatus.OK
)
async def api_check_address_payment(domain_id: str, payment_hash: str):
    # todo: can it be replaced with websocket?
    paid = await check_address_payment(domain_id, payment_hash)
    return {"paid": paid}


##################################### ADDRESSES #####################################


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
@nostrnip5_api_router.delete(
    "/api/v1/domain/{domain_id}/address/{address_id}",
    status_code=HTTPStatus.OK,
)
async def api_delete_address(
    domain_id: str,
    address_id: str,
    w: WalletTypeInfo = Depends(get_key_type),
):

    # make sure the address belongs to the user
    domain = await get_domain(domain_id, w.wallet.id)
    assert domain, "Domain does not exist."

    await delete_address_by_id(domain_id, address_id)


@http_try_except
@nostrnip5_api_router.put(
    "/api/v1/domain/{domain_id}/address/{address_id}/activate",
    status_code=HTTPStatus.OK,
)
async def api_activate_address(
    domain_id: str,
    address_id: str,
    w: WalletTypeInfo = Depends(require_admin_key),
) -> Address:
    # make sure the address belongs to the user
    domain = await get_domain(domain_id, w.wallet.id)
    assert domain, "Domain does not exist."

    return await activate_address(domain_id, address_id)


@http_try_except
@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}/address/{address_id}/reimburse",
    dependencies=[Depends(require_admin_key)],
    status_code=HTTPStatus.CREATED,
)
async def api_address_reimburse(
    domain_id: str,
    address_id: str,
):

    # make sure the address belongs to the user
    domain = await get_domain_by_id(domain_id)
    assert domain, "Domain does not exist."

    address = await get_address(domain.id, address_id)
    assert address and (address.domain_id == domain.id), "Domain ID missmatch"

    wallet_id = await get_reimburse_wallet_id(address)

    payment_hash, payment_request = await create_invoice(
        wallet_id=wallet_id,
        amount=address.reimburse_amount,
        memo=f"Reimbursement for NIP-05 for {address.local_part}@{domain.domain}",
        extra={
            "tag": "nostrnip5",
            "domain_id": domain_id,
            "address_id": address.id,
            "local_part": address.local_part,
            "action": "reimburse",
        },
    )

    return {
        "payment_hash": payment_hash,
        "payment_request": payment_request,
        "address_id": address.id,
    }


@http_try_except
@nostrnip5_api_router.put(
    "/api/v1/domain/{domain_id}/address/{address_id}",
    status_code=HTTPStatus.OK,
)
async def api_update_address(
    domain_id: str,
    address_id: str,
    data: UpdateAddressData,
    w: WalletTypeInfo = Depends(require_admin_key),
) -> Address:

    data.validate_relays_urls()

    # make sure the domain belongs to the user
    domain = await get_domain(domain_id, w.wallet.id)
    assert domain, "Domain does not exist."

    address = await get_address(domain_id, address_id)
    assert address, "Address not found"
    assert address.domain_id == domain_id, "Domain ID missmatch"

    pubkey = data.pubkey if data.pubkey else address.pubkey
    if data.relays:
        address.config.relays = data.relays
    await update_address(domain_id, address.id, pubkey=pubkey, config=address.config)

    return address


##################################### USER ADDRESSES ###################################


@http_try_except
@nostrnip5_api_router.get("/api/v1/user/addresses", status_code=HTTPStatus.OK)
async def api_get_user_addresses(
    user_id: Optional[str] = Depends(optional_user_id),
    local_part: Optional[str] = None,
    active: Optional[bool] = None,
):
    if not user_id:
        raise HTTPException(HTTPStatus.FORBIDDEN)

    owner_id = owner_id_from_user_id(user_id)
    assert owner_id
    return await get_valid_addresses_for_owner(owner_id, local_part, active)


@http_try_except
@nostrnip5_api_router.delete(
    "/api/v1/user/domain/{domain_id}/address/{address_id}",
    status_code=HTTPStatus.OK,
)
async def api_delete_user_address(
    domain_id: str,
    address_id: str,
    user_id: Optional[str] = Depends(optional_user_id),
):

    if not user_id:
        raise HTTPException(HTTPStatus.FORBIDDEN)

    owner_id = owner_id_from_user_id(user_id)  # todo: allow for admins
    return await delete_address(domain_id, address_id, owner_id)


@http_try_except
@nostrnip5_api_router.put(
    "/api/v1/domain/{domain_id}/address/{address_id}/rotate",
    status_code=HTTPStatus.OK,
)
async def api_rotate_user_address(
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


# todo: anonimous
@http_try_except
@nostrnip5_api_router.put(
    "/api/v1/user/domain/{domain_id}/address/{address_id}",
    status_code=HTTPStatus.OK,
)
async def api_update_user_address(
    domain_id: str,
    address_id: str,
    data: UpdateAddressData,
    user_id: Optional[str] = Depends(optional_user_id),
) -> Address:

    if not user_id:
        raise HTTPException(HTTPStatus.FORBIDDEN)

    data.validate_relays_urls()

    address = await get_address(domain_id, address_id)
    assert address, "Address not found"
    assert address.domain_id == domain_id, "Domain ID missmatch"

    owner_id = owner_id_from_user_id(user_id)  # todo: allow for admins
    assert address.owner_id == owner_id, "Address does not belong to this user"

    pubkey = data.pubkey if data.pubkey else address.pubkey
    if data.relays:
        address.config.relays = data.relays
    await update_address(domain_id, address.id, pubkey=pubkey, config=address.config)

    return address


@http_try_except
@nostrnip5_api_router.post(
    "/api/v1/user/domain/{domain_id}/address", status_code=HTTPStatus.CREATED
)
async def api_request_user_address(
    address_data: CreateAddressData,
    domain_id: str,
    user_id: Optional[str] = Depends(optional_user_id),
):

    # make sure the address belongs to the user
    domain = await get_domain_by_id(address_data.domain_id)
    assert domain, "Domain does not exist."

    assert address_data.domain_id == domain_id, "Domain ID missmatch"
    address = await create_address(domain, address_data, user_id)
    assert (
        address.config.price_in_sats
    ), f"Cannot compute price for '{address_data.local_part}'."

    if address_data.create_invoice:
        # in case the user pays, but the identifier is no longer available
        wallet_id = (await get_wallets(user_id))[0].id if user_id else None
        payment_hash, payment_request = await create_invoice(
            wallet_id=domain.wallet,
            amount=int(address.config.price_in_sats),
            memo=f"Payment of {address.config.price} {address.config.currency} "
            f"for NIP-05 for {address_data.local_part}@{domain.domain}",
            extra={
                "tag": "nostrnip5",
                "domain_id": domain_id,
                "address_id": address.id,
                "action": "activate",
                "reimburse_wallet_id": wallet_id,
            },
        )
    else:
        payment_hash, payment_request = None, None

    return {
        "payment_hash": payment_hash,
        "payment_request": payment_request,
        **dict(address),
    }


##################################### RANKING #####################################


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
