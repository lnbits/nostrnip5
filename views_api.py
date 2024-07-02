from http import HTTPStatus
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Query, Request, Response
from lnbits.core.crud import get_standalone_payment, get_user
from lnbits.core.models import User, WalletTypeInfo
from lnbits.core.services import create_invoice
from lnbits.decorators import (
    authenticated_user_id,
    check_admin,
    check_user_exists,
    get_key_type,
    require_admin_key,
)
from lnbits.utils.exchange_rates import fiat_amount_as_satoshis
from loguru import logger
from starlette.exceptions import HTTPException

from .crud import (
    activate_address,
    create_address_internal,
    create_domain_internal,
    create_identifier_ranking,
    create_settings,
    delete_address,
    delete_domain,
    delete_inferior_ranking,
    get_address_by_local_part,
    get_addresses,
    get_addresses_for_owner,
    get_all_addresses,
    get_domain,
    get_domain_by_id,
    get_identifier_ranking,
    get_settings,
    rotate_address,
    update_domain_internal,
    update_identifier_ranking,
)
from .helpers import owner_id_from_user_id, validate_local_part, validate_pub_key
from .models import (
    AddressStatus,
    CreateAddressData,
    CreateDomainData,
    EditDomainData,
    IdentifierRanking,
    Nip5Settings,
    RotateAddressData,
)
from .services import get_identifier_status, get_user_domains

nostrnip5_api_router: APIRouter = APIRouter()


@nostrnip5_api_router.get("/api/v1/domains", status_code=HTTPStatus.OK)
async def api_domains(
    all_wallets: bool = Query(None), wallet: WalletTypeInfo = Depends(get_key_type)
):

    try:
        domains = await get_user_domains(
            wallet.wallet.user, wallet.wallet.id, all_wallets
        )

        return [domain.dict() for domain in domains]

    except AssertionError as exc:
        logger.error(exc)
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc)) from exc
    except Exception as exc:
        logger.error(exc)
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR) from exc


@nostrnip5_api_router.get("/api/v1/addresses", status_code=HTTPStatus.OK)
async def api_addresses(
    all_wallets: bool = Query(None), wallet: WalletTypeInfo = Depends(get_key_type)
):
    wallet_ids = [wallet.wallet.id]
    if all_wallets:
        user = await get_user(wallet.wallet.user)
        if not user:
            return []
        wallet_ids = user.wallet_ids

    return [address.dict() for address in await get_all_addresses(wallet_ids)]


@nostrnip5_api_router.get("/api/v1/addresses/user", status_code=HTTPStatus.OK)
async def api_addresses_own(
    user_id: Optional[str] = Depends(authenticated_user_id),
):
    if not user_id:
        raise HTTPException(HTTPStatus.UNAUTHORIZED)

    owner_id = owner_id_from_user_id(user_id)
    assert owner_id
    return [address.dict() for address in await get_addresses_for_owner(owner_id)]


@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}",
    status_code=HTTPStatus.OK,
)
async def api_domain_get(domain_id: str, w: WalletTypeInfo = Depends(get_key_type)):
    domain = await get_domain(domain_id, w.wallet.id)
    if not domain:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Domain does not exist."
        )

    return domain


@nostrnip5_api_router.post("/api/v1/domain", status_code=HTTPStatus.CREATED)
async def api_domain_create(
    data: CreateDomainData, wallet: WalletTypeInfo = Depends(get_key_type)
):

    domain = await create_domain_internal(wallet_id=wallet.wallet.id, data=data)

    return domain


@nostrnip5_api_router.put("/api/v1/domain", status_code=HTTPStatus.OK)
async def api_domain_update(
    data: EditDomainData, wallet: WalletTypeInfo = Depends(get_key_type)
):

    domain = await update_domain_internal(wallet_id=wallet.wallet.id, data=data)

    return domain


@nostrnip5_api_router.delete(
    "/api/v1/domain/{domain_id}", status_code=HTTPStatus.CREATED
)
async def api_domain_delete(
    domain_id: str,
    w: WalletTypeInfo = Depends(require_admin_key),
):
    deleted = await delete_domain(domain_id, w.wallet.id)

    return deleted


@nostrnip5_api_router.delete(
    "/api/v1/address/{domain_id}/{address_id}", status_code=HTTPStatus.GONE
)
async def api_address_delete(
    domain_id: str,
    address_id: str,
    w: WalletTypeInfo = Depends(require_admin_key),
):
    domain = await get_domain(domain_id, w.wallet.id)
    if not domain:
        return False

    return await delete_address(domain_id, address_id)


@nostrnip5_api_router.put(
    "/api/v1/domain/{domain_id}/address/{address_id}/activate",
    status_code=HTTPStatus.OK,
)
async def api_address_activate(
    domain_id: str,
    address_id: str,
    w: WalletTypeInfo = Depends(require_admin_key),
):
    domain = await get_domain(domain_id, w.wallet.id)
    if not domain:
        return False

    address = await activate_address(domain_id, address_id)

    return address


@nostrnip5_api_router.put(
    "/api/v1/domain/{domain_id}/address/{address_id}/rotate",
    status_code=HTTPStatus.OK,
)
async def api_address_rotate(
    domain_id: str,
    address_id: str,
    post_data: RotateAddressData,
    user_id: Optional[str] = Depends(authenticated_user_id),
):
    # todo: improve checks

    post_data.pubkey = validate_pub_key(post_data.pubkey)

    # todo: owner id
    await rotate_address(domain_id, address_id, post_data.pubkey)

    return True


@nostrnip5_api_router.post(
    "/api/v1/domain/{domain_id}/address", status_code=HTTPStatus.CREATED
)
async def api_address_create(
    post_data: CreateAddressData,
    domain_id: str,
    user_id: Optional[str] = Depends(authenticated_user_id),
):
    domain = await get_domain_by_id(domain_id)

    if not domain:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Domain does not exist."
        )

    validate_local_part(post_data.local_part)
    post_data.pubkey = validate_pub_key(post_data.pubkey)

    existing_address = await get_address_by_local_part(domain_id, post_data.local_part)

    if existing_address and existing_address.active:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Identifier already used."
        )

    address = await create_address_internal(
        domain_id=domain_id, data=post_data, owner_id=owner_id_from_user_id(user_id)
    )
    if domain.currency == "sats":
        price_in_sats = domain.cost
    else:
        price_in_sats = await fiat_amount_as_satoshis(domain.cost, domain.currency)

    try:
        payment_hash, payment_request = await create_invoice(
            wallet_id=domain.wallet,
            amount=price_in_sats,
            memo=f"Payment for NIP-05 for {address.local_part}@{domain.domain}",
            extra={
                "tag": "nostrnip5",
                "domain_id": domain_id,
                "address_id": address.id,
            },
        )
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    return {
        "payment_hash": payment_hash,
        "payment_request": payment_request,
        "address_id": address.id,
    }


@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}/payments/{payment_hash}", status_code=HTTPStatus.OK
)
async def api_nostrnip5_check_payment(domain_id: str, payment_hash: str):
    # todo: who can call and from where?
    try:
        payment = await get_standalone_payment(payment_hash, incoming=True)
        if not payment:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail="Payment does not exist."
            )
        payment_domain_id = payment.extra.get("domain_id")
        payment_address_id = payment.extra.get("address_id")
        if payment_domain_id != domain_id or not payment_address_id:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail="Payment does not exist for this domain.",
            )
        status = await payment.check_status()
        return {"paid": status.paid}

    except Exception as exc:
        logger.error(exc)
        return {"paid": False}


@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}/search", status_code=HTTPStatus.OK
)
async def api_search_identifier(
    domain_id: str, q: Optional[str] = None
) -> AddressStatus:
    try:
        if not q:
            return AddressStatus()

        return await get_identifier_status(domain_id, q)

    except AssertionError as exc:
        logger.error(exc)
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc)) from exc
    except Exception as exc:
        logger.error(exc)
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR) from exc


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

        if address.get("active") is False:
            continue

        if name and name.lower() != local_part.lower():
            continue

        output[local_part.lower()] = address.get("pubkey")

    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET,OPTIONS"

    return {"names": output}


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
    headers = {"Authorization": f"Bearer {nip5_settings.cloudflare_access_token}"}
    ranking_url = "https://api.cloudflare.com/client/v4/radar/datasets?limit=12&datasetType=RANKING_BUCKET"
    dataset_url = "https://api.cloudflare.com/client/v4/radar/datasets"

    logger.info(f"Refresh requested for top {bucket} identifiers.")

    async with httpx.AsyncClient() as client:
        resp = await client.get(url=ranking_url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        datasets = data["result"]["datasets"]
        datasets.sort(key=lambda b: b["meta"]["top"])

        logger.info("Bucket info received.")

        for dataset in datasets:
            top = dataset["meta"]["top"]
            if top > bucket:
                continue
            logger.info(f"Refreshing bucket {top}.")

            resp = await client.get(
                url=f"""{dataset_url}/{dataset["alias"]}""", headers=headers
            )
            resp.raise_for_status()

            for identifier in resp.text.split("\n"):
                identifier_name = identifier.split(".")[0]
                await delete_inferior_ranking(identifier_name, top)
                await create_identifier_ranking(identifier_name, top)

        logger.info(f"Top {bucket} identifiers ranking refreshed.")


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

    for identifier in identifiers:
        await delete_inferior_ranking(identifier, bucket)
        await create_identifier_ranking(identifier, bucket)

    logger.info(f"Updated {len(identifiers)} rankings.")


@nostrnip5_api_router.get(
    "/api/v1/ranking/search",
    dependencies=[Depends(check_admin)],
    status_code=HTTPStatus.OK,
)
async def api_domain_search_address(
    q: Optional[str] = None,
) -> Optional[IdentifierRanking]:
    try:
        if not q:
            return None
        return await get_identifier_ranking(q)

    except Exception as exc:
        logger.error(exc)
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR) from exc


@nostrnip5_api_router.put(
    "/api/v1/ranking",
    dependencies=[Depends(check_admin)],
    status_code=HTTPStatus.OK,
)
async def api_domain_update_ranking(
    identifier_ranking: IdentifierRanking,
) -> Optional[IdentifierRanking]:
    try:

        return await update_identifier_ranking(
            identifier_ranking.name, identifier_ranking.rank
        )

    except Exception as exc:
        logger.error(exc)
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR) from exc


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
