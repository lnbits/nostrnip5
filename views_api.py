import re
from http import HTTPStatus

from bech32 import bech32_decode, convertbits
from fastapi import APIRouter, Depends, Query, Response
from lnbits.core.crud import get_standalone_payment, get_user
from lnbits.core.models import WalletTypeInfo
from lnbits.core.services import create_invoice
from lnbits.decorators import get_key_type, require_admin_key
from lnbits.utils.exchange_rates import fiat_amount_as_satoshis
from loguru import logger
from starlette.exceptions import HTTPException

from .crud import (
    activate_address,
    create_address_internal,
    create_domain_internal,
    delete_address,
    delete_domain,
    get_address_by_local_part,
    get_addresses,
    get_all_addresses,
    get_domain,
    get_domains,
    rotate_address,
    update_domain_internal,
)
from .models import (
    CreateAddressData,
    CreateDomainData,
    EditDomainData,
    RotateAddressData,
)

nostrnip5_api_router: APIRouter = APIRouter()


@nostrnip5_api_router.get("/api/v1/domains", status_code=HTTPStatus.OK)
async def api_domains(
    all_wallets: bool = Query(None), wallet: WalletTypeInfo = Depends(get_key_type)
):
    wallet_ids = [wallet.wallet.id]
    if all_wallets:
        user = await get_user(wallet.wallet.user)
        if not user:
            return []
        wallet_ids = user.wallet_ids

    return [domain.dict() for domain in await get_domains(wallet_ids)]


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


@nostrnip5_api_router.get(
    "/api/v1/domain/{domain_id}",
    status_code=HTTPStatus.OK,
    dependencies=[Depends(get_key_type)],
)
async def api_invoice(domain_id: str):
    domain = await get_domain(domain_id)
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
    wallet: WalletTypeInfo = Depends(require_admin_key),
):
    await delete_domain(domain_id)

    return True


@nostrnip5_api_router.delete(
    "/api/v1/address/{address_id}", status_code=HTTPStatus.CREATED
)
async def api_address_delete(
    address_id: str,
    wallet: WalletTypeInfo = Depends(require_admin_key),
):
    await delete_address(address_id)

    return True


@nostrnip5_api_router.post(
    "/api/v1/domain/{domain_id}/address/{address_id}/activate",
    status_code=HTTPStatus.OK,
    dependencies=[Depends(require_admin_key)],
)
async def api_address_activate(
    domain_id: str,
    address_id: str,
):
    await activate_address(domain_id, address_id)

    return True


@nostrnip5_api_router.post(
    "/api/v1/domain/{domain_id}/address/{address_id}/rotate",
    status_code=HTTPStatus.OK,
)
async def api_address_rotate(
    domain_id: str,
    address_id: str,
    post_data: RotateAddressData,
):

    if post_data.pubkey.startswith("npub"):
        _, data = bech32_decode(post_data.pubkey)
        if data:
            decoded_data = convertbits(data, 5, 8, False)
            if decoded_data:
                post_data.pubkey = bytes(decoded_data).hex()

    if len(bytes.fromhex(post_data.pubkey)) != 32:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Pubkey must be in hex format."
        )

    await rotate_address(domain_id, address_id, post_data.pubkey)

    return True


def _validate_local_part(local_part: str):
    if local_part == "_":
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="You're sneaky, nice try."
        )

    regex = re.compile(r"^[a-z0-9_.]+$")
    if not re.fullmatch(regex, local_part.lower()):
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Only a-z, 0-9 and .-_ are allowed characters, case insensitive.",
        )


@nostrnip5_api_router.post(
    "/api/v1/domain/{domain_id}/address", status_code=HTTPStatus.CREATED
)
async def api_address_create(
    post_data: CreateAddressData,
    domain_id: str,
):
    domain = await get_domain(domain_id)

    if not domain:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Domain does not exist."
        )

    _validate_local_part(post_data.local_part)

    exists = await get_address_by_local_part(domain_id, post_data.local_part)

    if exists:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Local part already exists."
        )

    if post_data and post_data.pubkey.startswith("npub"):
        _, data = bech32_decode(post_data.pubkey)
        if data:
            decoded_data = convertbits(data, 5, 8, False)
            if decoded_data:
                post_data.pubkey = bytes(decoded_data).hex()

    if len(bytes.fromhex(post_data.pubkey)) != 32:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Pubkey must be in npub or hex format.",
        )

    address = await create_address_internal(domain_id=domain_id, data=post_data)
    if domain.currency == "Satoshis":
        price_in_sats = domain.amount
    else:
        price_in_sats = await fiat_amount_as_satoshis(
            domain.amount / 100, domain.currency
        )

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
    domain = await get_domain(domain_id)
    if not domain:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Domain does not exist."
        )
    try:
        payment = await get_standalone_payment(payment_hash)
        if not payment:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail="Payment does not exist."
            )
        status = await payment.check_status()
        return {"paid": status.paid}

    except Exception as exc:
        logger.error(exc)
        return {"paid": False}


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
