from typing import List, Optional, Tuple

import httpx
from lnbits.core.crud import get_standalone_payment, get_user
from lnbits.db import Filters, Page
from lnbits.utils.exchange_rates import fiat_amount_as_satoshis
from loguru import logger

from .crud import (
    activate_domain_address,
    create_address_internal,
    create_identifier_ranking,
    delete_inferior_ranking,
    get_address,
    get_address_by_local_part,
    get_address_for_owner,
    get_all_addresses,
    get_all_addresses_paginated,
    get_domains,
    get_identifier_ranking,
)
from .helpers import (
    normalize_identifier,
    owner_id_from_user_id,
    validate_pub_key,
)
from .models import Address, AddressFilters, AddressStatus, CreateAddressData, Domain


async def get_user_domains(
    user_id: str, wallet_id: str, all_wallets: Optional[bool] = False
) -> List[Domain]:
    wallet_ids = [wallet_id]
    if all_wallets:
        user = await get_user(user_id)
        if not user:
            return []
        wallet_ids = user.wallet_ids

    return await get_domains(wallet_ids)


async def get_user_addresses(
    user_id: str, wallet_id: str, all_wallets: Optional[bool] = False
) -> List[Address]:
    wallet_ids = [wallet_id]
    if all_wallets:
        user = await get_user(user_id)
        if not user:
            return []
        wallet_ids = user.wallet_ids

    return await get_all_addresses(wallet_ids)


async def get_user_addresses_paginated(
    user_id: str,
    wallet_id: str,
    all_wallets: Optional[bool] = False,
    filters: Optional[Filters[AddressFilters]] = None,
) -> Page[Address]:
    wallet_ids = [wallet_id]
    if all_wallets:
        user = await get_user(user_id)
        if not user:
            return Page(data=[], total=0)
        wallet_ids = user.wallet_ids

    return await get_all_addresses_paginated(wallet_ids, filters)


async def get_identifier_status(domain: Domain, identifier: str) -> AddressStatus:
    identifier = normalize_identifier(identifier)
    address = await get_address_by_local_part(domain.id, identifier)
    reserved = address is not None
    if address and address.active:
        return AddressStatus(identifier=identifier, available=False, reserved=reserved)

    rank = None
    if domain.cost_config.enable_custom_cost:
        identifier_ranking = await get_identifier_ranking(identifier)
        rank = identifier_ranking.rank if identifier_ranking else None

    if rank == 0:
        return AddressStatus(identifier=identifier, available=False, reserved=True)

    price, reason = domain.price_for_identifier(identifier, rank)

    return AddressStatus(
        identifier=identifier,
        available=True,
        reserved=reserved,
        price=price,
        price_reason=reason,
        currency=domain.currency,
    )


async def create_address(
    domain: Domain, address_data: CreateAddressData, user_id: Optional[str] = None
) -> Tuple[Address, float]:

    identifier = normalize_identifier(address_data.local_part)
    address_data.local_part = identifier
    address_data.pubkey = validate_pub_key(address_data.pubkey)

    identifier_status = await get_identifier_status(domain, identifier)

    assert identifier_status.available, f"Identifier '{identifier}' not available."
    assert identifier_status.price, f"Cannot compute price for '{identifier}'."

    owner_id = owner_id_from_user_id(user_id)
    existing_address = await get_address_for_owner(owner_id, domain.id, identifier)

    address = existing_address or await create_address_internal(address_data, owner_id)

    price_in_sats = (
        identifier_status.price
        if domain.currency == "sats"
        else await fiat_amount_as_satoshis(identifier_status.price, domain.currency)
    )

    assert price_in_sats, f"Cannot compute price for {identifier}"

    return address, price_in_sats


async def activate_address(
    domain_id: str, address_id: str, payment_hash: Optional[str] = None
) -> bool:
    logger.info(f"Activating NOSTR NIP-05 '{address_id}' for {domain_id}")
    try:
        address = await get_address(domain_id, address_id)
        assert address, f"Cannot find address '{address_id}' for {domain_id}."
        assert not address.active, f"Address '{address_id}' already active."

        address.config.activated_by_owner = payment_hash is None
        address.config.payment_hash = payment_hash
        await activate_domain_address(domain_id, address_id, address.config)

        return True
    except Exception as exc:
        logger.warning(exc)
        logger.info(f"Failed to acivate NOSTR NIP-05 '{address_id}' for {domain_id}.")
        return False


async def check_address_payment(domain_id: str, payment_hash: str) -> bool:
    payment = await get_standalone_payment(payment_hash, incoming=True)
    assert payment, "Payment does not exist."

    payment_address_id = payment.extra.get("address_id")
    assert payment_address_id, "Payment does not exist for this address."

    payment_domain_id = payment.extra.get("domain_id")
    assert payment_domain_id == domain_id, "Payment does not exist for this domain."

    if payment.pending is False:
        return True

    status = await payment.check_status()
    return status.success


async def update_identifiers(identifiers: List[str], bucket: int):
    for identifier in identifiers:
        await update_identifier(identifier, bucket)


async def update_identifier(identifier, bucket):
    await delete_inferior_ranking(identifier, bucket)
    await create_identifier_ranking(identifier, bucket)


async def refresh_buckets(
    client: httpx.AsyncClient, ranking_url: str, dataset_url: str, bucket: int
):
    logger.info(f"Refresh requested for top {bucket} identifiers.")

    resp = await client.get(url=ranking_url)
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
        url = f"""{dataset_url}/{dataset["alias"]}"""
        await refresh_bucket(client, url, top)
        logger.info(f"Refreshed bucket {top}.")

    logger.info(f"Top {bucket} identifiers ranking refreshed.")


async def refresh_bucket(
    client: httpx.AsyncClient,
    url: str,
    bucket: int,
):
    resp = await client.get(url)
    resp.raise_for_status()

    for identifier in resp.text.split("\n"):
        identifier_name = identifier.split(".")[0]
        await update_identifier(identifier_name, bucket)
