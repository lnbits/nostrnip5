from typing import List, Optional

import httpx
from lnbits.core.crud import get_standalone_payment, get_user
from lnbits.core.models import Payment
from lnbits.db import Filters, Page
from lnbits.utils.exchange_rates import fiat_amount_as_satoshis
from loguru import logger

from .crud import (
    activate_domain_address,
    create_address_internal,
    create_identifier_ranking,
    delete_inferior_ranking,
    get_active_address_by_local_part,
    get_address,
    get_address_for_owner,
    get_addresses_for_owner,
    get_all_addresses,
    get_all_addresses_paginated,
    get_domain_by_id,
    get_domains,
    get_identifier_ranking,
    update_address,
)
from .helpers import (
    normalize_identifier,
    owner_id_from_user_id,
    validate_pub_key,
)
from .models import (
    Address,
    AddressConfig,
    AddressFilters,
    AddressStatus,
    CreateAddressData,
    Domain,
)


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


async def get_identifier_status(
    domain: Domain, identifier: str, years: int
) -> AddressStatus:
    identifier = normalize_identifier(identifier)
    address = await get_active_address_by_local_part(domain.id, identifier)
    if address:
        return AddressStatus(identifier=identifier, available=False)

    rank = None
    if domain.cost_config.enable_custom_cost:
        identifier_ranking = await get_identifier_ranking(identifier)
        rank = identifier_ranking.rank if identifier_ranking else None

    if rank == 0:
        return AddressStatus(identifier=identifier, available=False)

    price, reason = domain.price_for_identifier(identifier, years, rank)

    price_in_sats = (
        price
        if domain.currency == "sats"
        else await fiat_amount_as_satoshis(price, domain.currency)
    )

    return AddressStatus(
        identifier=identifier,
        available=True,
        price=price,
        price_in_sats=price_in_sats,
        price_reason=reason,
        currency=domain.currency,
    )


async def create_address(
    domain: Domain, data: CreateAddressData, user_id: Optional[str] = None
) -> Address:

    identifier = normalize_identifier(data.local_part)
    data.local_part = identifier
    if data.pubkey != "":
        data.pubkey = validate_pub_key(data.pubkey)

    identifier_status = await get_identifier_status(domain, identifier, data.years)

    assert identifier_status.available, f"Identifier '{identifier}' not available."
    assert identifier_status.price, f"Cannot compute price for '{identifier}'."

    price_in_sats = (
        identifier_status.price
        if domain.currency == "sats"
        else await fiat_amount_as_satoshis(identifier_status.price, domain.currency)
    )
    assert price_in_sats, f"Cannot compute price for '{identifier}'."

    owner_id = owner_id_from_user_id(user_id)
    addresss = await get_address_for_owner(owner_id, domain.id, identifier)

    config = addresss.config if addresss else AddressConfig()
    config.price = identifier_status.price
    config.price_in_sats = price_in_sats
    config.currency = domain.currency
    config.years = data.years
    config.max_years = domain.cost_config.max_years

    if addresss:
        assert not addresss.active, f"Identifier '{data.local_part}' already activated."
        address = await update_address(
            domain.id, addresss.id, config=config, pubkey=data.pubkey
        )
    else:
        address = await create_address_internal(data, owner_id, config=config)

    return address


async def activate_address(
    domain_id: str, address_id: str, payment_hash: Optional[str] = None
) -> bool:
    logger.info(f"Activating NOSTR NIP-05 '{address_id}' for {domain_id}")
    try:
        address = await get_address(domain_id, address_id)
        assert address, f"Cannot find address '{address_id}' for {domain_id}."
        active_address = await get_active_address_by_local_part(
            domain_id, address.local_part
        )
        assert not active_address, f"Address '{address.local_part}' already active."

        address.config.activated_by_owner = payment_hash is None
        address.config.payment_hash = payment_hash
        await activate_domain_address(domain_id, address_id, address.config)

        return True
    except Exception as exc:
        logger.warning(exc)
        logger.info(f"Failed to acivate NOSTR NIP-05 '{address_id}' for {domain_id}.")
        return False


async def get_valid_addresses_for_owner(
    owner_id: str, local_part: Optional[str] = None, active: Optional[bool] = None
) -> List[Address]:

    valid_addresses = []
    addresses = await get_addresses_for_owner(owner_id)
    for address in addresses:
        if active is not None and active != address.active:
            continue
        if local_part and address.local_part != local_part:
            continue
        domain = await get_domain_by_id(address.domain_id)
        if not domain:
            continue
        status = await get_identifier_status(
            domain, address.local_part, address.config.years
        )

        if status.available:
            # update to latest price
            address.config.price_in_sats = status.price_in_sats
            address.config.price = status.price
        elif not address.active:
            # do not return addresses which cannot be sold
            continue

        address.config.currency = domain.currency
        valid_addresses.append(address)

    return valid_addresses


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


async def get_reimburse_wallet_id(address: Address) -> str:
    payment_hash = address.config.reimburse_payment_hash
    assert payment_hash, f"No payment hash found to reimburse '{address.id}'."

    payment = await get_standalone_payment(
        checking_id_or_hash=payment_hash, incoming=True
    )
    assert payment, f"No payment found to reimburse '{payment_hash}'."
    wallet_id = payment.extra.get("reimburse_wallet_id")
    assert wallet_id, f"No wallet found to reimburse payment {payment_hash}."
    return wallet_id


async def reimburse_payment(payment: Payment):
    reimburse_wallet_ids = payment.extra.get("reimburse_wallet_ids", [])
    domain_id = payment.extra.get("domain_id")
    address_id = payment.extra.get("address_id")

    if len(reimburse_wallet_ids) == 0:
        logger.info(
            f"Cannot reimburse failed activation for payment '{payment.payment_hash}'"
            f"Info: domain ID ({domain_id}), address ID ({address_id})."
        )


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
