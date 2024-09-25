import json
from datetime import datetime, timedelta
from typing import Optional, Union

from lnbits.db import Database, Filters, Page
from lnbits.helpers import urlsafe_short_hash

from .helpers import normalize_identifier
from .models import (
    Address,
    AddressConfig,
    AddressFilters,
    CreateAddressData,
    CreateDomainData,
    Domain,
    EditDomainData,
    IdentifierRanking,
    Nip5Settings,
    PublicDomain,
)

db = Database("ext_nostrnip5")


async def get_domain(domain_id: str, wallet_id: str) -> Optional[Domain]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.domains WHERE id = :id AND wallet = :wallet",
        {"id": domain_id, "wallet": wallet_id},
    )
    return Domain(**row) if row else None


async def get_domain_by_id(domain_id: str) -> Optional[Domain]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.domains WHERE id = :id",
        {"id": domain_id},
    )
    return Domain(**row) if row else None


async def get_domain_public_data(domain_id: str) -> Optional[PublicDomain]:
    row = await db.fetchone(
        "SELECT id, currency, cost, domain FROM nostrnip5.domains WHERE id = :id",
        {"id": domain_id},
    )
    return PublicDomain(**row) if row else None


async def get_domain_by_name(domain: str) -> Optional[Domain]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.domains WHERE domain = :domain",
        {"domain": domain.lower()},
    )
    return Domain(**row) if row else None


async def get_domains(wallet_ids: Union[str, list[str]]) -> list[Domain]:
    if isinstance(wallet_ids, str):
        wallet_ids = [wallet_ids]

    q = ",".join([f"'{w}'" for w in wallet_ids])
    rows = await db.fetchall(f"SELECT * FROM nostrnip5.domains WHERE wallet IN ({q})")

    return [Domain(**row) for row in rows]


async def get_address(domain_id: str, address_id: str) -> Optional[Address]:
    row = await db.fetchone(
        """
        SELECT * FROM nostrnip5.addresses
        WHERE domain_id = :domain_id AND id = :address_id
        """,
        {"domain_id": domain_id, "address_id": address_id},
    )
    return Address(**row) if row else None


async def get_active_address_by_local_part(
    domain_id: str, local_part: str
) -> Optional[Address]:
    row = await db.fetchone(
        """
            SELECT * FROM nostrnip5.addresses
            WHERE active = true AND domain_id = :domain_id AND local_part = :local_part
        """,
        {"domain_id": domain_id, "local_part": normalize_identifier(local_part)},
    )
    return Address(**row) if row else None


async def get_addresses(domain_id: str) -> list[Address]:
    rows = await db.fetchall(
        "SELECT * FROM nostrnip5.addresses WHERE domain_id = :domain_id",
        {"domain_id": domain_id},
    )

    return [Address(**row) for row in rows]


async def get_address_for_owner(
    owner_id: str, domain_id: str, local_part: str
) -> Optional[Address]:
    row = await db.fetchone(
        """
        SELECT * FROM nostrnip5.addresses WHERE owner_id = :owner_id
        AND domain_id = :domain_id AND local_part = :local_part
        """,
        {"owner_id": owner_id, "domain_id": domain_id, "local_part": local_part},
    )

    return Address(**row) if row else None


async def get_addresses_for_owner(owner_id: str) -> list[Address]:
    rows = await db.fetchall(
        """
            SELECT * FROM nostrnip5.addresses WHERE owner_id = :owner_id
            ORDER BY time DESC
        """,
        {"owner_id": owner_id},
    )

    return [Address(**row) for row in rows]


async def get_all_addresses(wallet_ids: Union[str, list[str]]) -> list[Address]:
    if isinstance(wallet_ids, str):
        wallet_ids = [wallet_ids]

    q = ",".join([f"'{w}'" for w in wallet_ids])
    rows = await db.fetchall(
        f"""
        SELECT a.* FROM nostrnip5.addresses a
        JOIN nostrnip5.domains d ON d.id = a.domain_id
        WHERE d.wallet IN ({q})
        """
    )

    return [Address(**row) for row in rows]


async def get_all_addresses_paginated(
    wallet_ids: Union[str, list[str]],
    filters: Optional[Filters[AddressFilters]] = None,
) -> Page[Address]:
    if isinstance(wallet_ids, str):
        wallet_ids = [wallet_ids]

    q = ",".join([f"'{w}'" for w in wallet_ids])
    query = f"""
        SELECT a.* FROM nostrnip5.addresses a
        JOIN nostrnip5.domains d ON d.id = a.domain_id
        WHERE d.wallet IN ({q})
    """

    return await db.fetch_page(
        query,
        filters=filters,
        model=Address,
    )


async def activate_domain_address(
    domain_id: str, address_id: str, config: AddressConfig
) -> Address:
    extra = json.dumps(config, default=lambda o: o.__dict__)
    await db.execute(
        """
        UPDATE nostrnip5.addresses
        SET active = true, extra = :extra
        WHERE domain_id = :domain_id AND id = :address_id
        """,
        {"domain_id": domain_id, "address_id": address_id, "extra": extra},
    )

    address = await get_address(domain_id, address_id)
    assert address, "Newly updated address couldn't be retrieved"
    return address


async def update_address(address: Address) -> Address:
    years = address.config.years
    address.expires_at = datetime.now() + timedelta(days=365 * years)
    await db.update("nostrnip5.addresses", address)  # type: ignore
    return address


async def delete_domain(domain_id: str, wallet_id: str) -> bool:
    domain = await get_domain(domain_id, wallet_id)
    if not domain:
        return False
    await db.execute(
        """
        DELETE FROM nostrnip5.addresses WHERE domain_id = :domain_id
        """,
        {"domain_id": domain_id},
    )

    await db.execute(
        "DELETE FROM nostrnip5.domains WHERE id = :id",
        {"id": domain_id},
    )

    return True


async def delete_address(domain_id, address_id, owner_id):
    await db.execute(
        """
        DELETE FROM nostrnip5.addresses
        WHERE domain_id = :domain_id AND id = :id AND owner_id = :owner_id
        """,
        {"domain_id": domain_id, "id": address_id, "owner_id": owner_id},
    )


async def delete_address_by_id(domain_id, address_id):
    await db.execute(
        """
        DELETE FROM nostrnip5.addresses
        WHERE domain_id = :domain_id AND id = :id
        """,
        {"domain_id": domain_id, "id": address_id},
    )


async def create_address_internal(
    data: CreateAddressData,
    owner_id: Optional[str] = None,
    config: Optional[AddressConfig] = None,
) -> Address:
    extra = json.dumps(config or AddressConfig(), default=lambda o: o.__dict__)
    expires_at = datetime.now() + timedelta(days=365 * data.years)
    address = Address(
        id=urlsafe_short_hash(),
        domain_id=data.domain_id,
        owner_id=owner_id,
        local_part=normalize_identifier(data.local_part),
        pubkey=data.pubkey,
        active=False,
        extra=extra,
        expires_at=expires_at,
        time=datetime.now(),
    )
    await db.insert("nostrnip5.addresses", address)  # type: ignore
    return address


async def update_domain_internal(wallet_id: str, data: EditDomainData) -> Domain:
    cost_extra = (
        json.dumps(data.cost_config, default=lambda o: o.__dict__)
        if data.cost_config
        else None
    )
    await db.execute(
        """
        UPDATE nostrnip5.domains
        SET cost = :cost, currency = :currency, cost_extra = :cost_extra
        WHERE id = :id
        """,
        {
            "cost": data.cost,
            "currency": data.currency,
            "cost_extra": cost_extra,
            "id": data.id,
        },
    )

    domain = await get_domain(data.id, wallet_id)
    assert domain, "Domain couldn't be updated"
    return domain


async def create_domain_internal(wallet_id: str, data: CreateDomainData) -> Domain:
    cost_extra = (
        json.dumps(data.cost_config, default=lambda o: o.__dict__)
        if data.cost_config
        else ""
    )
    domain = Domain(
        id=urlsafe_short_hash(),
        wallet=wallet_id,
        time=datetime.now(),
        cost_extra=cost_extra,
        currency=data.currency,
        cost=data.cost,
        domain=data.domain.lower(),
    )
    await db.insert("nostrnip5.domains", domain)  # type: ignore
    return domain


# todo: rename to identifier
async def create_identifier_ranking(name: str, rank: int):
    await db.execute(
        """
        INSERT INTO nostrnip5.identifiers_rankings(name, rank)
        VALUES (:name, :rank) ON CONFLICT (name) DO NOTHING
        """,
        {"name": normalize_identifier(name), "rank": rank},
    )


async def update_identifier_ranking(name: str, rank: int):
    await db.execute(
        """
        UPDATE nostrnip5.identifiers_rankings
        SET rank = :rank WHERE name = :name
        """,
        {"name": normalize_identifier(name), "rank": rank},
    )


async def get_identifier_ranking(name: str) -> Optional[IdentifierRanking]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.identifiers_rankings WHERE name = :name",
        {"name": normalize_identifier(name)},
    )
    return IdentifierRanking(**row) if row else None


async def delete_inferior_ranking(name: str, rank: int):
    await db.execute(
        """
        DELETE from nostrnip5.identifiers_rankings
        WHERE name = :name and rank > :rank
        """,
        {"name": normalize_identifier(name), "rank": rank},
    )


async def create_settings(settings: Nip5Settings):
    await db.insert("nostrnip5.settings", settings)  # type: ignore


async def get_settings(owner_id: str) -> Optional[Nip5Settings]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.settings WHERE owner_id = :owner_id",
        {"owner_id": owner_id},
    )
    return Nip5Settings(**row) if row else None
