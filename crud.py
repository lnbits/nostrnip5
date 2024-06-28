import json
from typing import List, Optional, Union

from lnbits.db import Database
from lnbits.helpers import urlsafe_short_hash

from .models import (
    Address,
    CreateAddressData,
    CreateDomainData,
    Domain,
    DomainRanking,
    EditDomainData,
    Nip5Settings,
    PublicDomain,
)

db = Database("ext_nostrnip5")


async def get_domain(domain_id: str, wallet_id: str) -> Optional[Domain]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.domains WHERE id = ? AND wallet = ?",
        (
            domain_id,
            wallet_id,
        ),
    )
    return Domain.from_row(row) if row else None


async def get_domain_by_id(domain_id: str) -> Optional[Domain]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.domains WHERE id = ?",
        (domain_id,),
    )
    return Domain.from_row(row) if row else None


async def get_domain_public_data(domain_id: str) -> Optional[PublicDomain]:
    row = await db.fetchone(
        "SELECT id, currency, cost, domain FROM nostrnip5.domains WHERE id = ?",
        (domain_id,),
    )
    return PublicDomain.from_row(row) if row else None


async def get_domain_by_name(domain: str) -> Optional[Domain]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.domains WHERE domain = ?", (domain,)
    )
    return Domain.from_row(row) if row else None


async def get_domains(wallet_ids: Union[str, List[str]]) -> List[Domain]:
    if isinstance(wallet_ids, str):
        wallet_ids = [wallet_ids]

    q = ",".join(["?"] * len(wallet_ids))
    rows = await db.fetchall(
        f"SELECT * FROM nostrnip5.domains WHERE wallet IN ({q})", (*wallet_ids,)
    )

    return [Domain.from_row(row) for row in rows]


async def get_address(domain_id: str, address_id: str) -> Optional[Address]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.addresses WHERE domain_id = ? AND id = ?",
        (
            domain_id,
            address_id,
        ),
    )
    return Address.from_row(row) if row else None


async def get_address_by_local_part(
    domain_id: str, local_part: str
) -> Optional[Address]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.addresses WHERE domain_id = ? AND local_part = ?",
        (
            domain_id,
            local_part.lower(),
        ),
    )
    return Address.from_row(row) if row else None


async def get_addresses(domain_id: str) -> List[Address]:
    rows = await db.fetchall(
        "SELECT * FROM nostrnip5.addresses WHERE domain_id = ?", (domain_id,)
    )

    return [Address.from_row(row) for row in rows]


async def get_addresses_for_owner(owner_id: str) -> List[Address]:
    rows = await db.fetchall(
        "SELECT * FROM nostrnip5.addresses WHERE owner_id = ?", (owner_id,)
    )

    return [Address.from_row(row) for row in rows]


async def get_all_addresses(wallet_ids: Union[str, List[str]]) -> List[Address]:
    if isinstance(wallet_ids, str):
        wallet_ids = [wallet_ids]

    q = ",".join(["?"] * len(wallet_ids))
    rows = await db.fetchall(
        f"""
        SELECT a.*
        FROM nostrnip5.addresses a
        JOIN nostrnip5.domains d ON d.id = a.domain_id
        WHERE d.wallet IN ({q})
        """,
        (*wallet_ids,),
    )

    return [Address.from_row(row) for row in rows]


async def activate_address(domain_id: str, address_id: str) -> Address:
    await db.execute(
        """
        UPDATE nostrnip5.addresses
        SET active = true
        WHERE domain_id = ?
        AND id = ?
        """,
        (
            domain_id,
            address_id,
        ),
    )

    address = await get_address(domain_id, address_id)
    assert address, "Newly updated address couldn't be retrieved"
    return address


async def rotate_address(domain_id: str, address_id: str, pubkey: str) -> Address:
    await db.execute(
        """
        UPDATE nostrnip5.addresses
        SET pubkey = ?
        WHERE domain_id = ?
        AND id = ?
        """,
        (
            pubkey,
            domain_id,
            address_id,
        ),
    )

    address = await get_address(domain_id, address_id)
    assert address, "Newly updated address couldn't be retrieved"
    return address


async def delete_domain(domain_id: str, wallet_id: str) -> bool:
    domain = await get_domain(domain_id, wallet_id)
    if not domain:
        return False
    await db.execute(
        """
        DELETE FROM nostrnip5.addresses WHERE domain_id = ?
        """,
        (domain_id,),
    )

    await db.execute(
        """
        DELETE FROM nostrnip5.domains WHERE id = ?
        """,
        (domain_id,),
    )

    return True


async def delete_address(domain_id, address_id):
    await db.execute(
        """
        DELETE FROM nostrnip5.addresses WHERE domain_id = ? AND id = ?
        """,
        (
            domain_id,
            address_id,
        ),
    )


async def create_address_internal(
    domain_id: str, data: CreateAddressData, owner_id: Optional[str] = None
) -> Address:
    address_id = urlsafe_short_hash()

    await db.execute(
        """
        INSERT INTO nostrnip5.addresses
        (id, domain_id, owner_id, local_part, pubkey, active)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            address_id,
            domain_id,
            owner_id,
            data.local_part.lower(),
            data.pubkey,
            False,
        ),
    )

    address = await get_address(domain_id, address_id)
    assert address, "Newly created address couldn't be retrieved"
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
        SET cost = ?, currency = ?, cost_extra = ?
        WHERE id = ?
        """,
        (data.cost, data.currency, cost_extra, data.id),
    )

    domain = await get_domain(data.id, wallet_id)
    assert domain, "Domain couldn't be updated"
    return domain


async def create_domain_internal(wallet_id: str, data: CreateDomainData) -> Domain:
    domain_id = urlsafe_short_hash()

    cost_extra = (
        json.dumps(data.cost_config, default=lambda o: o.__dict__)
        if data.cost_config
        else None
    )
    await db.execute(
        """
        INSERT INTO nostrnip5.domains (id, wallet, currency, cost, domain, cost_extra)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (domain_id, wallet_id, data.currency, data.cost, data.domain, cost_extra),
    )

    domain = await get_domain(domain_id, wallet_id)
    assert domain, "Newly created domain couldn't be retrieved"
    return domain


async def create_domain_ranking(name: str, rank: int):
    await db.execute(
        """
        INSERT INTO nostrnip5.domain_rankings(name, rank) VALUES (?, ?)
        ON CONFLICT (name) DO NOTHING
        """,
        (name, rank),
    )


async def get_domain_ranking(name: str) -> Optional[DomainRanking]:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.domain_rankings WHERE name = ?",
        (name,),
    )
    return DomainRanking.from_row(row) if row else None


async def delete_inferior_ranking(name: str, rank: int):
    await db.execute(
        """
        DELETE from nostrnip5.domain_rankings
        WHERE name = ? and rank > ?
        """,
        (name, rank),
    )


async def create_settings(owner_id: str, settings: Nip5Settings):
    settings_json = json.dumps(settings, default=lambda o: o.__dict__)
    await db.execute(
        """
        INSERT INTO nostrnip5.settings(owner_id, settings) VALUES (?, ?)
        ON CONFLICT (owner_id) DO UPDATE SET settings = ?
        """,
        (owner_id, settings_json, settings_json),
    )


async def get_settings(owner_id: str) -> Nip5Settings:
    row = await db.fetchone(
        "SELECT * FROM nostrnip5.settings WHERE owner_id = ?",
        (owner_id,),
    )
    return Nip5Settings.from_row(row) if row else Nip5Settings()
