from .crud import get_address_by_local_part, get_domain_by_id, get_identifier_ranking
from .models import AddressStatus


async def get_identifier_status(domain_id: str, identifier: str) -> AddressStatus:
    address = await get_address_by_local_part(domain_id, identifier)
    reserved = address is not None
    if address and address.active:
        return AddressStatus(available=False, reserved=reserved)

    domain = await get_domain_by_id(domain_id)
    assert domain, "Unknown domain id."

    rank = None
    if domain.cost_config.enable_custom_cost:
        identifier_ranking = await get_identifier_ranking(identifier)
        rank = identifier_ranking.rank if identifier_ranking else None

    if rank == 0:
        return AddressStatus(available=False, reserved=True)

    price, reason = domain.price_for_identifier(identifier, rank)

    return AddressStatus(
        available=True,
        reserved=reserved,
        price=price,
        price_reason=reason,
        currency=domain.currency,
    )
