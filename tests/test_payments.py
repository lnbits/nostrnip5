from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from lnbits.core.models import Payment, PaymentState

from .. import services, tasks
from ..models import Address, AddressExtra, Domain, DomainCostConfig, PriceData


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def domain():
    return Domain(
        id="domain",
        wallet="domain-wallet",
        currency="sat",
        cost=21,
        domain="example.test",
        time=datetime.now(timezone.utc),
        cost_extra=DomainCostConfig(),
    )


@pytest.fixture
def address(domain):
    return Address(
        id="address",
        domain_id=domain.id,
        local_part="alice",
        active=False,
        time=datetime.now(timezone.utc),
        extra=AddressExtra(
            payment_hash="a" * 64,
            payment_amount_msat=21000,
            price=21,
            currency="sat",
        ),
    )


@pytest.fixture
def payment(domain, address):
    return Payment(
        checking_id="checking",
        payment_hash=address.extra.payment_hash,
        wallet_id=domain.wallet,
        amount=21000,
        fee=0,
        bolt11="",
        status=PaymentState.SUCCESS,
        extra={
            "tag": "nostrnip5",
            "domain_id": domain.id,
            "address_id": address.id,
            "action": "activate",
        },
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "changes",
    [
        {"wallet_id": "another-wallet"},
        {"payment_hash": "b" * 64},
        {"amount": 1000},
        {"amount": -21000},
        {"status": PaymentState.PENDING},
        {"status": PaymentState.FAILED},
    ],
)
async def test_activation_requires_matching_payment(
    monkeypatch, domain, address, payment, changes
):
    monkeypatch.setattr(tasks, "get_address", AsyncMock(return_value=address))
    monkeypatch.setattr(tasks, "get_domain_by_id", AsyncMock(return_value=domain))
    activate = AsyncMock()
    monkeypatch.setattr(tasks, "activate_address", activate)

    await tasks.on_invoice_paid(payment.model_copy(update=changes))

    activate.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("state", ["pending", "active", "unrecorded"])
async def test_activation_state(monkeypatch, domain, address, payment, state):
    if state == "active":
        address.active = True
    if state == "unrecorded":
        address.extra.payment_hash = None
        address.extra.payment_amount_msat = None
    monkeypatch.setattr(tasks, "get_address", AsyncMock(return_value=address))
    monkeypatch.setattr(tasks, "get_domain_by_id", AsyncMock(return_value=domain))
    activate = AsyncMock(return_value=address)
    monkeypatch.setattr(tasks, "activate_address", activate)
    monkeypatch.setattr(tasks, "_create_ln_address", AsyncMock())
    monkeypatch.setattr(tasks, "_pay_promo_code", AsyncMock())

    await tasks.on_invoice_paid(payment)

    if state == "pending":
        activate.assert_awaited_once_with(
            domain.id, address.id, payment_hash=payment.payment_hash
        )
    else:
        activate.assert_not_awaited()


@pytest.mark.anyio
async def test_invoice_records_payment_details(monkeypatch, domain, address, payment):
    price = PriceData(currency="sats", price=21, reason="")
    monkeypatch.setattr(
        services, "get_identifier_price_data", AsyncMock(return_value=price)
    )
    monkeypatch.setattr(
        services, "create_payment_request", AsyncMock(return_value=payment)
    )
    update = AsyncMock()
    monkeypatch.setattr(services, "update_address", update)
    address.extra.payment_hash = None
    address.extra.payment_amount_msat = None

    result = await services.create_invoice_for_identifier(domain, address, "buyer")

    assert result is payment
    assert address.extra.payment_hash == payment.payment_hash
    assert address.extra.payment_amount_msat == payment.amount
    update.assert_awaited_once_with(address)


@pytest.mark.anyio
@pytest.mark.parametrize("bonus, expected", [(5, 5), (30, 21)])
async def test_referral_amount(monkeypatch, address, payment, bonus, expected):
    payment.extra.update(referer="bob", referer_bonus_sats=bonus)
    pay = AsyncMock()
    monkeypatch.setattr(tasks, "pay_referer_for_promo_code", pay)

    await tasks._pay_promo_code(payment, address)

    pay.assert_awaited_once_with(address, "bob", expected)
