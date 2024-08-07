import asyncio

from lnbits.core.models import Payment
from lnbits.tasks import register_invoice_listener
from loguru import logger

from .crud import get_address, update_address
from .models import Address
from .services import activate_address, update_ln_address


async def wait_for_paid_invoices():
    invoice_queue = asyncio.Queue()
    register_invoice_listener(invoice_queue)

    while True:
        payment = await invoice_queue.get()
        await on_invoice_paid(payment)


async def on_invoice_paid(payment: Payment) -> None:
    if payment.extra.get("tag") != "nostrnip5":
        return

    domain_id = payment.extra.get("domain_id")
    address_id = payment.extra.get("address_id")
    action = payment.extra.get("action")

    if not domain_id or not address_id or not action:
        logger.info(
            f"Cannot {action} for payment '{payment.payment_hash}'."
            f"Missing domain ID ({domain_id}) or address ID ({address_id})."
        )
        return

    try:
        address = await get_address(domain_id, address_id)
        if not address:
            logger.info(
                f"Cannot find address for payment '{payment.payment_hash}'."
                f"Missing domain ID ({domain_id}) or address ID ({address_id})."
            )
            return

        await _handle_action(action, payment, address)
    except Exception as exc:
        logger.warning(exc)
        logger.info(f"Failed to {action} address `{domain_id}/{address_id}`")


async def _handle_action(action: str, payment: Payment, address: Address):
    if action == "activate":
        await _activate_address(payment, address)
    if action == "reimburse":
        await _reimburse_payment(address)


async def _activate_address(payment: Payment, address: Address):
    activated = await activate_address(
        address.domain_id, address.id, payment.payment_hash
    )
    if activated:
        await _create_ln_address(payment, address)
    else:
        await _update_reimburse_data(payment, address)


async def _update_reimburse_data(payment: Payment, address: Address):
    address.config.reimburse_payment_hash = payment.payment_hash
    await update_address(
        address.domain_id,
        address.id,
        reimburse_amount=payment.amount,
        config=address.config,
    )


async def _create_ln_address(payment: Payment, address: Address):
    wallet = payment.extra.get("reimburse_wallet_id")
    if not wallet:
        logger.warning(
            "Now wallet found for Lightning Address"
            f" '{address.local_part} ({address.id}')."
        )
        return
    address.config.ln_address.wallet = wallet
    await update_ln_address(address)


async def _reimburse_payment(address: Address):
    await update_address(address.domain_id, address.id, reimburse_amount=0)
