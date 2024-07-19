import asyncio

from lnbits.core.models import Payment
from lnbits.tasks import register_invoice_listener
from loguru import logger

from .crud import get_address, update_address
from .services import activate_address


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

    address = await get_address(domain_id, address_id)
    if not address:
        logger.info(
            f"Cannot find address for payment '{payment.payment_hash}'."
            f"Missing domain ID ({domain_id}) or address ID ({address_id})."
        )
        return

    if action == "activate":
        activated = await activate_address(domain_id, address_id, payment.payment_hash)
        if not activated:
            address.config.reimburse_payment_hash = payment.payment_hash
            await update_address(
                domain_id,
                address_id,
                reimburse_amount=payment.amount,
                config=address.config,
            )
    elif action == "reimburse":
        await update_address(domain_id, address_id, reimburse_amount=0)
