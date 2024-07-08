import asyncio

from lnbits.core.models import Payment
from lnbits.tasks import register_invoice_listener

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

    if domain_id and address_id:
        await activate_address(domain_id, address_id, payment_hash=payment.payment_hash)

    return
