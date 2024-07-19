import re
from functools import wraps
from hashlib import sha256
from http import HTTPStatus
from typing import Optional
from urllib.parse import urlparse

from bech32 import bech32_decode, convertbits
from loguru import logger
from starlette.exceptions import HTTPException


def http_try_except(f):
    @wraps(f)
    async def wrapper(*arg, **kwargs):
        try:
            await f(*arg, **kwargs)
        except HTTPException as exc:
            raise exc
        except AssertionError as exc:
            logger.error(exc)
            raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc)) from exc
        except Exception as exc:
            logger.error(exc)
            raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR) from exc

    return wrapper


def normalize_identifier(identifier: str):
    identifier = identifier.lower().split("@")[0]
    validate_local_part(identifier)
    return identifier


def validate_pub_key(pubkey: str):
    if pubkey.startswith("npub"):
        _, data = bech32_decode(pubkey)
        if data:
            decoded_data = convertbits(data, 5, 8, False)
            if decoded_data:
                pubkey = bytes(decoded_data).hex()
    try:
        _hex = bytes.fromhex(pubkey)
    except Exception as exc:
        raise ValueError("Pubkey must be in npub or hex format.") from exc

    if len(_hex) != 32:
        raise ValueError("Pubkey length incorrect.")

    return pubkey


def validate_local_part(local_part: str):
    if local_part == "_" or local_part == ".":
        raise ValueError("You're sneaky, nice try.")

    regex = re.compile(r"^[a-z0-9_.]+$")
    if not re.fullmatch(regex, local_part.lower()):
        raise ValueError(
            "Only a-z, 0-9 and .-_ are allowed characters, case insensitive."
        )


def is_ws_url(url):
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        return result.scheme in ["ws", "wss"]
    except ValueError:
        return False


def owner_id_from_user_id(user_id: Optional[str] = None) -> str:
    return sha256((user_id or "").encode("utf-8")).hexdigest()


def format_amount(amount: float, currency: str):
    return str(int(amount)) if currency == "sats" else format(amount, ".2f")
