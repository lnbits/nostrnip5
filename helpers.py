import re
from hashlib import sha256
from typing import Optional

from bech32 import bech32_decode, convertbits


def validate_pub_key(pubkey: str):
    if pubkey.startswith("npub"):
        _, data = bech32_decode(pubkey)
        if data:
            decoded_data = convertbits(data, 5, 8, False)
            if decoded_data:
                pubkey = bytes(decoded_data).hex()

    if len(bytes.fromhex(pubkey)) != 32:
        raise ValueError("Pubkey must be in npub or hex format.")

    return pubkey


def validate_local_part(local_part: str):
    if local_part == "_":
        raise ValueError("You're sneaky, nice try.")

    regex = re.compile(r"^[a-z0-9_.]+$")
    if not re.fullmatch(regex, local_part.lower()):
        raise ValueError(
            "Only a-z, 0-9 and .-_ are allowed characters, case insensitive."
        )


def owner_id_from_user_id(user_id: Optional[str] = None) -> str:
    return sha256((user_id or "").encode("utf-8")).hexdigest()
