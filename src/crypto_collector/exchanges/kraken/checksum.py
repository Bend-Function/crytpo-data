from __future__ import annotations

from collections.abc import Iterable
from zlib import crc32


def checksum_decimal_digits(value: str) -> str:
    if type(value) is not str or not value:
        raise TypeError("checksum decimal value must be a non-empty string")
    if value.count(".") > 1 or any(
        not (character.isascii() and character.isdigit()) and character != "."
        for character in value
    ):
        raise ValueError("checksum decimal value must use plain unsigned notation")
    digits = value.replace(".", "")
    if not digits:
        raise ValueError("checksum decimal value must contain digits")
    return digits.lstrip("0") or "0"


def kraken_spot_checksum_input(
    asks: Iterable[tuple[str, str]],
    bids: Iterable[tuple[str, str]],
) -> str:
    parts: list[str] = []
    for price, quantity in (*tuple(asks), *tuple(bids)):
        parts.append(checksum_decimal_digits(price))
        parts.append(checksum_decimal_digits(quantity))
    return "".join(parts)


def kraken_spot_crc32(value: str) -> int:
    if type(value) is not str:
        raise TypeError("checksum input must be a string")
    return crc32(value.encode("ascii")) & 0xFFFFFFFF


__all__ = [
    "checksum_decimal_digits",
    "kraken_spot_checksum_input",
    "kraken_spot_crc32",
]
