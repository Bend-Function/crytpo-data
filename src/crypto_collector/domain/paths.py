from urllib.parse import unquote

_SAFE = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.~")


def encode_instrument_key(instrument_key: str) -> str:
    if not instrument_key or instrument_key in {".", ".."} or "\x00" in instrument_key:
        raise ValueError("instrument key is not path-safe")
    return "".join(
        chr(byte) if byte in _SAFE else f"%{byte:02X}"
        for byte in instrument_key.encode("utf-8")
    )


def decode_instrument_key(encoded: str) -> str:
    return unquote(encoded, encoding="utf-8", errors="strict")
