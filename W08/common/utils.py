import json
import secrets
import socket

# bytes_to_hex(data)
def bytes_to_hex(data: bytes) -> str:
    return data.hex()

# hex_to_bytes(text)
def hex_to_bytes(text: str) -> bytes:
    return bytes.fromhex(text)

# xor_bytes(a, b)
def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Inputs must have equal length")

    return bytes(x ^ y for x, y in zip(a, b))

# pad(data, block_size) --> PKCS#7
def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be between 1 and 255")

    pad_length = block_size - (len(data) % block_size)
    return data + bytes([pad_length]) * pad_length

# unpad(data, block_size)
def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Padded data must be non-empty and block-aligned")

    pad_length = data[-1]
    if not 1 <= pad_length <= block_size:
        raise ValueError("Invalid PKCS#7 padding")
    if data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_length]

# generate_random_bytes(n)
def generate_random_bytes(n: int) -> bytes:
    if n < 0:
        raise ValueError("N (length) cannot be negative")

    return secrets.token_bytes(n)

# validate_aes_key(key)
def validate_aes_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")

# validate_block(block)
def validate_block(block: bytes) -> None:
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")

# validate_aes128_key(key)
def validate_aes128_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")

# converts ASCII string to bytes, and rejecting any non-ASCII chars
def ascii_to_bytes(value: str, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} must contain ASCII characters only") from exc

# converts the key for the AES from ASCII to bytes
def key_from_ascii(key: str) -> bytes:
    key_bytes = ascii_to_bytes(key, "AES key")

    validate_aes_key(key_bytes)

    return key_bytes

# serialize a payload to ASCII json
def serialize_payload(payload: dict) -> str:
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=True
    )
