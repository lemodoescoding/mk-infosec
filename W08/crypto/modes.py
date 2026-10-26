import secrets

from crypto.aes import AES
from config.constants import AES_BLOCK_SIZE
from common.utils import (
    pkcs7_pad,
    pkcs7_unpad,
    ascii_to_bytes,
    key_from_ascii
)

def ecb_encrypt(aes: AES, plaintext: bytes) -> bytes:
    # encrypt wrapper for arbitrary-length bytes using AES-ECB
    padded = pkcs7_pad(plaintext, AES_BLOCK_SIZE)

    return b"".join(
        aes.encrypt_block(padded[i:i + AES_BLOCK_SIZE])
        for i in range(0, len(padded), AES_BLOCK_SIZE)
    )


def ecb_decrypt(aes: AES, ciphertext: bytes) -> bytes:
    # decrypt wrapper for AES-ECB ciphertext and remove padding
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("ECB ciphertext must contain complete blocks")

    plaintext = b"".join(
        aes.decrypt_block(ciphertext[i:i + AES_BLOCK_SIZE])
        for i in range(0, len(ciphertext), AES_BLOCK_SIZE)
    )

    return pkcs7_unpad(plaintext, AES_BLOCK_SIZE)


def cbc_encrypt(
    aes: AES,
    plaintext: bytes,
    iv: bytes | None = None,
) -> tuple[bytes, bytes]:
    # encrypts using AES-CBC. return tuple (IV, ciphertext)
    if iv is None:
        iv = secrets.token_bytes(AES_BLOCK_SIZE)

    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("CBC IV must be exactly 16 bytes")

    padded = pkcs7_pad(plaintext, AES_BLOCK_SIZE)
    ciphertext_blocks = []
    previous_block = iv

    for i in range(0, len(padded), AES_BLOCK_SIZE):
        block = padded[i:i + AES_BLOCK_SIZE]

        # CBC: C_i = AES(P_i XOR C_(i-1)), where C_0 = IV.
        mixed = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted = aes.encrypt_block(mixed)

        ciphertext_blocks.append(encrypted)
        previous_block = encrypted

    return iv, b"".join(ciphertext_blocks)


def cbc_decrypt(
    aes: AES,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    # decrypts AES-CBC ciphertext and remove padding
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("CBC IV must be exactly 16 bytes")

    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("CBC ciphertext must contain complete blocks")

    plaintext_blocks = []
    previous_block = iv

    for i in range(0, len(ciphertext), AES_BLOCK_SIZE):
        block = ciphertext[i:i + AES_BLOCK_SIZE]

        # CBC: P_i = AES^-1(C_i) XOR C_(i-1).
        decrypted = aes.decrypt_block(block)
        plaintext = bytes(
            a ^ b for a, b in zip(decrypted, previous_block)
        )

        plaintext_blocks.append(plaintext)
        previous_block = block

    return pkcs7_unpad(b"".join(plaintext_blocks), AES_BLOCK_SIZE)


def encrypt_text(
    key: bytes,
    plaintext: str,
    mode: str = "CBC",
) -> dict:
    # encrypts UTF-8 encoded text into a transport-friendly dictionary
    aes = AES(key)
    plaintext_bytes = ascii_to_bytes(plaintext, "Plaintext")
    mode = mode.upper()

    if mode == "ECB":
        ciphertext = ecb_encrypt(aes, plaintext_bytes)
        iv_hex = None
    elif mode == "CBC":
        iv, ciphertext = cbc_encrypt(aes, plaintext_bytes)
        iv_hex = iv.hex()
    else:
        raise ValueError(f"Unsupported AES mode: {mode}")

    return {
        "mode": mode,
        "iv": iv_hex,
        "ciphertext": ciphertext.hex(),
    }


def decrypt_text(key: bytes, message: dict) -> str:
    # decrypts a dictionary returned by encrypt_text()
    aes = AES(key)
    mode = message["mode"].upper()
    ciphertext = bytes.fromhex(message["ciphertext"])

    if mode == "ECB":
        plaintext = ecb_decrypt(aes, ciphertext)
    elif mode == "CBC":
        iv = bytes.fromhex(message["iv"])
        plaintext = cbc_decrypt(aes, iv, ciphertext)
    else:
        raise ValueError(f"Unsupported AES mode: {mode}")

    return plaintext.decode("ascii")
