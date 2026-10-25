from common.utils import validate_aes128_key
from config.constants import (
    AES_BLOCK_SIZE,
    AES_KEY_SIZE,
    AES_ROUNDS,
    SBOX,
    INV_SBOX,
    RCON,
)

# TODO: implement the AES main algorithm

class AES:
    def __init__(self, key: bytes):
        validate_aes128_key(key)
        self.key = key
        self.round_keys = self.key_expansion(key)

    def key_expansion(self, key: bytes):
        """Generate the round keys."""
        raise NotImplementedError

    def sub_bytes(self, state):
        raise NotImplementedError

    def inv_sub_bytes(self, state):
        raise NotImplementedError

    def shift_rows(self, state):
        raise NotImplementedError

    def inv_shift_rows(self, state):
        raise NotImplementedError

    def mix_columns(self, state):
        raise NotImplementedError

    def inv_mix_columns(self, state):
        raise NotImplementedError

    def add_round_key(self, state, round_key):
        raise NotImplementedError

    def encrypt_block(self, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        raise NotImplementedError
