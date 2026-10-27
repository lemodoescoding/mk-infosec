from common.utils import validate_aes128_key, validate_aes_key
from config.constants import (
    AES_BLOCK_SIZE,
    AES_KEY_SIZE,
    AES_ROUNDS,
    AES_NB,
    AES_NK,
    SBOX,
    INV_SBOX,
    RCON,
)

# TODO: implement the AES main algorithm

# copied from the FIPS 197 - NIST
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

# Algorithm 1 Pseudocode for CIPHER()
# 1: procedure CIPHER(in, Nr, w)
# 2: state ← in . See Sec. 3.4
# 3: state ← ADDROUNDKEY(state, w[0..3]) . See Sec. 5.1.4
# 4: for round from 1 to Nr − 1 do
# 5: state ← SUBBYTES(state) . See Sec. 5.1.1
# 6: state ← SHIFTROWS(state) . See Sec. 5.1.2
# 7: state ← MIXCOLUMNS(state) . See Sec. 5.1.3
# 8: state ← ADDROUNDKEY(state, w[4 ∗ round..4 ∗ round + 3])
# 9: end for
# 10: state ← SUBBYTES(state)
# 11: state ← SHIFTROWS(state)
# 12: state ← ADDROUNDKEY(state, w[4 ∗ Nr..4 ∗ Nr + 3])
# 13: return state . See Sec. 3.4
# 14: end procedure

# Algorithm 2 Pseudocode for KEYEXPANSION()
# 1: procedure KEYEXPANSION(key)
# 2: i ← 0
# 3: while i ≤ Nk − 1 do
# 4: w[i] ← key[4 ∗ i..4 ∗ i + 3]
# 5: i ← i + 1
# 6: end while . When the loop concludes, i = Nk.
# 7: while i ≤ 4 ∗ Nr + 3 do
# 8: temp ← w[i − 1]
# 9: if i mod Nk = 0 then
# 10: temp ← SUBWORD(ROTWORD(temp)) ⊕ Rcon[i/Nk]
# 11: else if Nk > 6 and i mod Nk = 4 then
# 12: temp ← SUBWORD(temp)
# 13: end if
# 14: w[i] ← w[i − Nk] ⊕ temp
# 15: i ← i + 1
# 16: end while
# 17: return w
# 18: end procedure

# Algorithm 3 Pseudocode for INVCIPHER()
# 1: procedure INVCIPHER(in, Nr, w)
# 2: state ← in . See Sec. 3.4
# 3: state ← ADDROUNDKEY(state, w[4 ∗ Nr..4 ∗ Nr + 3]) . See Sec. 5.1.4
# 4: for round from Nr − 1 downto 1 do
# 5: state ← INVSHIFTROWS(state) . See Sec. 5.3.1
# 6: state ← INVSUBBYTES(state) . See Sec. 5.3.2
# 7: state ← ADDROUNDKEY(state, w[4 ∗ round..4 ∗ round + 3])
# 8: state ← INVMIXCOLUMNS(state) . See Sec. 5.3.3
# 9: end for
# 10: state ← INVSHIFTROWS(state)
# 11: state ← INVSUBBYTES(state)
# 12: state ← ADDROUNDKEY(state, w[0..3])
# 13: return state
# 14: end procedure

class AES:
    def __init__(self, key: bytes):
        validate_aes_key(key)

        if len(SBOX) != 256 or len(INV_SBOX) != 256:
            raise ValueError("SBOX and INV_SBOX must each contains the 256 value")

        self.key = key
        self.nk = len(key) // 4
        self.nr = self.nk + 6
        self.round_keys = self.key_expansion(key)

    @staticmethod
    def _bytes_to_state(block: bytes) -> list[list[int]]:
        if len(block) != AES_BLOCK_SIZE:
            raise ValueError("AES block must be 16 bytes long")

        return [
            [block[4 * column + row] for column in range(AES_NB)] for row in range(AES_NB)
        ]
    @staticmethod
    def _state_to_bytes(state: list[list[int]]) -> bytes:
        return bytes(
            state[row][column] for column in range(AES_NB) for row in range(AES_NB)
        )

    @staticmethod
    def _rot_word(word: list[int]) -> list[int]:
        return word[1:] + word[:1]

    @staticmethod
    def _sub_word(word: list[int]) -> list[int]:
        return [SBOX[byte] for byte in word]

    def key_expansion(self, key: bytes) -> list[bytes]:
        validate_aes_key(key)

        nk = len(key) // 4
        nr = nk + 6

        words = [
            list(key[4 * i:4 * i + 4]) for i in range(nk)
        ]

        total_words = AES_NB * (nr + 1)

        for i in range(nk, total_words):
            temp = words[i - 1].copy()

            if i % nk == 0:
                temp = self._sub_word(self._rot_word(temp))

                rcon_word = RCON[i // nk]
                temp[0] ^= (rcon_word >> 24) & 0xFF

            elif nk > 6 and i % nk == 4:
                # AES-256 only: an extra SubWord halfway through every key block
                temp = self._sub_word(temp)

            new_word = [
                words[i - nk][j] ^ temp[j] for j in range(4)
            ]
            
            words.append(new_word)

        round_keys = []

        for round_number in range(nr + 1):
            first_word = round_number * AES_NB
            key_bytes = []

            for word in words[first_word:first_word + AES_NB]:
                key_bytes.extend(word)

            round_keys.append(bytes(key_bytes))

        return round_keys

    def add_round_key(self, state: list[list[int]], round_key: bytes):
        if len(round_key) != AES_BLOCK_SIZE:
            raise ValueError("round key must be 16 bytes long")

        for column in range(AES_NB):
            for row in range(AES_NB):
                state[row][column] ^= round_key[AES_NB * column + row]

        return state

    @staticmethod
    def sub_bytes(state: list[list[int]]) -> list[list[int]]:
        for row in range(AES_NB):
            for column in range(AES_NB):
                state[row][column] = SBOX[state[row][column]]

        return state

    @staticmethod
    def inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
        for row in range(AES_NB):
            for column in range(AES_NB):
                state[row][column] = INV_SBOX[state[row][column]]

        return state

    @staticmethod
    def shift_rows(state: list[list[int]]) -> list[list[int]]:
        for row in range(1, AES_NB):
            state[row] = (
                state[row][row:] + state[row][:row]
            )

        return state

    @staticmethod
    def inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
        for row in range(1, AES_NB):
            state[row] = (
                state[row][-row:] + state[row][:-row]
            )

        return state

    @staticmethod
    def _gf_mul(a: int, b: int) -> int:
        result = 0

        for _ in range(8):
            if b & 1:
                result ^= a

            high_bit = a & 0x80
            a = (a << 1) & 0xFF

            if high_bit:
                a ^= 0x1B

            b >>= 1

        return result

    @classmethod
    def mix_columns(cls, state: list[list[int]]) -> list[list[int]]:
        for column in range(AES_NB):
            a0 = state[0][column]
            a1 = state[1][column]
            a2 = state[2][column]
            a3 = state[3][column]

            state[0][column] = (
                cls._gf_mul(a0, 2)
                ^ cls._gf_mul(a1, 3)
                ^ a2
                ^ a3
            )
            
            state[1][column] = (
                a0
                ^ cls._gf_mul(a1, 2)
                ^ cls._gf_mul(a2, 3)
                ^ a3
            )

            state[2][column] = (
                a0
                ^ a1
                ^ cls._gf_mul(a2, 2)
                ^ cls._gf_mul(a3, 3)
            )

            state[3][column] = (
                cls._gf_mul(a0, 3)
                ^ a1
                ^ a2
                ^ cls._gf_mul(a3, 2)
            )

        return state

    @classmethod
    def inv_mix_columns(cls, state: list[list[int]]) -> list[list[int]]:
        for column in range(AES_NB):
            a0 = state[0][column]
            a1 = state[1][column]
            a2 = state[2][column]
            a3 = state[3][column]

            state[0][column] = (
                cls._gf_mul(a0, 0x0e)
                ^ cls._gf_mul(a1, 0x0b)
                ^ cls._gf_mul(a2, 0x0d)
                ^ cls._gf_mul(a3, 0x09)
            )
            
            state[1][column] = (
                cls._gf_mul(a0, 0x09)
                ^ cls._gf_mul(a1, 0x0e)
                ^ cls._gf_mul(a2, 0x0b)
                ^ cls._gf_mul(a3, 0x0d)            
            )

            state[2][column] = (
                cls._gf_mul(a0, 0x0d)
                ^ cls._gf_mul(a1, 0x09)
                ^ cls._gf_mul(a2, 0x0e)
                ^ cls._gf_mul(a3, 0x0b)
            )

            state[3][column] = (
                cls._gf_mul(a0, 0x0b)
                ^ cls._gf_mul(a1, 0x0d)
                ^ cls._gf_mul(a2, 0x09)
                ^ cls._gf_mul(a3, 0x0e)
            )

        return state
        raise NotImplementedError

    # def encrypt_block(self, plaintext: bytes) -> bytes:
    #     raise NotImplementedError
    #
    # def decrypt_block(self, ciphertext: bytes) -> bytes:
    #     raise NotImplementedError

        
    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != AES_BLOCK_SIZE:
            raise ValueError("Plaintext block must be exactly 16 bytes")

        state = self._bytes_to_state(plaintext)

        # Initial AddRoundKey.
        self.add_round_key(state, self.round_keys[0])

        # Rounds 1 through 9 for AES-128.
        for round_number in range(1, self.nr):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(
                state,
                self.round_keys[round_number],
            )

        # Final round: no MixColumns.
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, self.round_keys[self.nr])

        return self._state_to_bytes(state)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 16-byte ciphertext block."""
        if len(ciphertext) != AES_BLOCK_SIZE:
            raise ValueError("Ciphertext block must be exactly 16 bytes")

        state = self._bytes_to_state(ciphertext)

        # Start with the final round key.
        self.add_round_key(state, self.round_keys[self.nr])

        # Rounds 9 down to 1.
        for round_number in range(self.nr - 1, 0, -1):
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)
            self.add_round_key(
                state,
                self.round_keys[round_number],
            )
            self.inv_mix_columns(state)

        # Final inverse round: no InvMixColumns.
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state)
        self.add_round_key(state, self.round_keys[0])

        return self._state_to_bytes(state)
