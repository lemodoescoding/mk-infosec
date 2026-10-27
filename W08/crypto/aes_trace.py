"""Step-by-step AES tracing (128/192/256-bit keys) (educational).

TracedAES subclasses the project's AES and re-uses its own primitives
(sub_bytes, shift_rows, mix_columns, add_round_key, ...), so what is printed
is what the real implementation computes. Every value is printed as hex.

Notes on the state layout (FIPS 197): the 16 input bytes fill the 4x4 state
column by column. The one-line hex shown for each step is the state read back
in that same order, i.e. the same byte order as the block itself.
"""
from typing import Optional

from common.utils import (
    generate_random_bytes,
    pkcs7_pad,
    pkcs7_unpad,
    xor_bytes,
    ascii_to_bytes,
)
from config.constants import (
    AES_BLOCK_SIZE,
    AES_NB,
    RCON,
)
from crypto.aes import AES


def hexs(data) -> str:
    # bytes / list of ints -> "19 3d e3 be ..."
    return " ".join(f"{b:02x}" for b in data)


class TracedAES(AES):
    def __init__(self, key: bytes, log=print, matrix: bool = False):
        self._log = log
        self._matrix = matrix
        super().__init__(key)
        self._trace_key_schedule(key)

    # ---------------------------------------------------------------- helpers
    def _show(self, label: str, state: list[list[int]]) -> None:
        self._log(f"    {label:<26}{hexs(self._state_to_bytes(state))}")
        if self._matrix:
            for row in state:
                self._log(f"    {'':<26}[ {hexs(row)} ]")

    def _add_round_key(self, state, round_number: int) -> None:
        round_key = self.round_keys[round_number]
        self._log(f"    {f'round_key[{round_number}]':<26}{hexs(round_key)}")
        self.add_round_key(state, round_key)
        self._show("AddRoundKey", state)

    # ----------------------------------------------------------- key schedule
    def _trace_key_schedule(self, key: bytes) -> None:
        log = self._log
        nk, nr = self.nk, self.nr
        total = AES_NB * (nr + 1)
        log("=" * 72)
        log(f"[KEY EXPANSION] AES-{8 * len(key)}: Nk={nk}, Nr={nr}, {total} words")
        log(f"  key = {hexs(key)}")

        words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i, w in enumerate(words):
            log(f"  w[{i:2}] = {hexs(w)}   (copied from key)")

        for i in range(nk, total):
            prev = words[i - 1]
            if i % nk == 0:
                rot = self._rot_word(prev.copy())
                sub = self._sub_word(rot)
                rcon = (RCON[i // nk] >> 24) & 0xFF
                temp = sub.copy()
                temp[0] ^= rcon
                log(
                    f"  w[{i:2}]: w[{i-1}]={hexs(prev)} RotWord={hexs(rot)} "
                    f"SubWord={hexs(sub)} Rcon={rcon:02x} -> temp={hexs(temp)}"
                )
            elif nk > 6 and i % nk == 4:
                temp = self._sub_word(prev.copy())  # AES-256 only
                log(f"  w[{i:2}]: w[{i-1}]={hexs(prev)} SubWord={hexs(temp)} (AES-256 extra step) -> temp={hexs(temp)}")
            else:
                temp = prev
            new = [words[i - nk][j] ^ temp[j] for j in range(4)]
            log(f"  w[{i:2}] = w[{i - nk}]({hexs(words[i - nk])}) ^ temp -> {hexs(new)}")
            words.append(new)

        log("  round keys:")
        for r in range(nr + 1):
            from_words = bytes(b for w in words[4 * r:4 * r + 4] for b in w)
            if from_words != self.round_keys[r]:
                raise RuntimeError("trace disagrees with key_expansion()")
            log(f"    round_key[{r:2}] = {hexs(from_words)}")
        log("=" * 72)

    # ---------------------------------------------------------------- cipher
    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != AES_BLOCK_SIZE:
            raise ValueError("Plaintext block must be exactly 16 bytes")

        log = self._log
        state = self._bytes_to_state(plaintext)
        log(f"  [AES ENCRYPT] input block = {hexs(plaintext)}")
        self._show("state (input)", state)

        log("  Round 0 (initial)")
        self._add_round_key(state, 0)

        for rnd in range(1, self.nr):
            log(f"  Round {rnd}")
            self.sub_bytes(state)
            self._show("SubBytes", state)
            self.shift_rows(state)
            self._show("ShiftRows", state)
            self.mix_columns(state)
            self._show("MixColumns", state)
            self._add_round_key(state, rnd)

        log(f"  Round {self.nr} (final, no MixColumns)")
        self.sub_bytes(state)
        self._show("SubBytes", state)
        self.shift_rows(state)
        self._show("ShiftRows", state)
        self._add_round_key(state, self.nr)

        out = self._state_to_bytes(state)
        log(f"  [AES ENCRYPT] output block = {hexs(out)}")
        return out

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != AES_BLOCK_SIZE:
            raise ValueError("Ciphertext block must be exactly 16 bytes")

        log = self._log
        state = self._bytes_to_state(ciphertext)
        log(f"  [AES DECRYPT] input block = {hexs(ciphertext)}")
        self._show("state (input)", state)

        log(f"  Round {self.nr} (initial inverse)")
        self._add_round_key(state, self.nr)

        for rnd in range(self.nr - 1, 0, -1):
            log(f"  Round {rnd}")
            self.inv_shift_rows(state)
            self._show("InvShiftRows", state)
            self.inv_sub_bytes(state)
            self._show("InvSubBytes", state)
            self._add_round_key(state, rnd)
            self.inv_mix_columns(state)
            self._show("InvMixColumns", state)

        log("  Round 0 (final inverse, no InvMixColumns)")
        self.inv_shift_rows(state)
        self._show("InvShiftRows", state)
        self.inv_sub_bytes(state)
        self._show("InvSubBytes", state)
        self._add_round_key(state, 0)

        out = self._state_to_bytes(state)
        log(f"  [AES DECRYPT] output block = {hexs(out)}")
        return out


# ------------------------------------------------------------ mode wrappers
def traced_encrypt_text(
    aes: TracedAES,
    plaintext: str,
    mode: str = "CBC",
    iv: Optional[bytes] = None,
) -> dict:
    # same output format as crypto.modes.encrypt_text(), but prints every step
    log = aes._log
    mode = mode.upper()
    if mode not in ("ECB", "CBC"):
        raise ValueError(f"Unsupported AES mode: {mode}")

    data = ascii_to_bytes(plaintext, "Plaintext")
    padded = pkcs7_pad(data, AES_BLOCK_SIZE)
    blocks = [padded[i:i + AES_BLOCK_SIZE] for i in range(0, len(padded), AES_BLOCK_SIZE)]

    log(f"[ENCRYPT {mode}] plaintext  = {plaintext!r}")
    log(f"  plaintext hex       = {hexs(data)}")
    log(f"  PKCS#7 padded hex   = {hexs(padded)}  ({len(blocks)} block(s))")

    iv_used: Optional[bytes] = None  # stays None for ECB
    prev = b""                    # previous ciphertext block (CBC chaining)
    if mode == "CBC":
        iv_used = iv if iv is not None else generate_random_bytes(AES_BLOCK_SIZE)
        if len(iv_used) != AES_BLOCK_SIZE:
            raise ValueError("CBC IV must be exactly 16 bytes")
        log(f"  IV                  = {hexs(iv_used)}")
        prev = iv_used

    out = []
    for n, block in enumerate(blocks, 1):
        log(f"--- block {n}/{len(blocks)}: P{n} = {hexs(block)}")
        if mode == "CBC":
            mixed = xor_bytes(block, prev)
            log(f"  CBC: P{n} XOR {'IV' if n == 1 else f'C{n-1}'} = {hexs(mixed)}")
            enc = aes.encrypt_block(mixed)
            prev = enc
        else:
            enc = aes.encrypt_block(block)
        log(f"  C{n} = {hexs(enc)}")
        out.append(enc)

    ciphertext = b"".join(out)
    log(f"[ENCRYPT {mode}] ciphertext = {hexs(ciphertext)}")
    return {
        "mode": mode,
        "iv": iv_used.hex() if iv_used is not None else None,
        "ciphertext": ciphertext.hex(),
    }


def traced_decrypt_text(aes: TracedAES, message: dict) -> str:
    # same input format as crypto.modes.decrypt_text(), but prints every step
    log = aes._log
    mode = message["mode"].upper()
    if mode not in ("ECB", "CBC"):
        raise ValueError(f"Unsupported AES mode: {mode}")

    ciphertext = bytes.fromhex(message["ciphertext"])
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must contain complete 16-byte blocks")
    blocks = [ciphertext[i:i + AES_BLOCK_SIZE] for i in range(0, len(ciphertext), AES_BLOCK_SIZE)]

    log(f"[DECRYPT {mode}] ciphertext = {hexs(ciphertext)}  ({len(blocks)} block(s))")
    prev = b""  # previous ciphertext block (CBC chaining)
    if mode == "CBC":
        iv = bytes.fromhex(message["iv"])
        if len(iv) != AES_BLOCK_SIZE:
            raise ValueError("CBC IV must be exactly 16 bytes")
        log(f"  IV                  = {hexs(iv)}")
        prev = iv

    out = []
    for n, block in enumerate(blocks, 1):
        log(f"--- block {n}/{len(blocks)}: C{n} = {hexs(block)}")
        dec = aes.decrypt_block(block)
        if mode == "CBC":
            plain = xor_bytes(dec, prev)
            log(f"  CBC: D(C{n}) XOR {'IV' if n == 1 else f'C{n-1}'} = {hexs(plain)}")
            prev = block
        else:
            plain = dec
        log(f"  P{n} = {hexs(plain)}")
        out.append(plain)

    padded = b"".join(out)
    data = pkcs7_unpad(padded, AES_BLOCK_SIZE)
    log(f"  padded plaintext    = {hexs(padded)}")
    log(f"  after PKCS#7 unpad  = {hexs(data)}")
    text = data.decode("ascii")
    log(f"[DECRYPT {mode}] plaintext  = {text!r}")
    return text
