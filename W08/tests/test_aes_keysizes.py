import json
import unittest

from common.utils import key_from_ascii
from crypto.aes import AES
from crypto.aes_trace import TracedAES
from crypto.modes import decrypt_text, encrypt_text
from entities import kdc

PT = bytes.fromhex("00112233445566778899aabbccddeeff")

# FIPS-197 Appendix C: key, ciphertext, Nr
VECTORS = {
    16: ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a", 10),
    24: ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191", 12),
    32: ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089", 14),
}


def words(aes: AES) -> list[str]:
    raw = b"".join(aes.round_keys)
    return [raw[i:i + 4].hex() for i in range(0, len(raw), 4)]


class AesKeySizeTest(unittest.TestCase):
    def test_fips197_appendix_c(self):
        for size, (key, ct, nr) in VECTORS.items():
            with self.subTest(bits=size * 8):
                aes = AES(bytes.fromhex(key))
                self.assertEqual(aes.nr, nr)
                self.assertEqual(len(aes.round_keys), nr + 1)
                self.assertEqual(aes.encrypt_block(PT), bytes.fromhex(ct))
                self.assertEqual(aes.decrypt_block(bytes.fromhex(ct)), PT)

    def test_key_expansion_fips197_appendix_a(self):
        w192 = words(AES(bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")))
        self.assertEqual(w192[6:8], ["fe0c91f7", "2402f5a5"])
        w256 = words(AES(bytes.fromhex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")))
        self.assertEqual(w256[8:10], ["9ba35411", "8e6925af"])
        self.assertEqual(w256[12], "a8b09c1a")  # needs the AES-256-only SubWord step

    def test_roundtrip_all_sizes_and_modes(self):
        for size in (16, 24, 32):
            key = bytes(range(size))
            for mode in ("ECB", "CBC"):
                for n in (0, 1, 15, 16, 17, 100):
                    msg = "x" * n
                    with self.subTest(bits=size * 8, mode=mode, n=n):
                        self.assertEqual(decrypt_text(key, encrypt_text(key, msg, mode)), msg)

    def test_different_key_sizes_give_different_ciphertext(self):
        out = {AES(bytes.fromhex(k)).encrypt_block(PT) for k, _, _ in VECTORS.values()}
        self.assertEqual(len(out), 3)

    def test_rejects_invalid_key_sizes(self):
        for bad in (b"", b"x" * 8, b"x" * 15, b"x" * 17, b"x" * 20, b"x" * 33, "x" * 16, None):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(ValueError):
                    AES(bad)  # type: ignore[arg-type]

    def test_key_from_ascii_accepts_16_24_32_only(self):
        for n in (16, 24, 32):
            self.assertEqual(len(key_from_ascii("k" * n)), n)
        for n in (0, 15, 17, 31, 33):
            with self.assertRaises(ValueError):
                key_from_ascii("k" * n)

    def test_traced_aes_matches_for_all_sizes(self):
        for size, (key, ct, _) in VECTORS.items():
            with self.subTest(bits=size * 8):
                traced = TracedAES(bytes.fromhex(key), log=lambda *_: None)
                self.assertEqual(traced.encrypt_block(PT), bytes.fromhex(ct))
                self.assertEqual(traced.decrypt_block(bytes.fromhex(ct)), PT)


class KDCKeySizeTest(unittest.TestCase):
    def setUp(self):
        kdc._seen_nonces.clear()
        self._old = kdc.SESSION_KEY_SIZE

    def tearDown(self):
        kdc.SESSION_KEY_SIZE = self._old

    def test_mixed_master_key_sizes_and_256_bit_session_key(self):
        keys = {"Alice": b"A" * 24, "Bob": b"B" * 32}   # AES-192 and AES-256 master keys
        for ks_size in (16, 24, 32):
            kdc._seen_nonces.clear()
            kdc.SESSION_KEY_SIZE = ks_size
            resp = kdc.build_key_response(
                {"requester": "Alice", "target": "Bob", "nonce": "n1"}, keys)
            inner = json.loads(decrypt_text(keys["Alice"], resp["response"]))
            self.assertEqual(len(bytes.fromhex(inner["session_key"])), ks_size)
            ks, ida = decrypt_text(keys["Bob"], inner["ticket"]).split(kdc.SEPARATOR)
            self.assertEqual((ks, ida), (inner["session_key"], "Alice"))
            # the session key is itself usable as an AES key of that size
            session = bytes.fromhex(ks)
            self.assertEqual(decrypt_text(session, encrypt_text(session, "hello")), "hello")


if __name__ == "__main__":
    unittest.main()
