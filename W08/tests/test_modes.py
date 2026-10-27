import unittest

from crypto.aes import AES
from crypto.modes import (
    cbc_decrypt,
    cbc_encrypt,
    decrypt_text,
    ecb_decrypt,
    ecb_encrypt,
    encrypt_text,
)

# NIST SP 800-38A (December 2001), Appendix F: "Example Vectors for Modes of Operation of the AES"
# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#   F.1.1 / F.1.3 / F.1.5  ECB-AES128 / AES192 / AES256 .Encrypt
#   F.2.1 / F.2.3 / F.2.5  CBC-AES128 / AES192 / AES256 .Encrypt
# The values below are the ones printed in the document (generated from its text, not typed by hand).
# The decrypt examples (F.1.2, F.1.4, ...) are the same blocks run backwards.
PT_BLOCKS = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
]
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

NIST = {
    128: {
        "key": "2b7e151628aed2a6abf7158809cf4f3c",
        "ecb": [
            "3ad77bb40d7a3660a89ecaf32466ef97",
            "f5d3d58503b9699de785895a96fdbaaf",
            "43b1cd7f598ece23881b00e3ed030688",
            "7b0c785e27e8ad3f8223207104725dd4",
        ],  # F.1.1
        "cbc_input": [
            "6bc0bce12a459991e134741a7f9e1925",
            "d86421fb9f1a1eda505ee1375746972c",
            "604ed7ddf32efdff7020d0238b7c2a5d",
            "8521f2fd3c8eef2cdc3da7e5c44ea206",
        ],  # F.2.1 "Input Block"
        "cbc": [
            "7649abac8119b246cee98e9b12e9197d",
            "5086cb9b507219ee95db113a917678b2",
            "73bed6b8e3c1743b7116e69e22229516",
            "3ff1caa1681fac09120eca307586e1a7",
        ],  # F.2.1
    },
    192: {
        "key": "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "ecb": [
            "bd334f1d6e45f25ff712a214571fa5cc",
            "974104846d0ad3ad7734ecb3ecee4eef",
            "ef7afd2270e2e60adce0ba2face6444e",
            "9a4b41ba738d6c72fb16691603c18e0e",
        ],  # F.1.3
        "cbc_input": [
            "6bc0bce12a459991e134741a7f9e1925",
            "e12f97e55dbfcfa1efcf7796da0fffb9",
            "8411b1ef0e2109e5001cf96f256346b5",
            "a1840065cdb4e1f7d282fbd7db9d35f0",
        ],  # F.2.3 "Input Block"
        "cbc": [
            "4f021db243bc633d7178183a9fa071e8",
            "b4d9ada9ad7dedf4e5e738763f69145a",
            "571b242012fb7ae07fa9baac3df102e0",
            "08b0e27988598881d920a9e64f5615cd",
        ],  # F.2.3
    },
    256: {
        "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "ecb": [
            "f3eed1bdb5d2a03c064b5a7e3db181f8",
            "591ccb10d410ed26dc5ba74a31362870",
            "b6ed21b99ca6f4f9f153e7b1beafed1d",
            "23304b7a39f9f3ff067d8d8f9e24ecc7",
        ],  # F.1.5
        "cbc_input": [
            "6bc0bce12a459991e134741a7f9e1925",
            "5ba1c653c8e65d26e929c4571ad47587",
            "ac3452d0dd87649c8264b662dc7a7e92",
            "cf6d172c769621d8081ba318e24f2371",
        ],  # F.2.5 "Input Block"
        "cbc": [
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
            "9cfc4e967edb808d679f777bc6702c7d",
            "39f23369a9d9bacfa530e26304231461",
            "b2eb05e2c39be9fcda6c19078c6a9d1b",
        ],  # F.2.5
    },
}

PT = bytes.fromhex("".join(PT_BLOCKS))
KEYS = {bits: bytes.fromhex(v["key"]) for bits, v in NIST.items()}

BLOCK = 16


def blocks_of(hex_blocks):
    return [bytes.fromhex(h) for h in hex_blocks]


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class NistKnownAnswerTest(unittest.TestCase):
    """The NIST vectors have no padding, but our modes always apply PKCS#7. So the whole-message
    output is the NIST ciphertext followed by exactly one extra block (the encrypted padding block)."""

    def test_ecb_whole_message(self):
        for bits, key in KEYS.items():
            with self.subTest(bits=bits):
                expected = "".join(NIST[bits]["ecb"])
                ct = ecb_encrypt(AES(key), PT)
                self.assertEqual(len(ct), len(PT) + BLOCK)
                self.assertEqual(ct[:len(PT)].hex(), expected)
                self.assertEqual(ecb_decrypt(AES(key), ct), PT)

    def test_cbc_whole_message(self):
        for bits, key in KEYS.items():
            with self.subTest(bits=bits):
                expected = "".join(NIST[bits]["cbc"])
                iv, ct = cbc_encrypt(AES(key), PT, IV)
                self.assertEqual(iv, IV)
                self.assertEqual(len(ct), len(PT) + BLOCK)
                self.assertEqual(ct[:len(PT)].hex(), expected)
                self.assertEqual(cbc_decrypt(AES(key), IV, ct), PT)

    def test_ecb_block_by_block_encrypt_and_decrypt(self):
        # F.1.x: every plaintext block maps to its own ciphertext block, independently
        for bits, key in KEYS.items():
            aes = AES(key)
            for n, (p, c) in enumerate(zip(blocks_of(PT_BLOCKS), blocks_of(NIST[bits]["ecb"])), 1):
                with self.subTest(bits=bits, block=n):
                    self.assertEqual(aes.encrypt_block(p), c)
                    self.assertEqual(aes.decrypt_block(c), p)

    def test_cbc_chaining_intermediate_values(self):
        # F.2.x: Input Block_j = P_j xor (IV for j=1, else C_(j-1)); C_j = CIPH(Input Block_j).
        # The decrypt examples show the same Input Blocks as the "Output Block" of CIPH^-1(C_j).
        for bits, key in KEYS.items():
            aes = AES(key)
            plain = blocks_of(PT_BLOCKS)
            inputs = blocks_of(NIST[bits]["cbc_input"])
            cipher = blocks_of(NIST[bits]["cbc"])
            previous = IV
            for n in range(4):
                with self.subTest(bits=bits, block=n + 1):
                    self.assertEqual(xor(plain[n], previous), inputs[n])
                    self.assertEqual(aes.encrypt_block(inputs[n]), cipher[n])
                    self.assertEqual(aes.decrypt_block(cipher[n]), inputs[n])
                    self.assertEqual(xor(aes.decrypt_block(cipher[n]), previous), plain[n])
                previous = cipher[n]


class RoundTripTest(unittest.TestCase):
    def test_all_sizes_modes_and_padding_boundaries(self):
        # lengths 0..48 cover every PKCS#7 pad size, including a full extra block at 16/32/48
        for bits, key in KEYS.items():
            aes = AES(key)
            for n in range(0, 49):
                data = bytes(range(n))
                with self.subTest(bits=bits, n=n):
                    ecb = ecb_encrypt(aes, data)
                    self.assertEqual(len(ecb), (n // BLOCK + 1) * BLOCK)
                    self.assertEqual(ecb_decrypt(aes, ecb), data)

                    iv, cbc = cbc_encrypt(aes, data)
                    self.assertEqual(len(cbc), (n // BLOCK + 1) * BLOCK)
                    self.assertEqual(cbc_decrypt(aes, iv, cbc), data)

    def test_encrypt_text_decrypt_text(self):
        for bits, key in KEYS.items():
            for mode in ("ECB", "CBC"):
                for text in ("", "a", "hello world", "x" * 16, "The quick brown fox jumps over the lazy dog"):
                    with self.subTest(bits=bits, mode=mode, text=text):
                        message = encrypt_text(key, text, mode)
                        self.assertEqual(message["mode"], mode)
                        self.assertEqual(decrypt_text(key, message), text)

    def test_mode_name_is_case_insensitive(self):
        key = KEYS[128]
        self.assertEqual(encrypt_text(key, "hi", "cbc")["mode"], "CBC")
        self.assertEqual(encrypt_text(key, "hi", "ecb")["mode"], "ECB")
        message = encrypt_text(key, "hi", "CBC")
        message["mode"] = "cbc"
        self.assertEqual(decrypt_text(key, message), "hi")


class ModeBehaviourTest(unittest.TestCase):
    def setUp(self):
        self.aes = AES(KEYS[128])

    def test_ecb_repeats_identical_blocks_but_cbc_does_not(self):
        data = b"A" * (BLOCK * 3)  # three identical plaintext blocks

        ecb = ecb_encrypt(self.aes, data)
        self.assertEqual(ecb[0:16], ecb[16:32])
        self.assertEqual(ecb[16:32], ecb[32:48])

        _, cbc = cbc_encrypt(self.aes, data, IV)
        blocks = {cbc[i:i + BLOCK] for i in range(0, len(cbc), BLOCK)}
        self.assertEqual(len(blocks), len(cbc) // BLOCK)  # all distinct

    def test_ecb_is_deterministic(self):
        self.assertEqual(ecb_encrypt(self.aes, b"same"), ecb_encrypt(self.aes, b"same"))

    def test_cbc_random_iv_by_default(self):
        iv1, ct1 = cbc_encrypt(self.aes, b"same")
        iv2, ct2 = cbc_encrypt(self.aes, b"same")
        self.assertEqual(len(iv1), BLOCK)
        self.assertNotEqual(iv1, iv2)
        self.assertNotEqual(ct1, ct2)

    def test_cbc_uses_the_iv_it_is_given(self):
        other_iv = bytes(range(16, 32))
        iv_a, ct_a = cbc_encrypt(self.aes, PT, IV)
        iv_b, ct_b = cbc_encrypt(self.aes, PT, other_iv)
        self.assertEqual((iv_a, iv_b), (IV, other_iv))
        self.assertNotEqual(ct_a, ct_b)

    def test_cbc_chaining_each_block_depends_on_previous(self):
        # C_i = E(P_i xor C_(i-1)): changing only the first plaintext block changes every later block
        a = bytearray(PT)
        b = bytearray(PT)
        b[0] ^= 0x01
        _, ct_a = cbc_encrypt(self.aes, bytes(a), IV)
        _, ct_b = cbc_encrypt(self.aes, bytes(b), IV)
        for i in range(0, len(PT), BLOCK):
            self.assertNotEqual(ct_a[i:i + BLOCK], ct_b[i:i + BLOCK])

    def test_ecb_blocks_are_independent(self):
        # the same change only affects its own block in ECB
        b = bytearray(PT)
        b[0] ^= 0x01
        ct_a = ecb_encrypt(self.aes, PT)
        ct_b = ecb_encrypt(self.aes, bytes(b))
        self.assertNotEqual(ct_a[:16], ct_b[:16])
        self.assertEqual(ct_a[16:], ct_b[16:])

    def test_cbc_bit_flip_garbles_its_block_and_flips_the_same_bit_in_the_next(self):
        iv, ct = cbc_encrypt(self.aes, PT, IV)
        tampered = bytearray(ct)
        tampered[0] ^= 0x80                      # flip one bit in ciphertext block 0
        plain = cbc_decrypt(self.aes, iv, bytes(tampered))

        self.assertNotEqual(plain[0:16], PT[0:16])           # block 0 is garbage
        self.assertEqual(plain[16] ^ PT[16], 0x80)           # block 1: exactly that bit flipped
        self.assertEqual(plain[17:], PT[17:])                # everything else untouched

    def test_encrypt_text_message_format(self):
        ecb = encrypt_text(KEYS[128], "hello", "ECB")
        self.assertIsNone(ecb["iv"])
        self.assertEqual(set(ecb), {"mode", "iv", "ciphertext"})
        bytes.fromhex(ecb["ciphertext"])

        cbc = encrypt_text(KEYS[128], "hello", "CBC")
        self.assertEqual(len(bytes.fromhex(cbc["iv"])), BLOCK)
        self.assertEqual(len(bytes.fromhex(cbc["ciphertext"])) % BLOCK, 0)


class InvalidInputTest(unittest.TestCase):
    def setUp(self):
        self.aes = AES(KEYS[128])

    def test_cbc_rejects_bad_iv_length(self):
        for bad in (b"", b"x" * 15, b"x" * 17):
            with self.subTest(len=len(bad)):
                with self.assertRaises(ValueError):
                    cbc_encrypt(self.aes, b"data", bad)
                with self.assertRaises(ValueError):
                    cbc_decrypt(self.aes, bad, b"x" * 16)

    def test_rejects_ciphertext_that_is_empty_or_not_block_aligned(self):
        for bad in (b"", b"x" * 15, b"x" * 17, b"x" * 31):
            with self.subTest(len=len(bad)):
                with self.assertRaises(ValueError):
                    ecb_decrypt(self.aes, bad)
                with self.assertRaises(ValueError):
                    cbc_decrypt(self.aes, IV, bad)

    def test_invalid_padding_is_rejected(self):
        # a block of zeros is not valid PKCS#7 padding
        bad_block = self.aes.encrypt_block(bytes(16))
        with self.assertRaises(ValueError):
            ecb_decrypt(self.aes, bad_block)

    def test_wrong_key_fails_to_decrypt(self):
        message = encrypt_text(KEYS[128], "attack at dawn", "ECB")
        with self.assertRaises(ValueError):
            decrypt_text(bytes(16), message)

    def test_unsupported_mode(self):
        with self.assertRaises(ValueError):
            encrypt_text(KEYS[128], "hi", "CTR")
        message = encrypt_text(KEYS[128], "hi", "ECB")
        message["mode"] = "CTR"
        with self.assertRaises(ValueError):
            decrypt_text(KEYS[128], message)

    def test_non_ascii_plaintext_is_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_text(KEYS[128], "h\u00e9llo", "CBC")

    def test_invalid_key_sizes_are_rejected(self):
        for bad in (b"", b"x" * 15, b"x" * 20, b"x" * 33):
            with self.subTest(len=len(bad)):
                with self.assertRaises(ValueError):
                    encrypt_text(bad, "hi", "CBC")


if __name__ == "__main__":
    unittest.main()
