import unittest

from crypto.aes import AES
from crypto.aes_trace import TracedAES, traced_encrypt_text, traced_decrypt_text
from crypto.modes import cbc_encrypt, ecb_encrypt, decrypt_text

# FIPS-197 Appendix B
KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
PT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
CT = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")


def spaced(h):
    return " ".join(h[i:i + 2] for i in range(0, len(h), 2))


class AesTraceTest(unittest.TestCase):
    def test_block_matches_fips197_and_base_class(self):
        lines = []
        t = TracedAES(KEY, log=lines.append)
        out = t.encrypt_block(PT)
        self.assertEqual(out, CT)
        self.assertEqual(out, AES(KEY).encrypt_block(PT))
        self.assertEqual(t.decrypt_block(CT), PT)

    def test_round1_intermediates_match_fips197(self):
        lines = []
        TracedAES(KEY, log=lines.append).encrypt_block(PT)
        text = "\n".join(lines)
        for expected in (
            "19 3d e3 be a0 f4 e2 2b 9a c6 8d 2a e9 f8 48 08",  # start of round 1
            "d4 27 11 ae e0 bf 98 f1 b8 b4 5d e5 1e 41 52 30",  # SubBytes
            "d4 bf 5d 30 e0 b4 52 ae b8 41 11 f1 1e 27 98 e5",  # ShiftRows
            "04 66 81 e5 e0 cb 19 9a 48 f8 d3 7a 28 06 26 4c",  # MixColumns
            "a4 9c 7f f2 68 9f 35 2b 6b 5b ea 43 02 6a 50 49",  # end of round 1
        ):
            self.assertIn(expected, text)

    def test_modes_match_repo_implementation(self):
        t = TracedAES(KEY, log=lambda *_: None)
        msg = "hello network security, this spans several blocks"
        iv = bytes(range(16))

        cbc = traced_encrypt_text(t, msg, "CBC", iv=iv)
        self.assertEqual(cbc["iv"], iv.hex(), "traced CBC must use the IV passed in")
        _, expected = cbc_encrypt(AES(KEY), msg.encode("ascii"), iv)
        self.assertEqual(cbc["ciphertext"], expected.hex())
        self.assertEqual(traced_decrypt_text(t, cbc), msg)
        self.assertEqual(decrypt_text(KEY, cbc), msg)  # repo can read traced output

        ecb = traced_encrypt_text(t, msg, "ECB")
        self.assertEqual(ecb["ciphertext"], ecb_encrypt(AES(KEY), msg.encode("ascii")).hex())
        self.assertEqual(traced_decrypt_text(t, ecb), msg)


if __name__ == "__main__":
    unittest.main()
