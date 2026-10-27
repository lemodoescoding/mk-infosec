import json
import unittest

from common.protocol import KEY_REQUEST, KEY_RESPONSE
from crypto.modes import decrypt_text
from entities import kdc

KA = b"alice-master-key"
KB = b"bob---master-key"
KEYS = {"Alice": KA, "Bob": KB}


def req(**over):
    base = {"type": KEY_REQUEST, "requester": "Alice", "target": "Bob", "nonce": "abc123"}
    base.update(over)
    return base


class KDCProtocolTest(unittest.TestCase):
    def setUp(self):
        kdc._seen_nonces.clear()

    def test_alice_opens_response_and_bob_opens_ticket(self):
        for mode in ("CBC", "ECB"):
            kdc._seen_nonces.clear()
            resp = kdc.build_key_response(req(), KEYS, mode)
            self.assertEqual(resp["type"], KEY_RESPONSE)
            self.assertEqual(set(resp) - {"type"}, {"response"})

            inner = json.loads(decrypt_text(KA, resp["response"]))
            self.assertEqual(inner["requester"], "Alice")
            self.assertEqual(inner["target"], "Bob")
            self.assertEqual(inner["nonce"], "abc123")
            self.assertEqual(len(bytes.fromhex(inner["session_key"])), 16)

            ks, ida = decrypt_text(KB, inner["ticket"]).split(kdc.SEPARATOR)
            self.assertEqual(ks, inner["session_key"])
            self.assertEqual(ida, "Alice")

    def test_session_keys_are_fresh(self):
        a = kdc.build_key_response(req(nonce="n1"), KEYS)
        b = kdc.build_key_response(req(nonce="n2"), KEYS)
        ka = json.loads(decrypt_text(KA, a["response"]))["session_key"]
        kb = json.loads(decrypt_text(KA, b["response"]))["session_key"]
        self.assertNotEqual(ka, kb)

    def test_response_never_contains_master_keys(self):
        wire = json.dumps(kdc.build_key_response(req(), KEYS))
        for key in (KA, KB):
            self.assertNotIn(key.decode(), wire)
            self.assertNotIn(key.hex(), wire)

    def test_rejects_bad_requests(self):
        for bad in (
            req(requester="Mallory"),
            req(target="Mallory"),
            req(target="Alice"),
            req(nonce=""),
            req(nonce="a||b"),
            req(nonce="x" * 65),
            req(nonce=123),
            req(requester=None),
            req(requester=""),
            "not a dict",
        ):
            with self.assertRaises(kdc.KDCError, msg=repr(bad)):
                kdc.build_key_response(bad, KEYS)

    def test_error_text_has_no_internal_prefix(self):
        with self.assertRaises(kdc.KDCError) as ctx:
            kdc.build_key_response(req(requester="Mallory"), KEYS)
        self.assertNotIn("[KDC]", str(ctx.exception))

    def test_rejects_replayed_nonce(self):
        kdc.build_key_response(req(), KEYS)
        with self.assertRaises(kdc.KDCError):
            kdc.build_key_response(req(), KEYS)

    def test_cache_full_evicts_oldest_only(self):
        old_limit = kdc.MAX_SEEN_NONCES
        kdc.MAX_SEEN_NONCES = 3
        try:
            for n in ("a1", "a2", "a3", "a4"):       # a4 evicts a1 only
                kdc.build_key_response(req(nonce=n), KEYS)
            for n in ("a2", "a3", "a4"):             # still remembered
                with self.assertRaises(kdc.KDCError, msg=n):
                    kdc.build_key_response(req(nonce=n), KEYS)
        finally:
            kdc.MAX_SEEN_NONCES = old_limit


if __name__ == "__main__":
    unittest.main()
