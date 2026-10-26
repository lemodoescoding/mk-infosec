from crypto.aes import AES

key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

aes = AES(key)

ciphertext = aes.encrypt_block(plaintext)
decrypted = aes.decrypt_block(ciphertext)

print("Round keys:", len(aes.round_keys))
print("Ciphertext:", ciphertext.hex())
print("Decrypted: ", decrypted.hex())

assert len(aes.round_keys) == 11
assert ciphertext == expected
assert decrypted == plaintext

print("All AES-128 block tests passed.")
