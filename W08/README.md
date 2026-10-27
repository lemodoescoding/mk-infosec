## Tugas 3 Information Security B

| Nama | NRP | Kelas |
| --------------- | --------------- | --------------- |
| Ahmad Satrio Arrohman | 5025241061 | KI - B |
| Danish Faiq Ibad Yuadi | 5025241038 | KI - B |

Educational project implementing AES manually and using a Key Distribution Center (KDC)
to establish a shared session key between Alice and Bob.

> This repository is a learning scaffold, not production-ready cryptography. Do not use it
> to protect real data. Implement and validate the protocol required by your lecturer.

## Project structure

- `config/constants.py`: fixed AES constants
- `config/settings.py`: network and runtime configuration
- `common/utils.py`: reusable byte, padding, and validation helpers
- `common/protocol.py`: message type names and message constructors
- `common/network.py`: TCP framing helpers
- `crypto/aes.py`: manual AES block cipher implementation
- `entities/kdc.py`: KDC process
- `entities/alice.py`: Alice client
- `entities/bob.py`: Bob client
- `docs/`: architecture, protocol, and Wireshark notes

## Requirements

Python 3.10+; the core scaffold uses the Python standard library only.

## Before running

1. Implement AES in `crypto/aes.py` and fill in the tables in `config/constants.py`.
2. Verify AES against published known-answer test vectors.
3. Implement the exact KDC protocol specified by your lecturer.
4. Configure the IP addresses and routes in `config/settings.py`.
5. Do not commit real pre-shared keys or other secrets.
6. Run each entity in its own VM/process after its implementation is complete.

The current files intentionally contain placeholders and are not yet a functioning system.
