## Tugas 3 Information Security B

| Nama                   | NRP        | Kelas  |
| ---------------------- | ---------- | ------ |
| Ahmad Satrio Arrohman  | 5025241061 | KI - B |
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
- `crypto/`: manual AES block cipher, AES modes, and tracing utilities
- `entities/kdc.py`: KDC process
- `entities/alice.py`: Alice client
- `entities/bob.py`: Bob client
- `docs/`: architecture, protocol, and Wireshark notes
- `scripts/`: shell scripts for running KDC, Bob, and Alice

## Requirements

Python 3.9 or newer; the core implementation uses the Python standard library only.

## Running the demo

Run each command in a separate terminal, from this `W08` directory. Start the
processes in this order:

```bash
bash scripts/run_kdc.sh
```

```bash
bash scripts/run_bob.sh
```

```bash
bash scripts/run_alice.sh
```

Alice and Bob prompt for the AES mode (`ECB` or `CBC`) and key size
(`128`, `192`, or `256` bits); choose the same key size on both.

The scripts use localhost defaults for a same-machine demo. For separate
machines, configure the KDC and Bob host/port environment variables to use
addresses reachable by Alice and update the KDC/Bob bind addresses as needed.
The bundled master keys are demo defaults only; do not use them to protect real
data.
