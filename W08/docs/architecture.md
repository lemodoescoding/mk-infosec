# Architecture

## Components

- **KDC**: establishes/distributes a session key according to the assigned protocol.
- **Alice**: requests a session and initiates messages.
- **Bob**: validates session setup and replies.
- **AES**: manually implemented block cipher.
- **Mode layer**: should handle CBC/IV/padding separately from AES block operations.
- **Common modules**: message framing, serialization, validation, and byte helpers.

## Network example

| Entity | Example IP | Example TCP port |
|---|---|---:|
| KDC | 192.168.10.10 | 5000 |
| Alice | 192.168.10.11 | 5001 |
| Bob | 192.168.10.12 | 5002 |

These are examples only; adapt them to the GNS3 topology.
