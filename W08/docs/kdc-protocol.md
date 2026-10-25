# KDC protocol notes

Write down the exact protocol from the lecturer's slides before implementing it.

Record for every step:
1. Sender and receiver
2. Message fields
3. Which key protects each field
4. How the receiver validates/decrypts it
5. Nonce, timestamp, or replay-protection requirements
6. Expected response and failure cases

Do not assume a generic KDC flow is identical to the course protocol. Avoid logging session keys,
master keys, or decrypted secret payloads.
