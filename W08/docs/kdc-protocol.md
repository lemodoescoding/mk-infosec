# KDC protocol notes

Write down the exact protocol from the lecturer's slides before implementing it.

Record for every step:
1. Sender and receiver
2. Message fields
3. Which key protects each field
4. How the receiver validates/decrypts it
5. Nonce, timestamp, or replay-protection requirements
6. Expected response and failure cases

The KDC protocol is determined to be like below format and sequence
 
(1) A   -> KDC : ID_A || ID_B || N1
(2) KDC -> A   : E(Ka, { Ks, ID_A, ID_B, N1, E(Kb, [Ks || ID_A]) })
(3) A   -> B   : E(Kb, [Ks || ID_A])          (ticket, forwarded by Alice)
 
The ticket is nested inside the payload that only Alice can decrypt, so the
KDC response carries a single protected object ("response").
