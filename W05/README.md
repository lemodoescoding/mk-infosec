## DES encryption/decryption implemented using C

#### How to compile (for now)

```bash
gcc -Wall -Wextra -Wpedantic -std=c17 \
    main.c constant.c util.c keygen.c des_functions.c \
    -o des
```

> [!IMPORTANT]
> Make sure you have gcc installed
