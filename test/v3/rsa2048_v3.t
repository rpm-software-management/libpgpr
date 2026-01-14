TEST rsa2048_v3 signature parsing
RUN siginfo rsa2048_v3.asc
---
Version: 3
CreationTime: 1768400780
Algorithm: 1
Hash: 8
KeyID: 8d4f6ec4c9566211
---
TEST rsa2048_v3 signature verification
RUN verifysignature rsa2048.key rsa2048_v3.asc hello
---
signature verified OK
