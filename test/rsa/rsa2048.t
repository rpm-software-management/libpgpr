TEST rsa2048 pubkey parsing
RUN keyinfo rsa2048.key
---
Version: 4
CreationTime: 1765791915
Algorithm: 1
AlgorithmInfo: 2048
UserID: rsa2048 <rsa2048@pgpr.lib>
KeyFP: 69a80f54946ae787b3fd9f4e8d4f6ec4c9566211
KeyID: 8d4f6ec4c9566211
---
TEST rsa2048 signature parsing
RUN siginfo rsa2048.asc
---
Version: 4
CreationTime: 1765793890
Algorithm: 1
Hash: 8
KeyFP: 69a80f54946ae787b3fd9f4e8d4f6ec4c9566211
KeyID: 8d4f6ec4c9566211
---
TEST rsa2048 signature verification
RUN verifysignature rsa2048.key rsa2048.asc hello
---
signature verified OK
---
TEST rsa2048 signature verification error
RUN verifysignature rsa2048.key rsa2048_bad.asc hello
---
Exit status: 1
signature verification error: Bad signature
---
TEST rsa2048 signature expiration parsing
RUN siginfo rsa2048_expire.asc
---
Version: 4
CreationTime: 1770715992
ExpirationTime: 1802251992
Algorithm: 1
Hash: 8
KeyFP: 69a80f54946ae787b3fd9f4e8d4f6ec4c9566211
KeyID: 8d4f6ec4c9566211
---
