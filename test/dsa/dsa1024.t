TEST dsa1024 pubkey parsing
RUN keyinfo dsa1024.key
---
Version: 4
CreationTime: 1767796315
Algorithm: 17
AlgorithmInfo: 1024
UserID: dsa1024 <dsa1024@pgpr.lib>
KeyFP: 261a5cda960091e4c8873818bc27616c17e01afb
KeyID: bc27616c17e01afb
---
TEST dsa1024 signature parsing
RUN siginfo dsa1024.asc
---
Version: 4
CreationTime: 1767797177
Algorithm: 17
Hash: 2
KeyFP: 261a5cda960091e4c8873818bc27616c17e01afb
KeyID: bc27616c17e01afb
---
TEST dsa1024 signature verification
RUN verifysignature dsa1024.key dsa1024.asc hello
---
signature verified OK
---
TEST dsa1024 signature verification error
RUN verifysignature dsa1024.key dsa1024_bad.asc hello
---
Exit status: 1
signature verification error: Bad signature
---
TEST dsa2_1024 signature parsing
RUN siginfo dsa2_1024.asc
---
Version: 4
CreationTime: 1767800686
Algorithm: 17
Hash: 8
KeyFP: 261a5cda960091e4c8873818bc27616c17e01afb
KeyID: bc27616c17e01afb
---
TEST dsa2_1024 signature verification
RUN verifysignature dsa1024.key dsa2_1024.asc hello
---
signature verified OK
---
