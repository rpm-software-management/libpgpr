TEST ed25519 pubkey parsing
RUN keyinfo ed25519.key
---
Version: 4
CreationTime: 1767801366
Algorithm: 22
AlgorithmInfo: 6
UserID: ed25519 <ed25519@pgpr.lib>
KeyFP: 844901a5768d219988920a2baa242b58f33d6457
KeyID: aa242b58f33d6457
---
TEST ed25519 signature parsing
RUN siginfo ed25519.asc
---
Version: 4
CreationTime: 1767801453
Algorithm: 22
Hash: 10
KeyFP: 844901a5768d219988920a2baa242b58f33d6457
KeyID: aa242b58f33d6457
---
TEST ed25519 signature verification
RUN verifysignature ed25519.key ed25519.asc hello
---
signature verified OK
---
TEST ed25519 signature verification error
RUN verifysignature ed25519.key ed25519_bad.asc hello
---
Exit status: 1
signature verification error
---
