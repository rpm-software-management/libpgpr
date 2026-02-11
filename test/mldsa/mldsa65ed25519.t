ALLREQUIRE algo(30)

TEST mldsa65ed25519 pubkey parsing
RUN keyinfo -s 1 mldsa65ed25519.key
---
Version: 6
CreationTime: 1768555184
Algorithm: 30
AlgorithmInfo: 0
UserID: mldsa65ed25519 <mldsa65ed25519@pgpr.lib>
KeyFP: 4047091cff4560969cd3fc36976b937a0e3374335091c2e5bb2f7131fc97ea5c
KeyID: 4047091cff456096
---
TEST mldsa65ed25519 signature parsing
RUN siginfo mldsa65ed25519.asc
---
Version: 6
CreationTime: 1768560776
Algorithm: 30
Hash: 10
KeyFP: 4047091cff4560969cd3fc36976b937a0e3374335091c2e5bb2f7131fc97ea5c
KeyID: 4047091cff456096
---
TEST mldsa65ed25519 signature verification
RUN verifysignature -s 1 mldsa65ed25519.key mldsa65ed25519.asc hello
---
signature verified OK
---
TEST mldsa65ed25519 signature verification failure 1
RUN verifysignature -s 1 mldsa65ed25519.key mldsa65ed25519_bad1.asc hello
---
Exit status: 1
signature verification error: Bad signature
---
TEST mldsa65ed25519 signature verification failure 2
RUN verifysignature -s 1 mldsa65ed25519.key mldsa65ed25519_bad2.asc hello
---
Exit status: 1
signature verification error: Bad signature
---
