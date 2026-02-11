ALLREQUIRE algo(31)

TEST mldsa87ed448 pubkey parsing
RUN keyinfo -s 1 mldsa87ed448.key
---
Version: 6
CreationTime: 1768570793
Algorithm: 31
AlgorithmInfo: 0
UserID: mldsa87ed448 <mldsa87ed448@pgpr.lib>
KeyFP: f3aec6dbd5039dafb4fed14bc76149e599742c1cb2ed570725839c485dc8d0d9
KeyID: f3aec6dbd5039daf
---
TEST mldsa87ed448 signature parsing
RUN siginfo mldsa87ed448.asc
---
Version: 6
CreationTime: 1768570857
Algorithm: 31
Hash: 10
KeyFP: f3aec6dbd5039dafb4fed14bc76149e599742c1cb2ed570725839c485dc8d0d9
KeyID: f3aec6dbd5039daf
---
TEST mldsa87ed448 signature verification
RUN verifysignature -s 1 mldsa87ed448.key mldsa87ed448.asc hello
---
signature verified OK
---
TEST mldsa87ed448 signature verification failure 1
RUN verifysignature -s 1 mldsa87ed448.key mldsa87ed448_bad1.asc hello
---
Exit status: 1
signature verification error: Bad signature
---
TEST mldsa87ed448 signature verification failure 2
RUN verifysignature -s 1 mldsa87ed448.key mldsa87ed448_bad2.asc hello
---
Exit status: 1
signature verification error: Bad signature
---
