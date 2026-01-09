TEST ed448_v5 pubkey parsing
RUN keyinfo ed448_v5.key
---
Version: 5
CreationTime: 1767950480
Algorithm: 22
AlgorithmInfo: 11
UserID: ed448_v5 <ed448_v5@pgpr.lib>
KeyFP: cfe61908887da5dc6fbdc5220f888b17e022b6da34e407b17cb208d24b3ba206
KeyID: cfe61908887da5dc
---
TEST ed448_v5 signature parsing
RUN siginfo ed448_v5.asc
---
Version: 5
CreationTime: 1767957797
Algorithm: 22
Hash: 10
KeyFP: cfe61908887da5dc6fbdc5220f888b17e022b6da34e407b17cb208d24b3ba206
KeyID: cfe61908887da5dc
---
TEST ed448_v5 signature verification
RUN verifysignature ed448_v5.key ed448_v5.asc hello
---
signature verified OK
---
