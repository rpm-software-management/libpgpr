TEST rsa2048_v5 pubkey parsing
RUN keyinfo rsa2048_v5.key
---
Version: 5
CreationTime: 1767863567
Algorithm: 1
AlgorithmInfo: 2048
UserID: rsa2048_v5 <rsa2048_v5@pgpr.lib>
KeyFP: a091d587f09734045b6682825743e79154968e5d1633cae0f3999b2e58c8a516
KeyID: a091d587f0973404
---
TEST rsa2048_v5 signature parsing
RUN siginfo rsa2048_v5.asc
---
Version: 5
CreationTime: 1767863675
Algorithm: 1
Hash: 8
KeyFP: a091d587f09734045b6682825743e79154968e5d1633cae0f3999b2e58c8a516
KeyID: a091d587f0973404
---
TEST rsa2048_v5 signature verification
RUN verifysignature rsa2048_v5.key rsa2048_v5.asc hello
---
signature verified OK
---
