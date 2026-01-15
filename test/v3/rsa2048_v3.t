TEST rsa2048_v3 pubkey parsing
RUN certinfo rsa2048_v3.key
---
KeyFP: ddc44f08f8a2e17ca7496e515d1fd7a3
KeyID: cc9b6466ae90bb19
CertLen: 586
---
TEST rsa2048_v3 signature parsing
RUN siginfo rsa2048_v3.asc
---
Version: 3
CreationTime: 1768482059
Algorithm: 1
Hash: 8
KeyID: cc9b6466ae90bb19
---
TEST rsa2048_v3 signature verification error
RUN verifysignature rsa2048_v3.key rsa2048_v3.asc hello
---
Exit status: 1
pubkey parse error: Unsupported pubkey version (V3)
