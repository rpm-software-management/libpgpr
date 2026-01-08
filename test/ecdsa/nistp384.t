TEST nistp384 pubkey parsing
RUN keyinfo nistp384.key
---
Version: 4
CreationTime: 1767801058
Algorithm: 19
UserID: nistp384 <nistp384@pgpr.lib>
KeyFP: f536b835725986076ad6c8539d6d38f95bc65067
KeyID: 9d6d38f95bc65067
---
TEST nistp384 signature parsing
RUN siginfo nistp384.asc
---
Version: 4
CreationTime: 1767801174
Algorithm: 19
Hash: 9
KeyFP: f536b835725986076ad6c8539d6d38f95bc65067
KeyID: 9d6d38f95bc65067
---
TEST nistp384 signature verification
RUN verifysignature nistp384.key nistp384.asc hello
---
signature verified OK
---
TEST nistp384 signature verification error
RUN verifysignature nistp384.key nistp384_bad.asc hello
---
Exit status: 1
signature verification error
---
