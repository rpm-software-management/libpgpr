TEST key parsing
RUN keyinfo rsa2048.key
---
Version: 4
CreationTime: 1765791915
ExpirationTime: 1801048746
Algorithm: 1
AlgorithmInfo: 2048
UserID: rsa2048 <rsa2048@pgpr.lib>
KeyFP: 69a80f54946ae787b3fd9f4e8d4f6ec4c9566211
KeyID: 8d4f6ec4c9566211
---
TEST signature with expiration parsing
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
TEST signature from future parsing
RUN siginfo rsa2048_future.asc
---
Version: 4
CreationTime: 1801048802
Algorithm: 1
Hash: 8
KeyFP: 69a80f54946ae787b3fd9f4e8d4f6ec4c9566211
KeyID: 8d4f6ec4c9566211
---
TEST signature from past parsing
RUN siginfo rsa2048_past.asc
---
Version: 4
CreationTime: 1765791902
Algorithm: 1
Hash: 8
KeyFP: 69a80f54946ae787b3fd9f4e8d4f6ec4c9566211
KeyID: 8d4f6ec4c9566211
---
TEST signature verification (sig not expired)
FIXEDTIME 1770808504
RUN verifysignature rsa2048.key rsa2048_expire.asc hello
---
signature verified OK
---
TEST signature verification (sig expired)
FIXEDTIME 1870808504
RUN verifysignature rsa2048.key rsa2048_expire.asc hello
---
Exit status: 1
signature verification error: Signature expired on 2027-02-10 09:33:12
---
TEST signature verification (sig from future)
FIXEDTIME 1670808504
RUN verifysignature rsa2048.key rsa2048_expire.asc hello
---
Exit status: 1
signature verification error: Signature was created in the future
---
TEST signature verification (expired key, sig ok)
FIXEDTIME 1801048800
RUN verifysignature rsa2048.key rsa2048_expire.asc hello
---
signature verified OK
---
TEST signature verification (expired key, sig expired)
FIXEDTIME 1801048810
RUN verifysignature rsa2048.key rsa2048_future.asc hello
---
Exit status: 1
signature verification error: Key 8d4f6ec4c9566211 (rsa2048 <rsa2048@pgpr.lib>) expired on 2027-01-27 11:19:06
---
TEST signature verification (sig created before key)
RUN verifysignature rsa2048.key rsa2048_past.asc hello
---
Exit status: 1
signature verification error: Key 8d4f6ec4c9566211 (rsa2048 <rsa2048@pgpr.lib>) has been created after the signature
---
