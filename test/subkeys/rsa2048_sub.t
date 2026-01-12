TEST rsa2048_sub pubkey parsing (main key)
RUN keyinfo rsa2048_sub.key
---
Version: 4
CreationTime: 1768212217
Algorithm: 1
AlgorithmInfo: 2048
UserID: rsa2048_sub <rsa2048_sub@pgpr.lib>
KeyFP: a4bae225aba0675d6460b336d115648a561f2303
KeyID: d115648a561f2303
---
TEST rsa2048_sub pubkey parsing (subkey 1)
RUN keyinfo -s 1 rsa2048_sub.key
---
Version: 4
CreationTime: 1768212217
Algorithm: 1
AlgorithmInfo: 2048
UserID: rsa2048_sub <rsa2048_sub@pgpr.lib>
KeyFP: b7693906de576d6983ddcf3f85b2303b12c982d0
KeyID: 85b2303b12c982d0
---
TEST rsa2048_sub pubkey parsing (subkey 2)
RUN keyinfo -s 2 rsa2048_sub.key
---
Version: 4
CreationTime: 1768212270
Algorithm: 1
AlgorithmInfo: 2048
UserID: rsa2048_sub <rsa2048_sub@pgpr.lib>
KeyFP: c104c3ba6c98df5efddaf0c8031dca4afaadf9b6
KeyID: 031dca4afaadf9b6
---
TEST rsa2048_sub signature verification (main key)
RUN verifysignature rsa2048_sub.key rsa2048_sub.asc hello
---
Exit status: 1
signature verification error: Key d115648a561f2303 (rsa2048_sub <rsa2048_sub@pgpr.lib>) is not suitable for signing
---
TEST rsa2048_sub signature verification (subkey 1)
RUN verifysignature -s 1 rsa2048_sub.key rsa2048_sub_1.asc hello
---
Exit status: 1
signature verification error: Subkey 85b2303b12c982d0 of key d115648a561f2303 (rsa2048_sub <rsa2048_sub@pgpr.lib>) is not suitable for signing
---
TEST rsa2048_sub signature verification (subkey 2)
RUN verifysignature -s 2 rsa2048_sub.key rsa2048_sub_2.asc hello
---
signature verified OK
---
