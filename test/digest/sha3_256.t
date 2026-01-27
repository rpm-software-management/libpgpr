ALLREQUIRE digest(12)

TEST sha3_256 empty digest
RUN digest 12 empty
---
a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
---
TEST sha3_256 digest of hello
RUN digest 12 hello
---
b314e28493eae9dab57ac4f0c6d887bddbbeb810e900d818395ace558e96516d
---
