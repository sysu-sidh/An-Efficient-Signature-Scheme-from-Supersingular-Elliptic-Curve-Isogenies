An-Efficient-Signature-Scheme-from-Supersingular-Elliptic-Curve-Isogenies
================================================

This document mainly describes the source code structure of hypersingular elliptic curve homologous signature scheme, including code compilation and

Test run. Among them, Winternitz signature, PORST signature and cache structure refer to the first round of NIST submission.

The implementation of Gravity-SPHINCS [1].

The main contents are as follows:

         1. hash：fpopenssel.c, fp2.c, eci.c, hash.c.
		 
         2. Winternitz signature： wots.c, ltree.c, merkle.c.
		 
         3. PORST signature： pors.c
		 
         4.  Batch signature：batch.c
		 
         5. others:  aes.c, randombytes.c, gravity.c, sign.c .
		 

Compile and run:

$ cd <project path>

$ make clean

$ make

```
cc -pedantic -w -Wextra -Wno-long-long -march=native -O3 -fomit-frame-pointer pors.c eci.c fp2.c wots.c gravity.c sign.c fpopenssl.c batch.c ltree.c api.c main.c hash.c randombytes.c bench2.c aes.c merkle.c bench.c -o bench -lcrypto
./bench
k       24
h       5
d       3
c       0
sk len  144
pk len  288
sig len 118520

# crypto_sign_keypair
6750760062.00 usec

# crypto_sign
38936187961.00 usec

# crypto_sign_open
398182221.00 usec
```


[1]Aumasson, J. P.,  Endignoux,  G.(2017). Design and implementation of a post-quantum hash-based cryptographic signature scheme. NIST Post-Quantum Cryptography, https://csrc.nist.gov/projects/post-quantum-cryptography/round-1-submissions/Gravity-SPHINCS.zip




