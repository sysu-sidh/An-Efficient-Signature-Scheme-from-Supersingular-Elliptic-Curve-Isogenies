#pragma once

#ifndef SIG_BYTES

/* setting SIG_BYTES to the static structure size, for simplicity,
   as opposed to the actual message-dependent signature size */

#define SIG_ALGNAME "Gravity-SPHINCS"
#define SIG_SECRETKEYBYTES 144
#define SIG_PUBLICKEYBYTES 288
#define SIG_BYTES 118530

#endif


int sig_keygen(unsigned char *pk, unsigned char *sk);
int sig_sign(unsigned char *sk,
             unsigned char *m, unsigned long long mlen,
             unsigned char *sm, unsigned long long *smlen);
int sig_verf(unsigned char *pk,
             unsigned char *sm, unsigned long long smlen,
             unsigned char *m, unsigned long long mlen);
