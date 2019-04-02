#include "api.h"
#include "sign.h"

int sig_keygen(unsigned char *pk, unsigned char *sk)
{
    return crypto_sign_keypair(pk, sk);
}


int sig_sign(unsigned char *sk,
             unsigned char *m, unsigned long long mlen,
             unsigned char *sm, unsigned long long *smlen)
{
    return crypto_sign(sm, smlen, m, mlen, sk);
}



int sig_verf(unsigned char *pk,
             unsigned char *sm, unsigned long long smlen,
             unsigned char *m, unsigned long long mlen)
{
    return crypto_sign_open(m, &mlen, sm, smlen, pk);
}
