/*
 * Copyright (C) 2017 Nagravision S.A.
 */
#include "hash.h"

#include "eci.h"
#include <openssl/sha.h>

void hash_N_to_N(struct hash *dst, const struct hash *src)
{
    iso_hash_N_2_N(src->h, dst->h);
}

void hash_N_to_N_chain(struct hash *dst, const struct hash *src, int chainlen)
{
    iso_hash(src->h, dst->h, chainlen);
}

void hash_2N_to_N(struct hash *dst, const struct hash *src0, const struct hash *src1)
{
    f2elm_t a;
    iso_hash_N_2_N(src0->h, a);
    iso_hash_N_2_N_E(a, src1->h, dst->h);
}

void hash_to_N(struct hash *dst, const uint8_t *src, uint64_t srclen)
{
    u8 re[66]={0};
    SHA256(src, srclen, re);
    bin66_to_felem(dst->h[0],re);
}

void hash_compress_pairs(struct hash *dst, const struct hash *src, int count)
{
    int i = 0;
    for (; i < count; ++i)
        hash_2N_to_N(&dst[i], &src[2*i],&src[2*i+1]);
}

void hash_compress_all(struct hash *dst, const struct hash *src, int count)
{
    /* Fast implementation with a single call to a large input hash function */
    hash_to_N(dst, src->h, count * HASH_SIZE);
    /* TODO: implement a real L-tree with 2N->N compression function */
}

void hash_parallel(struct hash *dst, const struct hash *src, int count)
{
    int i = 0;
    for (; i < count; ++i)
        hash_N_to_N(&dst[i], &src[i]);
}

//
void hash_parallel_chains(struct hash *dst, const struct hash *src, int count, int chainlen)
{
    int i = 0;
    for (; i < count; ++i)
    {
        hash_N_to_N_chain(&dst[i], &src[i], chainlen);
    }
}
