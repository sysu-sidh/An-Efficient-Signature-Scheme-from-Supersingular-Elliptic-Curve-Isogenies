#ifndef FP_OPENSSL_H_
#define FP_OPENSSL_H_

#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <openssl/bn.h>

#if defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
/* even with gcc, the typedef won't work for 32-bit platforms */
typedef __uint128_t uint128_t; /* nonstandard; implemented by gcc on 64-bit platforms */
#else
#error "Need GCC 3.1 or later to define type uint128_t"
#endif

typedef uint8_t u8;
typedef uint64_t u64;
typedef int64_t s64;

/* The underlying field.
 *
 * P521 operates over GF(2^521-1). We can serialise an element of this field
 * into 66 bytes where the most significant byte contains only a single bit. We
 * call this an felem_bytearray. */

typedef u8 felem_bytearray[66];

/* The representation of field elements.
 * ------------------------------------
 *
 * We represent field elements with nine values. These values are either 64 or
 * 128 bits and the field element represented is:
 *   v[0]*2^0 + v[1]*2^58 + v[2]*2^116 + ... + v[8]*2^464  (mod p)
 * Each of the nine values is called a 'limb'. Since the limbs are spaced only
 * 58 bits apart, but are greater than 58 bits in length, the most significant
 * bits of each limb overlap with the least significant bits of the next.
 *
 * A field element with 64-bit limbs is an 'felem'. One with 128-bit limbs is a
 * 'largefelem' */

#define NLIMBS 9

typedef uint64_t limb;
typedef limb felem[NLIMBS];
typedef uint128_t largefelem[NLIMBS];

static const limb bottom57bits = 0x1ffffffffffffff;
static const limb bottom58bits = 0x3ffffffffffffff;

int BN_to_felem(felem out, const BIGNUM *bn);
BIGNUM *felem_to_BN(BIGNUM *out, const felem in);
void felem_sum64(felem out, const felem in);
void felem_neg(felem out, const felem in);
void felem_diff64(felem out, const felem in);
void felem_diff_128_64(largefelem out, const felem in);
void felem_diff128(largefelem out, const largefelem in);
void felem_reduce(felem out, const largefelem in);
void felem_square_reduce(felem out, const felem in);
void felem_mul_reduce(felem out, const felem in1, const felem in2);
void felem_inv(felem out, const felem in);
int felem_is_zero_int(const felem in);
void felem_contract(felem out, const felem in);
void felem_scalar128(largefelem out, limb scalar);
void felem_scalar64(felem out, limb scalar);
void felem_to_bin66(u8 out[66], const felem in);
void bin66_to_felem(felem out, const u8 in[66]);

int fplastbit(const felem x);
void fpadd(const felem x, const felem y, felem w);
void fpsub(const felem x, const felem y, felem w);
void fpcopy(const felem x,  felem w);
void fpcorrection(felem w,const largefelem in);
void fpsqr_mont(const felem x, felem w);
void fpmul_mont(const felem x, const felem y, felem w);
void fpinv_mont(felem x);
void fpzero(felem x);
void fpone(felem x); 
void fpneg(felem x);
void fpdiv2(const felem x,felem w);

int fpequl(const felem x,const felem y );



#endif