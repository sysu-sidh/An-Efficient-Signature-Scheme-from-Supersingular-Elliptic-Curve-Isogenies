/*
 * gf2.cpp
 *
 *  Created on: 2019年2月14日
 *      Author: lzj
 */

#include "fp2.h"
#include <stdio.h>

int fp2equl(const f2elm_t x, const f2elm_t y)
{
    return fpequl(x[0], y[0]) & fpequl(x[1], y[1]);
}

void fp2contract(const f2elm_t x, f2elm_t w)
{
    felem_contract(w[0], x[0]);
    felem_contract(w[1], x[1]);
}
void fp2printf(const f2elm_t x)
{
    BIGNUM *a0, *a1;
    a0 = BN_new();
    a1 = BN_new();
    f2elm_t w;
    fp2contract(x, w);

    felem_to_BN(a0, w[0]);
    felem_to_BN(a1, w[1]);

    printf("%s \n%s*i \n", BN_bn2hex(a0), BN_bn2hex(a1));
   // printf("%s \n", BN_bn2hex(a0));

    BN_free(a0);
    BN_free(a1);
}

void fp2byfp(const felem a0, const felem a1, f2elm_t c)
{
    fpcopy(a0, c[0]);
    fpcopy(a1, c[1]);
}

void fp2copy(const f2elm_t a, f2elm_t c)
{ // Copy a GF(p^2) element, c = a.
    fpcopy(a[0], c[0]);
    fpcopy(a[1], c[1]);
}

void fp2zero(f2elm_t a)
{ // Zero a GF(p^2) element, a = 0.
    fpzero(a[0]);
    fpzero(a[1]);
}

void fp2one(f2elm_t a)
{ // Zero a GF(p^2) element, a = 1.
    fpone(a[0]);
    fpzero(a[1]);
}

void fp2neg(f2elm_t a)
{ // GF(p^2) negation, a = -a in GF(p^2).
    fpneg(a[0]);
    fpneg(a[1]);
    // fp2contract(a,a);
}

void fp2add(const f2elm_t a, const f2elm_t b, f2elm_t c)
{ // GF(p^2) addition, c = a+b in GF(p^2).

    fpadd(a[0], b[0], c[0]);
    fpadd(a[1], b[1], c[1]);
}

void fp2sub(const f2elm_t a, const f2elm_t b, f2elm_t c)
{ // GF(p^2) subtraction, c = a-b in GF(p^2).
    fpsub(a[0], b[0], c[0]);
    fpsub(a[1], b[1], c[1]);
}

void fp2sqr_mont(const f2elm_t a, f2elm_t c)
{
    // GF(p^2) squaring using Montgomery arithmetic, c = a^2 in GF(p^2).
    // Inputs: a = a0+a1*i, where a0, a1 are in [0, 2*p-1]
    // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]
    felm_t t1, t2, t3;

    fpadd(a[0], a[1], t1);      // t1 = a0+a1
    fpsub(a[0], a[1], t2);      // t2 = a0-a1
    fpadd(a[0], a[0], t3);      // t3 = 2a0
    fpmul_mont(t1, t2, c[0]);   // c0 = (a0+a1)(a0-a1)
    fpmul_mont(t3, a[1], c[1]); // c1 = 2a0*a1
}

void fp2mul_mont(const f2elm_t a, const f2elm_t b, f2elm_t c)
{
    // GF(p^2) multiplication using Montgomery arithmetic, c = a*b in GF(p^2).
    // Inputs: a = a0+a1*i and b = b0+b1*i, where a0, a1, b0, b1 are in [0, 2*p-1]
    // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]
    felm_t t1, t2;
    felm_t tt1, tt2, tt3;
    fpadd(a[0], a[1], t1);       // t1 = a0+a1
    fpadd(b[0], b[1], t2);       // t2 = b0+b1
    fpmul_mont(a[0], b[0], tt1); // tt1 = a0*b0
    fpmul_mont(a[1], b[1], tt2); // tt2 = a1*b1
    fpmul_mont(t1, t2, tt3);     // tt3 = (a0+a1)*(b0+b1)
    fpsub(tt3, tt1, tt3);        // c1 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
    fpsub(tt3, tt2, c[1]);
    fpsub(tt1, tt2, c[0]); // c0 = a0*b0 - a1*b1.
}

void fp2inv_mont(f2elm_t a)
{ // GF(p^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2).
    f2elm_t t1;
    fpsqr_mont(a[0], t1[0]);    // t10 = a0^2
    fpsqr_mont(a[1], t1[1]);    // t11 = a1^2
    fpadd(t1[0], t1[1], t1[0]); // t10 = a0^2+a1^2
    fpinv_mont(t1[0]);          // t10 = (a0^2+a1^2)^-1
    fpneg(a[1]);                // a = a0-i*a1
    fpmul_mont(a[0], t1[0], a[0]);
    fpmul_mont(a[1], t1[0], a[1]); // a = (a0-i*a1)*(a0^2+a1^2)^-1
}

void fp2div2(const f2elm_t a, f2elm_t c)
{ // GF(p^2) division by two, c = a/2  in GF(p^2).
    fpdiv2(a[0], c[0]);
    fpdiv2(a[1], c[1]);
}
