/*
 * gf2.h
 *
 *  Created on: 2019年2月14日
 *      Author: lzj
 */

#ifndef FP2_H_
#define FP2_H_

#include "fpopenssl.h"
typedef felem f2elm_t[2];
typedef felem felm_t;


void fp2contract(const f2elm_t x,f2elm_t w);

// Copy of a GF element, c = a
void fp2copy(const f2elm_t a, f2elm_t c);

//a = 1
void fp2one(f2elm_t a);

// Zeroing a GF element, a = 0
void fp2zero(f2elm_t a);

// GF negation, a = -a in GF
void fp2neg(f2elm_t a);

// GF addition, c = a+b in GF
void fp2add(const f2elm_t a, const f2elm_t b, f2elm_t c);

// GF subtraction, c = a-b in GF
void fp2sub(const f2elm_t a, const f2elm_t b, f2elm_t c);

// GF squaring using Montgomery arithmetic, c = a^2 in GF
void fp2sqr_mont(const f2elm_t a, f2elm_t c);

// GF multiplication using Montgomery arithmetic, c = a*b in GF
void fp2mul_mont(const f2elm_t a, const f2elm_t b, f2elm_t c);

// GF inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
void fp2inv_mont(f2elm_t a);

void fp2div2(const f2elm_t a, f2elm_t c);

void fp2byfp(const felem a0,const felem a1,f2elm_t c);

void fp2printf(const f2elm_t x);


int fp2equl(const f2elm_t x,const f2elm_t y);

#endif /* FP2_H_ */
