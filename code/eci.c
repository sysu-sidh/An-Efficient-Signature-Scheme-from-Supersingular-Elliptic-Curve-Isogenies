#include "eci.h"

void point_by_fp2(point_proj_t P, const f2elm_t x, const f2elm_t z)
{
    fp2copy(x, P->X);
    fp2copy(z, P->Z);
}

void xDBLADD(point_proj_t P, point_proj_t Q, const f2elm_t xPQ,
             const f2elm_t A24)
{
    // Simultaneous doubling and differential addition.
    // Input: projective Montgomery points P=(XP:ZP) and Q=(XQ:ZQ) such that xP=XP/ZP and xQ=XQ/ZQ, affine difference xPQ=x(P-Q) and Montgomery curve constant A24=(A+2)/4.
    // Output: projective Montgomery points P <- 2*P = (X2P:Z2P) such that x(2P)=X2P/Z2P, and Q <- P+Q = (XQP:ZQP) such that = x(Q+P)=XQP/ZQP.
    f2elm_t t0, t1, t2;

    fp2add(P->X, P->Z, t0);        // t0 = XP+ZP
    fp2sub(P->X, P->Z, t1);        // t1 = XP-ZP
    fp2sqr_mont(t0, P->X);         // XP = (XP+ZP)^2
    fp2sub(Q->X, Q->Z, t2);        // t2 = XQ-ZQ
    fp2add(Q->X, Q->Z, Q->X);      // XQ = XQ+ZQ
    fp2mul_mont(t0, t2, t0);       // t0 = (XP+ZP)*(XQ-ZQ)
    fp2sqr_mont(t1, P->Z);         // ZP = (XP-ZP)^2
    fp2mul_mont(t1, Q->X, t1);     // t1 = (XP-ZP)*(XQ+ZQ)
    fp2sub(P->X, P->Z, t2);        // t2 = (XP+ZP)^2-(XP-ZP)^2
    fp2mul_mont(P->X, P->Z, P->X); // XP = (XP+ZP)^2*(XP-ZP)^2
    fp2mul_mont(t2, A24, Q->X);    // XQ = A24*[(XP+ZP)^2-(XP-ZP)^2]
    fp2sub(t0, t1, Q->Z);          // ZQ = (XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)
    fp2add(Q->X, P->Z, P->Z);      // ZP = A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2
    fp2add(t0, t1, Q->X);          // XQ = (XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)
    fp2mul_mont(P->Z, t2, P->Z);   // ZP = [A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2]*[(XP+ZP)^2-(XP-ZP)^2]
    fp2sqr_mont(Q->Z, Q->Z);       // ZQ = [(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
    fp2sqr_mont(Q->X, Q->X);       // XQ = [(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2
    fp2mul_mont(Q->Z, xPQ, Q->Z);  // ZQ = xPQ*[(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
}

void xDBL(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus,
          const f2elm_t C24)
{ // Doubling of a Montgomery point in projective coordinates (X:Z).
    // Input: projective Montgomery x-coordinates P = (X1:Z1), where x1=X1/Z1 and Montgomery curve constants A+2C and 4C.
    // Output: projective Montgomery x-coordinates Q = 2*P = (X2:Z2).
    f2elm_t t0, t1;

    fp2sub(P->X, P->Z, t0);       // t0 = X1-Z1
    fp2add(P->X, P->Z, t1);       // t1 = X1+Z1
    fp2sqr_mont(t0, t0);          // t0 = (X1-Z1)^2
    fp2sqr_mont(t1, t1);          // t1 = (X1+Z1)^2
    fp2mul_mont(C24, t0, Q->Z);   // Z2 = C24*(X1-Z1)^2
    fp2mul_mont(t1, Q->Z, Q->X);  // X2 = C24*(X1-Z1)^2*(X1+Z1)^2
    fp2sub(t1, t0, t1);           // t1 = (X1+Z1)^2-(X1-Z1)^2
    fp2mul_mont(A24plus, t1, t0); // t0 = A24plus*[(X1+Z1)^2-(X1-Z1)^2]
    fp2add(Q->Z, t0, Q->Z);       // Z2 = A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2
    fp2mul_mont(Q->Z, t1, Q->Z);  // Z2 = [A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2]*[(X1+Z1)^2-(X1-Z1)^2]
}

void xDBLe(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus,
           const f2elm_t C24, const int e)
{ // Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
    // Input: projective Montgomery x-coordinates P = (XP:ZP), such that xP=XP/ZP and Montgomery curve constants A+2C and 4C.
    // Output: projective Montgomery x-coordinates Q <- (2^e)*P.
    int i;
    fp2copy(P->X, Q->X);
    fp2copy(P->Z, Q->Z);

    for (i = 0; i < e; i++)
    {
        xDBL(Q, Q, A24plus, C24);
    }
}

void xADD(point_proj_t P, const point_proj_t Q, f2elm_t const xPQ)
{
    // Differential addition.
    // Input: projective Montgomery points P=(XP:ZP) and Q=(XQ:ZQ) such that xP=XP/ZP and xQ=XQ/ZQ, and affine difference xPQ=x(P-Q).
    // Output: projective Montgomery point P <- P+Q = (XQP:ZQP) such that = x(Q+P)=XQP/ZQP.
    f2elm_t t0, t1;

    fp2add(P->X, P->Z, t0);       // t0 = XP+ZP
    fp2sub(P->X, P->Z, t1);       // t1 = XP-ZP
    fp2sub(Q->X, Q->Z, P->X);     // XP = XQ-ZQ
    fp2add(Q->X, Q->Z, P->Z);     // ZP = XQ+ZQ
    fp2mul_mont(t0, P->X, t0);    // t0 = (XP+ZP)*(XQ-ZQ)
    fp2mul_mont(t1, P->Z, t1);    // t1 = (XP-ZP)*(XQ+ZQ)
    fp2sub(t0, t1, P->Z);         // ZP = (XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)
    fp2add(t0, t1, P->X);         // XP = (XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)
    fp2sqr_mont(P->Z, P->Z);      // ZP = [(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
    fp2sqr_mont(P->X, P->X);      // XP = [(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2
    fp2mul_mont(P->Z, xPQ, P->Z); // ZP = xPQ*[(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
}

void get_4_isog(const point_proj_t P, f2elm_t A24plus, f2elm_t C24, f2elm_t coeff[5])
{ // Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
    // Input:  projective point of order four P = (X4:Z4).
    // Output: the 4-isogenous Montgomery curve with A  / C and the 5 coefficients
    //         that are used to evaluate the isogeny at a point in eval_4_isog().

    f2elm_t tmp;
    fp2mul_mont(P->X, P->Z, coeff[0]);
    fp2add(coeff[0], coeff[0], coeff[0]); // coeff0:=2*X4*Z4;

    fp2sqr_mont(P->X, A24plus); // A24plus = X4^2
    fp2sqr_mont(P->Z, C24);     // C24 = Z4^2

    fp2add(A24plus, C24, coeff[1]); //coeff1 = X4^2+Z4^2;
    fp2sub(A24plus, C24, coeff[2]); //coeff2 = X4^2-Z4^2;
    fp2sqr_mont(A24plus, coeff[3]); //coeff3 = X4^4;
    fp2sqr_mont(C24, coeff[4]);     //coeff4 = Z4^4;

    fp2add(A24plus, A24plus, A24plus); // A24plus = 2*X4^2
    fp2sqr_mont(A24plus, A24plus);     // A24plus = 4*X4^4
    fp2sqr_mont(C24, C24);             // C24 = Z4^4
    fp2add(C24, C24, tmp);             // tmp = 2*Z4^4

    fp2sub(A24plus, tmp, A24plus); // A24plus = 4*X4^4-2*Z4^4

    //A24num:=C+C;
    //A24den:=A24num+A24num;
    //A24num:=A24num+A;
}

void eval_4_isog(point_proj_t P, f2elm_t coeff[5])
{ // Evaluates the isogeny at the point (X:Z) in the domain of the isogeny, given a 4-isogeny phi defined
    // by the 3 coefficients in coeff (computed in the function get_4_isog()).
    // Inputs: the coefficients defining the isogeny, and the projective point P = (X:Z).
    // Output: the projective point P = phi(P) = (X:Z) in the codomain.
    f2elm_t t0, t1;

    fp2mul_mont(coeff[0], P->X, P->X); //X:=coeff[0]*X;
    fp2mul_mont(coeff[1], P->Z, t0);   //t0:=coeff[1]*Z;
    fp2sub(P->X, t0, P->X);            //X:=X-t0;
    fp2mul_mont(coeff[2], P->Z, P->Z); //Z:=coeff[2]*Z;
    fp2sub(P->X, P->Z, t0);            //t0:=X-Z;
    fp2mul_mont(P->X, P->Z, P->Z);     //Z:=X*Z;
    fp2sqr_mont(t0, t0);               // t0:=t0^2;
    fp2add(P->Z, P->Z, P->Z);          //Z:=Z+Z;
    fp2add(P->Z, P->Z, P->Z);          //Z:=Z+Z;
    fp2add(t0, P->Z, P->X);            //X:=t0+Z;
    fp2mul_mont(t0, P->Z, P->Z);       //Z:=t0*Z;
    fp2mul_mont(coeff[4], P->Z, P->Z); //Z:=coeff[4]*Z;
    fp2mul_mont(coeff[4], t0, t0);     //t0:=t0*coeff[4];
    fp2mul_mont(coeff[3], P->X, t1);   //t1:=X*coeff[3];
    fp2sub(t0, t1, t0);                //t0:=t0-t1;
    fp2mul_mont(t0, P->X, P->X);       //X:=X*t0;
}

void j_inv(f2elm_t A, f2elm_t C, f2elm_t jinv)
{ // Computes the j-invariant of a Montgomery curve with projective constant.
    // Input: A,C in GF(p^2).
    // Output: j=256*(A^2-3*C^2)^3/(C^4*(A^2-4*C^2)), which is the j-invariant of the Montgomery curve B*y^2=x^3+(A/C)*x^2+x or (equivalently) j-invariant of B'*y^2=C*x^3+A*x^2+C*x.
    f2elm_t t0, t1;

    fp2sqr_mont(A, jinv);        // jinv = A^2
    fp2sqr_mont(C, t1);          // t1 = C^2
    fp2add(t1, t1, t0);          // t0 = t1+t1
    fp2sub(jinv, t0, t0);        // t0 = jinv-t0
    fp2sub(t0, t1, t0);          // t0 = t0-t1
    fp2sub(t0, t1, jinv);        // jinv = t0-t1
    fp2sqr_mont(t1, t1);         // t1 = t1^2
    fp2mul_mont(jinv, t1, jinv); // jinv = jinv*t1
    fp2add(t0, t0, t0);          // t0 = t0+t0
    fp2add(t0, t0, t0);          // t0 = t0+t0
    fp2sqr_mont(t0, t1);         // t1 = t0^2
    fp2mul_mont(t0, t1, t0);     // t0 = t0*t1
    fp2add(t0, t0, t0);          // t0 = t0+t0
    fp2add(t0, t0, t0);          // t0 = t0+t0
    fp2inv_mont(jinv);           // jinv = 1/jinv
    fp2mul_mont(jinv, t0, jinv); // jinv = t0*jinv
}

void LADDER_3_pt(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xPQ,
                 const felm_t m, point_proj_t W, const f2elm_t A)
{
    point_proj_t U, V;
    u8 bits[66] = {0};
    limb mask;
    f2elm_t A24;
    int i, bit, swap, prevbit = 0;

    // Initializing constant
    fp2one(A24);
    fp2add(A24, A24, A24);
    fp2add(A, A24, A24);

    fp2div2(A24, A24);
    fp2div2(A24, A24); // A24 = (A+2)/4

    fp2zero(U->Z);
    fp2one(U->X); // Initializing with point at infinity (1:0),

    fp2copy(xQ, V->X);
    fp2one(V->Z); // (xQ:1)

    fp2copy(xP, W->X);
    fp2one(W->Z); // (xP:1)

    // fpcopy(m, bits);
    felem_to_bin66(bits, m);

    // Main loop
    for (i = 520; i >= 0; i--)
    {
        limb tmp = bits[i >> 6];
        bit = (tmp >> (i & (63))) & 1;
        if (bit)
        {
            xADD(U, V, xQ);          // UX,UZ:=xADD(UX,UZ,VX,VZ,xQ);
            xDBLADD(V, W, xPQ, A24); //VX,VZ,WX,WZ:=xDBLADD(VX,VZ,WX,WZ,xPQ,A24);
        }
        else
        {
            xADD(W, U, xP);         //WX,WZ:=xADD(UX,UZ,WX,WZ,xP);
            xDBLADD(U, V, xQ, A24); //UX,UZ,VX,VZ:=xDBLADD(UX,UZ,VX,VZ,xQ,A24);
        }
    }
}

void xDiff(const point_proj_t P, const point_proj_t Q, f2elm_t xPQ, const f2elm_t A)
{ // Computing the point (x(Q-P))
    // Input:  point -P=(xP,-yP) and point Q=(xQ,yQ)
    // Output: the point D = x(Q-P)=(yQ+yP)^2/(xQ-xP)^2-xQ-xP-A.
    f2elm_t x1, y1, x2, y2;
    f2elm_t c, d, e;
    fp2copy(P->X, x1);
    fp2copy(P->Z, y1);
    fp2copy(Q->X, x2);
    fp2copy(Q->Z, y2);
    fp2add(y2, y1, c);
    fp2sub(x2, x1, d);
    fp2inv_mont(d);
    fp2mul_mont(c, d, e);
    fp2sqr_mont(e, xPQ);
    fp2sub(xPQ, x1, xPQ);
    fp2sub(xPQ, x2, xPQ);
    fp2sub(xPQ, A, xPQ);
}

static void fp2sqr_i(const f2elm_t a, felem sqr_i)
{
    felm_t a1, a0;
    fpsqr_mont(a[0], a0);
    fpsqr_mont(a[1], a1);
    fpadd(a1, a0, sqr_i);
}

static void fp2sqr_p(const felem a, felem s)
{
    fpcopy(a, s);
    int i;
    for (i = 0; i < 519; i++)
    {
        fpsqr_mont(s, s);
    }
}

void select_p(const f2elm_t A, const int per_r, point_proj_t P, point_proj_t Q, int *r)
{
    int i;
    felem z, s, s_2, one, alpha, beta, alpha2;
    felem *tabler, *tablev;

    f2elm_t v, x, t, tmp, y;
    fpone(one);

    fp2sqr_i(A, z);
    fp2sqr_p(z, s);
    fpsqr_mont(s, s_2);

    if (fpequl(s_2, z))
    { //T1
        tabler = table_r_qr;
        tablev = table_v_qr;
    }
    else
    {
        tabler = table_r_sqr;
        tablev = table_v_sqr;
    }

    for (i = per_r; i < TBALE_R_SIZE; i++)
    {
        int index = 2 * i;
        fp2zero(v);
        bin66_to_felem(v[0], tablev[index]);
        bin66_to_felem(v[1], tablev[index + 1]);
        fp2mul_mont(A, v, x); // x = A*V
        fp2neg(x);            // x = -A*V

        fp2sqr_mont(x, t);          // x^2
        fp2mul_mont(A, x, tmp);     // Ax
        fpadd(tmp[0], one, tmp[0]); // Ax +1

        fp2add(tmp, t, t);    // x^2 + Ax + 1
        fp2mul_mont(x, t, t); // t   = x * (x^2 + Ax + 1)
        fp2sqr_i(t, z);
        fp2sqr_p(z, s);
        fpsqr_mont(s, s_2);

        if (fpequl(s_2, z))
        {
            *r = i;
            break;
        }
    }

    fpadd(t[0], s, z); // z = e + s

    fpdiv2(z, z); // z = (e+s) / 2

    fp2sqr_p(z, alpha); // alpha = z ^ ( (p+1)/4)

    fpadd(alpha, alpha, beta); // 2*alpha
    fpinv_mont(beta);          // 1/ (2*alpha)
    fpmul_mont(t[1], beta, beta);

    fpsqr_mont(alpha, alpha2);

    if (fpequl(alpha2, z))
    {
        fpcopy(alpha, y[0]);
        fpcopy(beta, y[1]);
    }
    else
    {
        fpcopy(beta, y[0]);
        fpneg(y[0]);
        fpcopy(alpha, y[1]);
    }

    fp2copy(x, P->X);
    fp2copy(y, P->Z);

    fp2zero(v);
    bin66_to_felem(v[0], tabler[i]);
    bin66_to_felem(v[1], tabler[i]); // u0*r
    fp2mul_mont(v, y, y);

    fp2sqr_mont(v, v);
    fp2mul_mont(v, x, x);

    fp2copy(x, Q->X);
    fp2copy(y, Q->Z);
}

void iso_2m_curve(const felem sk, const point_proj_t P, const point_proj_t Q, const f2elm_t xPQ, const f2elm_t A, f2elm_t out)
{
    int row, i;
    point_proj_t W, R;
    f2elm_t A24plus, C24, coeff[5], ONE;

    fp2one(ONE);
    fp2one(C24); //  1
    fp2copy(A, A24plus);

    LADDER_3_pt(P->X, Q->X, xPQ, sk, R, A); // p + sk*Q

    for (row = 519; row > 0; row = row - 2)
    {
        fp2add(C24, C24, C24);         // 2
        fp2add(C24, A24plus, A24plus); //A +2
        fp2add(C24, C24, C24);         //  4
        xDBLe(R, W, A24plus, C24, row);
        get_4_isog(W, A24plus, C24, coeff);
        eval_4_isog(R, coeff);
    }

    fp2inv_mont(C24);                   //  C24:=1/C;
    fp2mul_mont(C24, A24plus, A24plus); //   A:=A*C;
    fp2inv_mont(R->Z);                  // RZ:=1/RZ;
    fp2mul_mont(R->Z, R->X, R->X);      // xR:=RX*RZ;
    fp2sqr_mont(R->X, R->X);            //a1:=xR^2;
    fp2add(R->X, R->X, R->X);           // a1:=2*a1;
    fp2sub(ONE, R->X, R->X);            //a1:=1-a1;
    fp2add(R->X, R->X, out);            //  A:=a1+a1;
}

//1
void iso_hash521(const felem m1, const felem m2, f2elm_t A)
{

    int index = 0;
    f2elm_t A2, A3, xPQ;
    felem m;
    point_proj_t P, Q;
    f2elm_t E0;
    bin66_to_felem(E0[0], E0_64[0]);
    bin66_to_felem(E0[1], E0_64[1]);

    fp2copy(E0, A2);

    felem_inv(m, m1);
    fpmul_mont(m2, m, m);

    while (fp2equl(A2, E0))
    {
        select_p(A2, index, P, Q, &index); // select P,Q
        xDiff(P, Q, xPQ, A2);              // XPQ = P-Q   // WEN TI
        iso_2m_curve(m, P, Q, xPQ, A2, A2);
        index++;
    }
    fp2copy(A2, A);
}

// 15-1
void iso_hash(const f2elm_t A, f2elm_t B, int chainlen)
{
    f2elm_t m, tmp;
    f2elm_t E0;
    bin66_to_felem(E0[0], E0_64[0]);
    bin66_to_felem(E0[1], E0_64[1]);

    fp2copy(A, m);
    int i;
    for (i = 0; i < chainlen; i++)
    {
        iso_hash521(m[0], m[1], tmp);
        fp2copy(tmp, m);
    }

    fp2copy(m, B);
}

void iso_hash_N_2_N(const f2elm_t A, f2elm_t B)
{
    iso_hash521(A[0], A[1], B);
}

void iso_hash_N_2_N_E(const f2elm_t E0, const f2elm_t A, f2elm_t B)
{
   iso_hash521_E(A[0], A[1], E0, B);
}

void iso_hash521_E(const felem m1, const felem m2, const f2elm_t E0, f2elm_t A)
{

    int index = 0;
    felem m;
    f2elm_t A2, A3, xPQ;
    point_proj_t P, Q;

    fp2copy(E0, A2);
    felem_inv(m, m1);
    fpmul_mont(m2, m, m);

    while (fp2equl(A2, E0))
    {
        select_p(A2, index, P, Q, &index); // select P,Q
        xDiff(P, Q, xPQ, A2);              // XPQ = P-Q   // WEN TI
        iso_2m_curve(m, P, Q, xPQ, A2, A2);
        index++;
    }
    fp2copy(A2, A);
}
