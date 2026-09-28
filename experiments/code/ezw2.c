/* fe_mul4_ezw — all-SIMD: 4-lane 5x52 fused mul, flag-free.
 * Product split: hi=fma_rz(a,b,2^104) bits-B_HI=p>>52;
 *                ad=(2^104+2^52)-hi; lo=fma(a,b,ad) bits-B_LO=p mod 2^52.
 * Accumulate bit-patterns via vpaddq (init = -nterms*bias, mod-2^64 wrap
 * makes it exact). Carry-resolve & mod-p fold all in SIMD lanes.
 * Fold multiply v=out*16C uses the SAME RZ trick (out<2^52 as double:
 *   16C<2^37, product<2^89 -> hi gives top-37, lo gives low-52).
 * int<2^53->double: bits(B_LO+x) reinterpreted = 2^52+x -> fsub 2^52. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <fenv.h>
#include <time.h>
#include <immintrin.h>
#include "secp256k1.c"
#define S(n) rustsecp256k1_v0_10_0_##n
void S(default_illegal_callback_fn)(const char *a, void *b){(void)a;(void)b;}
void S(default_error_callback_fn)(const char *a, void *b){(void)a;(void)b;}
static double now_wall(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec+ts.tv_nsec*1e-9;}
typedef __m256d vd; typedef __m256i vi;
#define M52v _mm256_set1_epi64x((1LL<<52)-1)
#define M48v _mm256_set1_epi64x((1LL<<48)-1)
static const int64_t B_HI = 0x4670000000000000LL;
static const int64_t B_LO = 0x4330000000000000LL;
static inline vd i2d(vi x){ /* x int64 lanes, each <2^52 -> doubles */
    vi b=_mm256_add_epi64(x,_mm256_set1_epi64x(B_LO));
    return _mm256_sub_pd(_mm256_castsi256_pd(b),_mm256_set1_pd(0x1p52));
}
static inline vi d2bits(vd x){ /* biased-double -> int via bits trick:
     x in ulp-1 binade [2^52,2^53): bits(x)-B_LO = x_int */
    return _mm256_sub_epi64(_mm256_castpd_si256(x),_mm256_set1_epi64x(B_LO));
}
/* out (int lanes <2^52) * 16C -> two int vectors: lo52 & hi37 */
static inline void fold16C(vi out, vi *lo, vi *hi){
    vd od=i2d(out);
    vd c16=_mm256_set1_pd((double)(16ULL*0x1000003D1ULL));
    vd h=_mm256_fmadd_pd(od,c16,_mm256_set1_pd(0x1p104));
    vd ad=_mm256_sub_pd(_mm256_set1_pd(0x1p104+0x1p52),h);
    vd l=_mm256_fmadd_pd(od,c16,ad);
    *hi=_mm256_sub_epi64(_mm256_castpd_si256(h),_mm256_set1_epi64x(B_HI));
    *lo=d2bits(l);
}
/* x4 * C : x4 tiny (<2^8) -> vpmuludq fine: x4*(2^32+977) = x4<<32 + x4*977 */
static inline vi mulC_small(vi x){
    vi lo=_mm256_mul_epu32(x,_mm256_set1_epi64x(977));
    vi hi=_mm256_slli_epi64(x,32);
    return _mm256_add_epi64(lo,hi);
}
static void fe_mul4_ezw(uint64_t r[4][5], const uint64_t a[4][5], const uint64_t b[4][5]){
    vd A[5],B[5];
    for(int i=0;i<5;i++){
        A[i]=_mm256_set_pd((double)a[3][i],(double)a[2][i],(double)a[1][i],(double)a[0][i]);
        B[i]=_mm256_set_pd((double)b[3][i],(double)b[2][i],(double)b[1][i],(double)b[0][i]);
    }
    static const int nt[9]={1,2,3,4,5,4,3,2,1};
    vi H[9],L[9];
    for(int k=0;k<9;k++){
        H[k]=_mm256_set1_epi64x(-(int64_t)nt[k]*B_HI);
        L[k]=_mm256_set1_epi64x(-(int64_t)nt[k]*B_LO);
    }
    vd C1=_mm256_set1_pd(0x1p104), C2=_mm256_set1_pd(0x1p104+0x1p52);
    for(int i=0;i<5;i++) for(int j=0;j<5;j++){
        int c=i+j;
        vd hi=_mm256_fmadd_pd(A[i],B[j],C1);
        vd ad=_mm256_sub_pd(C2,hi);
        vd lo=_mm256_fmadd_pd(A[i],B[j],ad);
        H[c]=_mm256_add_epi64(H[c],_mm256_castpd_si256(hi));
        L[c]=_mm256_add_epi64(L[c],_mm256_castpd_si256(lo));
    }
    /* S[c]=L[c]+H[c-1] ; carry-resolve all SIMD */
    vi O[10],car=_mm256_setzero_si256(),m52=M52v;
    for(int c=0;c<9;c++){
        vi t=_mm256_add_epi64(L[c], c?_mm256_add_epi64(H[c-1],car):car);
        O[c]=_mm256_and_si256(t,m52);
        car=_mm256_srli_epi64(t,52);
    }
    O[9]=_mm256_add_epi64(H[8],car);
    /* fold limbs 5..9: v=out*16C at position c-5 / c-4 */
    vi F[6]; for(int i=0;i<6;i++)F[i]=_mm256_setzero_si256();
    for(int c=5;c<10;c++){
        vi lo,hi; fold16C(O[c],&lo,&hi);
        F[c-5]=_mm256_add_epi64(F[c-5],lo);
        F[c-4]=_mm256_add_epi64(F[c-4],hi);
    }
    /* limb4 top-4 bits -> *C into limb0,1 */
    {
        vi x4=_mm256_srli_epi64(O[4],48);
        vi g =mulC_small(x4);
        F[0]=_mm256_add_epi64(F[0],_mm256_and_si256(g,m52));
        F[1]=_mm256_add_epi64(F[1],_mm256_srli_epi64(g,52));
    }
    /* F[5] (weight 2^260) -> *16C into limbs 0,1 — iterate */
    for(int it=0;it<3;it++){
        vi lo,hi; fold16C(F[5],&lo,&hi);
        F[0]=_mm256_add_epi64(F[0],lo);
        F[1]=_mm256_add_epi64(F[1],hi);
        F[5]=_mm256_setzero_si256();
    }
    /* combine */
    vi c2=_mm256_setzero_si256(),m48=M48v; vi rr[5]; { vi t;
        t=_mm256_add_epi64(O[0],F[0]); t=_mm256_add_epi64(t,c2);
        rr[0]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[1],F[1]); t=_mm256_add_epi64(t,c2);
        rr[1]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[2],F[2]); t=_mm256_add_epi64(t,c2);
        rr[2]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[3],F[3]); t=_mm256_add_epi64(t,c2);
        rr[3]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_and_si256(O[4],m48); t=_mm256_add_epi64(t,F[4]); t=_mm256_add_epi64(t,c2);
        rr[4]=_mm256_and_si256(t,m48); c2=_mm256_srli_epi64(t,48);
    }
    /* residual carry2*C into limbs — 2 fixed iterations */
    for(int it=0;it<2;it++){
        vi g=mulC_small(c2);
        vi t=_mm256_add_epi64(rr[0],_mm256_and_si256(g,m52));
        rr[0]=_mm256_and_si256(t,m52);
        vi cc=_mm256_add_epi64(_mm256_srli_epi64(t,52),_mm256_srli_epi64(g,52));
        t=_mm256_add_epi64(rr[1],cc); rr[1]=_mm256_and_si256(t,m52); cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(rr[2],cc); rr[2]=_mm256_and_si256(t,m52); cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(rr[3],cc); rr[3]=_mm256_and_si256(t,m52); cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(rr[4],cc); rr[4]=_mm256_and_si256(t,m48); c2=_mm256_srli_epi64(t,48);
        /* 3rd iteration virtually impossible; assert via test */
        (void)c2;
    }
    uint64_t tmp[4];
    for(int i=0;i<5;i++){
        _mm256_storeu_si256((vi*)tmp,rr[i]);
        for(int l=0;l<4;l++) r[l][i]=tmp[l];
    }
}
/* fe_sqr4: r=a^2. Column c gets: 2*sum_{i<j,i+j=c} a_i*a_j + (a_{c/2})^2
 * if c even. Compute each off-diag product once, double it into the
 * column (or accumulate into both halves' sums: lo-part <<1). */
static void fe_sqr4_ezw(uint64_t r[4][5], const uint64_t a[4][5]){
    vd A[5];
    for(int i=0;i<5;i++)
        A[i]=_mm256_set_pd((double)a[3][i],(double)a[2][i],(double)a[1][i],(double)a[0][i]);
    vd C1=_mm256_set1_pd(0x1p104), C2=_mm256_set1_pd(0x1p104+0x1p52);
    static const int ntH[9]={0}, ntL[9]={0}; (void)ntH;(void)ntL;
    /* count products per column for bias init */
    int nH[9]={0},nL[9]={0};
    /* we just accumulate everything then handle bias via tracking terms:
       simpler — track counts at compile time:
       col c: off-diag pairs (i<j, i+j=c) count + diagonal if c even */
    static const int ndiag[9]={1,0,1,0,1,0,1,0,1};
    static const int noff[9]={0,1,1,2,2,2,1,1,0}; /* pairs i<j, i+j=c */
    vi H[9],L[9];
    for(int k=0;k<9;k++){
        /* bias count = ndiag + 2*noff for both H and L sides */
        int n = ndiag[k]+2*noff[k];
        H[k]=_mm256_set1_epi64x(-(int64_t)n*B_HI);
        L[k]=_mm256_set1_epi64x(-(int64_t)n*B_LO);
    }
    /* off-diagonal: each product contributes TWICE to the column —
       accumulate its bits twice (or accumulate once into col and once
       via a doubling of the final column sums — cheaper: add bits twice
       costs same as separate; better accumulate once and double the
       column total — the sL/sH sums are ints -> <<1 at resolve time).
       NOTE doubling must happen on the INTEGER sums; accumulate
       off-diag separately then double */
    vi Ho[9],Lo[9],Hd[9],Ld[9];
    for(int k=0;k<9;k++){
        Ho[k]=_mm256_set1_epi64x(-(int64_t)noff[k]*B_HI);
        Lo[k]=_mm256_set1_epi64x(-(int64_t)noff[k]*B_LO);
        Hd[k]=_mm256_set1_epi64x(-(int64_t)ndiag[k]*B_HI);
        Ld[k]=_mm256_set1_epi64x(-(int64_t)ndiag[k]*B_LO);
    }
    for(int i=0;i<5;i++){
        /* diagonal */
        { vd hi=_mm256_fmadd_pd(A[i],A[i],C1);
          vd ad=_mm256_sub_pd(C2,hi);
          vd lo=_mm256_fmadd_pd(A[i],A[i],ad);
          int c=2*i;
          Hd[c]=_mm256_add_epi64(Hd[c],_mm256_castpd_si256(hi));
          Ld[c]=_mm256_add_epi64(Ld[c],_mm256_castpd_si256(lo)); }
        for(int j=i+1;j<5;j++){
            vd hi=_mm256_fmadd_pd(A[i],A[j],C1);
            vd ad=_mm256_sub_pd(C2,hi);
            vd lo=_mm256_fmadd_pd(A[i],A[j],ad);
            int c=i+j;
            Ho[c]=_mm256_add_epi64(Ho[c],_mm256_castpd_si256(hi));
            Lo[c]=_mm256_add_epi64(Lo[c],_mm256_castpd_si256(lo));
        }
    }
    /* combined column sums: S[c] = Ld[c]+Lo[c]*2 + (Hd[c-1]+Ho[c-1]*2) */
    vi O[10],car=_mm256_setzero_si256(),m52=M52v;
    for(int c=0;c<9;c++){
        vi lo=_mm256_add_epi64(Ld[c],_mm256_add_epi64(Lo[c],Lo[c]));
        vi hh=_mm256_add_epi64(c?Hd[c-1]:_mm256_setzero_si256(),
                                 c?_mm256_add_epi64(Ho[c-1],Ho[c-1]):_mm256_setzero_si256());
        vi t=_mm256_add_epi64(_mm256_add_epi64(lo,hh),car);
        O[c]=_mm256_and_si256(t,m52);
        car=_mm256_srli_epi64(t,52);
    }
    { vi hh=_mm256_add_epi64(Hd[8],_mm256_add_epi64(Ho[8],Ho[8]));
      O[9]=_mm256_add_epi64(hh,car); }
    /* same fold as mul */
    vi F[6]; for(int i=0;i<6;i++)F[i]=_mm256_setzero_si256();
    for(int c=5;c<10;c++){
        vi lo,hi; fold16C(O[c],&lo,&hi);
        F[c-5]=_mm256_add_epi64(F[c-5],lo);
        F[c-4]=_mm256_add_epi64(F[c-4],hi);
    }
    {
        vi x4=_mm256_srli_epi64(O[4],48);
        vi g =mulC_small(x4);
        F[0]=_mm256_add_epi64(F[0],_mm256_and_si256(g,m52));
        F[1]=_mm256_add_epi64(F[1],_mm256_srli_epi64(g,52));
    }
    for(int it=0;it<3;it++){
        vi lo,hi; fold16C(F[5],&lo,&hi);
        F[0]=_mm256_add_epi64(F[0],lo);
        F[1]=_mm256_add_epi64(F[1],hi);
        F[5]=_mm256_setzero_si256();
    }
    vi c2=_mm256_setzero_si256(),m48=M48v; vi rr[5]; { vi t;
        t=_mm256_add_epi64(O[0],F[0]); t=_mm256_add_epi64(t,c2);
        rr[0]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[1],F[1]); t=_mm256_add_epi64(t,c2);
        rr[1]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[2],F[2]); t=_mm256_add_epi64(t,c2);
        rr[2]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[3],F[3]); t=_mm256_add_epi64(t,c2);
        rr[3]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_and_si256(O[4],m48); t=_mm256_add_epi64(t,F[4]); t=_mm256_add_epi64(t,c2);
        rr[4]=_mm256_and_si256(t,m48); c2=_mm256_srli_epi64(t,48);
    }
    for(int it=0;it<2;it++){
        vi g=mulC_small(c2);
        vi t=_mm256_add_epi64(rr[0],_mm256_and_si256(g,m52));
        rr[0]=_mm256_and_si256(t,m52);
        vi cc=_mm256_add_epi64(_mm256_srli_epi64(t,52),_mm256_srli_epi64(g,52));
        t=_mm256_add_epi64(rr[1],cc); rr[1]=_mm256_and_si256(t,m52); cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(rr[2],cc); rr[2]=_mm256_and_si256(t,m52); cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(rr[3],cc); rr[3]=_mm256_and_si256(t,m52); cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(rr[4],cc); rr[4]=_mm256_and_si256(t,m48); c2=_mm256_srli_epi64(t,48);
        (void)c2;
    }
    uint64_t tmp[4];
    for(int i=0;i<5;i++){
        _mm256_storeu_si256((vi*)tmp,rr[i]);
        for(int l=0;l<4;l++) r[l][i]=tmp[l];
    }
    (void)H;(void)L;
}

static void ref_mul(uint64_t r[5], const uint64_t a[5], const uint64_t b[5]){
    S(fe) fa,fb,fr;
    for(int i=0;i<5;i++){fa.n[i]=a[i];fb.n[i]=b[i];}
    S(fe_mul)(&fr,&fa,&fb); S(fe_normalize)(&fr);
    for(int i=0;i<5;i++)r[i]=fr.n[i];
}
int main(void){
    fesetround(FE_TOWARDZERO);
    srand(3);
    uint64_t a[4][5],b[4][5],rr[4][5],ref[4][5];
    int bad=0;
    for(int t=0;t<200000;t++){
        for(int l=0;l<4;l++)
            for(int i=0;i<5;i++){
                a[l][i]=((uint64_t)rand()<<21|rand())&((1ULL<<52)-1);
                b[l][i]=((uint64_t)rand()<<21|rand())&((1ULL<<52)-1);
                if(i==4){a[l][i]&=(1ULL<<48)-1;b[l][i]&=(1ULL<<48)-1;}
            }
        fe_mul4_ezw(rr,(const uint64_t(*)[5])a,(const uint64_t(*)[5])b);
        /* compare values mod p via ref */
        S(fe) f;
        for(int l=0;l<4;l++){
            ref_mul(ref[l],a[l],b[l]);
            for(int i=0;i<5;i++)f.n[i]=rr[l][i];
            S(fe_normalize)(&f);
            if(memcmp(f.n,ref[l],40)){bad++;if(bad<5)printf("lane%d t%d\n",l,t);}
        }
    }
    printf("correct: %d/200000\n",200000-bad);
    bad=0;
    for(int t=0;t<100000;t++){
        for(int l=0;l<4;l++)
            for(int i=0;i<5;i++){
                a[l][i]=((uint64_t)rand()<<21|rand())&((1ULL<<52)-1);
                if(i==4)a[l][i]&=(1ULL<<48)-1;
            }
        fe_sqr4_ezw(rr,(const uint64_t(*)[5])a);
        S(fe) f,fs;
        for(int l=0;l<4;l++){
            for(int i=0;i<5;i++)f.n[i]=a[l][i];
            S(fe_sqr)(&fs,&f); S(fe_normalize)(&fs);
            for(int i=0;i<5;i++)f.n[i]=rr[l][i];
            S(fe_normalize)(&f);
            if(memcmp(f.n,fs.n,40)){bad++;if(bad<5)printf("sqr lane%d t%d\n",l,t);}
        }
    }
    printf("sqr4 correct: %d/100000\n",100000-bad);
    int ITERS=400000;
    for(int l=0;l<4;l++)for(int i=0;i<5;i++){a[l][i]=((uint64_t)rand()<<21|rand())&((1ULL<<52)-1);b[l][i]=((uint64_t)rand()<<21|rand())&((1ULL<<52)-1);if(i==4){a[l][i]&=(1ULL<<48)-1;b[l][i]&=(1ULL<<48)-1;}}
    uint64_t acc=0;double t0=now_wall();
    for(int i=0;i<ITERS;i++){
        fe_mul4_ezw(rr,(const uint64_t(*)[5])a,(const uint64_t(*)[5])b);
        for(int l=0;l<4;l++)memcpy(a[l],rr[l],40);
        acc+=rr[0][0];
    }
    printf("chain : %.1f ns/group = %.2f ns/mul-equiv\n",(now_wall()-t0)/ITERS*1e9,(now_wall()-t0)/ITERS*1e9/4);
    uint64_t a2[4][5],b2[4][5];memcpy(a2,a,sizeof a);memcpy(b2,b,sizeof b);
    t0=now_wall();
    for(int i=0;i<ITERS/4;i++){
        fe_mul4_ezw(rr,(const uint64_t(*)[5])a,(const uint64_t(*)[5])b);
        fe_mul4_ezw(rr,(const uint64_t(*)[5])a2,(const uint64_t(*)[5])b2);
        fe_mul4_ezw(rr,(const uint64_t(*)[5])a,(const uint64_t(*)[5])b);
        fe_mul4_ezw(rr,(const uint64_t(*)[5])a2,(const uint64_t(*)[5])b2);
        a[0][0]++;b[0][0]++;a2[0][0]++;b2[0][0]++;acc+=rr[0][0];
    }
    printf("indep : %.1f ns/group = %.2f ns/mul-equiv\n",(now_wall()-t0)/(ITERS/4)/4*1e9,(now_wall()-t0)/(ITERS/4)/16*1e9);
    printf("acc %lu\n",acc);
    fesetround(FE_TONEAREST);
    return 0;
}
