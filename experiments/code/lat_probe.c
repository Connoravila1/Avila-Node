#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <fenv.h>
#include <time.h>
#include <immintrin.h>
typedef __m256d vd; typedef __m256i vi;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
#define M52v _mm256_set1_epi64x((1LL<<52)-1)
static const int64_t B_HI=0x4670000000000000LL, B_LO=0x4330000000000000LL;
static inline vd i2d(vi x){vi b=_mm256_add_epi64(x,_mm256_set1_epi64x(B_LO));return _mm256_sub_pd(_mm256_castsi256_pd(b),_mm256_set1_pd(0x1p52));}
/* stage A: products+acc only (output O[10] sums unreduced) */
static inline void prod_only(int64_t out[10][4], const vi ai[5], const vi bi[5]){
    vd a[5],b[5];
    for(int i=0;i<5;i++){a[i]=i2d(ai[i]);b[i]=i2d(bi[i]);}
    vd C1=_mm256_set1_pd(0x1p104),C2=_mm256_set1_pd(0x1p104+0x1p52);
    vi A=_mm256_setzero_si256(),N=_mm256_setzero_si256(),car=A;
    for(int c=0;c<9;c++){
        for(int i=(c<5?0:c-4);i<5&&i<=c;i++){int j=c-i;
            vd hi=_mm256_fmadd_pd(a[i],b[j],C1);
            vd ad=_mm256_sub_pd(C2,hi);
            vd lo=_mm256_fmadd_pd(a[i],b[j],ad);
            A=_mm256_add_epi64(A,_mm256_castpd_si256(lo));
            N=_mm256_add_epi64(N,_mm256_castpd_si256(hi));
        }
        vi t=_mm256_add_epi64(A,car);
        _mm256_store_si256((vi*)out[c],_mm256_and_si256(t,_mm256_set1_epi64x(-1)));
        car=_mm256_srli_epi64(t,52);
        A=N; N=_mm256_setzero_si256();
    }
    vi t=_mm256_add_epi64(A,car);
    _mm256_store_si256((vi*)out[9],t);
}
int main(void){
    fesetround(FE_TOWARDZERO);
    srand(2);
    vi ai[5],bi[5];
    for(int i=0;i<5;i++){ai[i]=_mm256_set1_epi64x(rand()&((1LL<<52)-1));bi[i]=_mm256_set1_epi64x(rand()&((1LL<<52)-1));}
    int64_t out[10][4] __attribute__((aligned(32)));
    int IT=1000000; volatile int64_t sink=0;
    double t0=now();
    for(int i=0;i<IT;i++){
        prod_only(out,ai,bi);
        ai[0]=_mm256_add_epi64(ai[0],_mm256_set1_epi64x(out[0][0]&3)); /* serial dep */
    }
    printf("products+resolve only: %.1f ns\n",(now()-t0)/IT*1e9);
    printf("%ld\n",(long)sink+out[5][0]);
    return 0;
}
