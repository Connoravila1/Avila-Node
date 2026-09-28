/* dependency-distance probe: fused-4 mul throughput vs independence L.
   acc[i] cycles through L slots; each step muls acc[j] by fixed factor.
   L=1: fully serial chain. Larger L: L independent chains interleaved. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <fenv.h>
#include <time.h>
#include <immintrin.h>
typedef __m256d vd; typedef __m256i vi;
typedef vi fe4[5];
#define M52v _mm256_set1_epi64x((1LL<<52)-1)
#define M48v _mm256_set1_epi64x((1LL<<48)-1)
static const int64_t B_HI=0x4670000000000000LL, B_LO=0x4330000000000000LL;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static inline vd i2d(vi x){vi b=_mm256_add_epi64(x,_mm256_set1_epi64x(B_LO));return _mm256_sub_pd(_mm256_castsi256_pd(b),_mm256_set1_pd(0x1p52));}
static inline vi d2bits(vd x){return _mm256_sub_epi64(_mm256_castpd_si256(x),_mm256_set1_epi64x(B_LO));}
#include "v4.inc"
#define MAXL 64
static fe4 accs[MAXL];
int main(void){
    fesetround(FE_TOWARDZERO);
    srand(3);
    fe4 fac;
    for(int k=0;k<5;k++)fac[k]=_mm256_set1_epi64x(0x12345LL+k);
    volatile int64_t sink=0;
    for(int L=1;L<=32;L*=2){
        for(int s=0;s<MAXL;s++)
            for(int k=0;k<5;k++)
                accs[s][k]=_mm256_set1_epi64x((rand()&0xFFFFFFFFFFF)+s);
        int IT=200000;
        double t0=now();
        int j=0;
        for(int i=0;i<IT;i++){
            fe4 r;
            fe4_mul4v4(r,accs[j],fac);
            memcpy(accs[j],r,sizeof r);
            j++; if(j==L)j=0;
        }
        double d=(now()-t0)/IT*1e9;
        printf("L=%2d : %6.1f ns/fused-op = %5.1f ns/mul-equiv\n",L,d,d/4);
        sink+=accs[0][0][0];
    }
    printf("%ld\n",(long)sink);
    return 0;
}
