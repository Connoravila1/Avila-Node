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
static inline void fe4_sqr4(fe4 r, const fe4 a){
    vd ad[5]; for(int i=0;i<5;i++)ad[i]=i2d(a[i]);
    vd C1=_mm256_set1_pd(0x1p104),C2=_mm256_set1_pd(0x1p104+0x1p52);
    static const int noff[9]={0,1,1,2,2,2,1,1,0};
    static const int ndiag[9]={1,0,1,0,1,0,1,0,1};
    vi O[10]; vi car=_mm256_setzero_si256(); vi m52=M52v;
    vd c16=_mm256_set1_pd((double)(16ULL*0x1000003D1ULL));
    vi F[6]; for(int i=0;i<6;i++)F[i]=_mm256_setzero_si256();
    vi A=_mm256_setzero_si256(),N=_mm256_setzero_si256();
    for(int c=0;c<9;c++){
        vi lo_accs=A, hi_accs=N;
        for(int i=(c<5?0:(c+1)/2);i<5 && i<c-i;i++){int j=c-i;
            vd hi=_mm256_fmadd_pd(ad[i],ad[j],C1);
            vd dd=_mm256_sub_pd(C2,hi);
            vd lo=_mm256_fmadd_pd(ad[i],ad[j],dd);
            lo_accs=_mm256_add_epi64(lo_accs,_mm256_castpd_si256(lo));
            hi_accs=_mm256_add_epi64(hi_accs,_mm256_castpd_si256(hi));
        }
        if(c%2==0){int i=c/2;
            vd hi=_mm256_fmadd_pd(ad[i],ad[i],C1);
            vd dd=_mm256_sub_pd(C2,hi);
            vd lo=_mm256_fmadd_pd(ad[i],ad[i],dd);
            lo_accs=_mm256_add_epi64(lo_accs,_mm256_castpd_si256(lo));
            hi_accs=_mm256_add_epi64(hi_accs,_mm256_castpd_si256(hi));
        }
        /* bias: A gets lo-parts (doubled for off-diag? handled by adding
           off-diag lo twice) — simplest: just accumulate and correct
           bias at end via known constants */
        vi t=_mm256_add_epi64(lo_accs,car);
        O[c]=_mm256_and_si256(t,m52); car=_mm256_srli_epi64(t,52);
        A=N; N=_mm256_setzero_si256();
        if(c>=5){ vd od=i2d(O[c]);
            vd h=_mm256_fmadd_pd(od,c16,C1);
            vd dd=_mm256_sub_pd(C2,h);
            vd l=_mm256_fmadd_pd(od,c16,dd);
            F[c-5]=_mm256_add_epi64(F[c-5],d2bits(l));
            F[c-4]=_mm256_add_epi64(F[c-4],_mm256_sub_epi64(_mm256_castpd_si256(h),_mm256_set1_epi64x(B_HI)));
        }
    }
    O[9]=_mm256_add_epi64(A,car);
    (void)noff;(void)ndiag;
    /* note: bias constants omitted -> wrong math but same op profile */
    vd od9=i2d(O[9]);
    vd h9=_mm256_fmadd_pd(od9,c16,C1);
    vd dd9=_mm256_sub_pd(C2,h9);
    vd l9=_mm256_fmadd_pd(od9,c16,dd9);
    F[4]=_mm256_add_epi64(F[4],d2bits(l9));
    F[5]=_mm256_add_epi64(F[5],_mm256_sub_epi64(_mm256_castpd_si256(h9),_mm256_set1_epi64x(B_HI)));
    {vi x4=_mm256_srli_epi64(O[4],48);
     vi g=_mm256_add_epi64(_mm256_mul_epu32(x4,_mm256_set1_epi64x(977)),_mm256_slli_epi64(x4,32));
     F[0]=_mm256_add_epi64(F[0],_mm256_and_si256(g,m52));
     F[1]=_mm256_add_epi64(F[1],_mm256_srli_epi64(g,52));}
    {vd od=i2d(F[5]);vd h=_mm256_fmadd_pd(od,c16,C1);vd dd=_mm256_sub_pd(C2,h);
     vd l=_mm256_fmadd_pd(od,c16,dd);
     F[0]=_mm256_add_epi64(F[0],d2bits(l));
     F[1]=_mm256_add_epi64(F[1],_mm256_sub_epi64(_mm256_castpd_si256(h),_mm256_set1_epi64x(B_HI)));}
    vi c2=_mm256_setzero_si256(),m48=M48v;{vi t;
        t=_mm256_add_epi64(O[0],F[0]);t=_mm256_add_epi64(t,c2);r[0]=_mm256_and_si256(t,m52);c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[1],F[1]);t=_mm256_add_epi64(t,c2);r[1]=_mm256_and_si256(t,m52);c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[2],F[2]);t=_mm256_add_epi64(t,c2);r[2]=_mm256_and_si256(t,m52);c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[3],F[3]);t=_mm256_add_epi64(t,c2);r[3]=_mm256_and_si256(t,m52);c2=_mm256_srli_epi64(t,52);
        t=_mm256_and_si256(O[4],m48);t=_mm256_add_epi64(t,F[4]);t=_mm256_add_epi64(t,c2);r[4]=_mm256_and_si256(t,m48);c2=_mm256_srli_epi64(t,48);}
    for(int it=0;it<2;it++){
        vi g=_mm256_add_epi64(_mm256_mul_epu32(c2,_mm256_set1_epi64x(977)),_mm256_slli_epi64(c2,32));
        vi t=_mm256_add_epi64(r[0],_mm256_and_si256(g,m52));r[0]=_mm256_and_si256(t,m52);
        vi cc=_mm256_add_epi64(_mm256_srli_epi64(t,52),_mm256_srli_epi64(g,52));
        t=_mm256_add_epi64(r[1],cc);r[1]=_mm256_and_si256(t,m52);cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(r[2],cc);r[2]=_mm256_and_si256(t,m52);cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(r[3],cc);r[3]=_mm256_and_si256(t,m52);cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(r[4],cc);r[4]=_mm256_and_si256(t,m48);c2=_mm256_srli_epi64(t,48);(void)c2;}
}
#define MAXL 64
static fe4 accs[MAXL];
int main(void){
    fesetround(FE_TOWARDZERO);srand(3);
    volatile int64_t sink=0;
    for(int L=1;L<=32;L*=2){
        for(int s=0;s<MAXL;s++)for(int k=0;k<5;k++)accs[s][k]=_mm256_set1_epi64x((rand()&0xFFFFFFFFFFF)+s);
        int IT=200000;double t0=now();int j=0;
        for(int i=0;i<IT;i++){fe4 r;fe4_sqr4(r,accs[j]);memcpy(accs[j],r,sizeof r);j++;if(j==L)j=0;}
        double d=(now()-t0)/IT*1e9;
        printf("sqr4 L=%2d : %6.1f ns/fused-op\n",L,d);
        sink+=accs[0][0][0];
    }
    printf("%ld\n",(long)sink);
    return 0;
}
