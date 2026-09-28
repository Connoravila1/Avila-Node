#include <immintrin.h>
#include <stdio.h>
#include <time.h>
static double now(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec+ts.tv_nsec*1e-9;}
int main(void){
    /* raw vfmadd ymm throughput: 8 independent FMA chains */
    __m256d a=_mm256_set1_pd(1.0000001), b=_mm256_set1_pd(0.9999999), c=_mm256_set1_pd(0.5);
    __m256d x0=a,x1=a,x2=a,x3=a,x4=a,x5=a,x6=a,x7=a;
    long N=200000000; double t=now();
    for(long i=0;i<N;i++){
        x0=_mm256_fmadd_pd(x0,b,c); x1=_mm256_fmadd_pd(x1,b,c);
        x2=_mm256_fmadd_pd(x2,b,c); x3=_mm256_fmadd_pd(x3,b,c);
        x4=_mm256_fmadd_pd(x4,b,c); x5=_mm256_fmadd_pd(x5,b,c);
        x6=_mm256_fmadd_pd(x6,b,c); x7=_mm256_fmadd_pd(x7,b,c);
    }
    double dt=now()-t;
    printf("vfmadd ymm: %.2f vec-ops/cycle @2.9GHz (%.1f fma/cyc)\n",
           N*8.0/dt/2.9e9, N*8.0/dt/2.9e9*4);
    volatile double s=((double*)&x0)[0]+((double*)&x7)[3];
    /* mulx+adc relay throughput for contrast: 8 independent adcx chains via asm? 
       simpler: measure scalar mul throughput chain */
    unsigned long long u0=3,u1=5,u2=7,u3=11,u4=13,u5=17,u6=19,u7=23;
    unsigned long long m=0xdeadbeefcafebabeULL;
    t=now();
    for(long i=0;i<N;i++){
        u0*=m; u1*=m+1; u2*=m+2; u3*=m+3;
        u4*=m+4; u5*=m+5; u6*=m+6; u7*=m+7;
    }
    dt=now()-t;
    printf("imul scalar x8: %.2f muls/cycle\n", N*8.0/dt/2.9e9);
    volatile unsigned long long v=u0+u7;
    return (int)(s+v);
}
