#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <x86intrin.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
/* premise test: does flag-free accumulate overlap where flag chains can't?
   adc chain: x += p (serial flag dep). logic carry: s=x^y, c=(x&y); x=s; carry=c<<1.
   carry-pair: keep redundant (s,c) — s,c = x^y, (x&y)|(x|y)&z... proper csa pair */
int main(void){
    uint64_t a0=0x1111,b0=0x2222,c0=0x3333,d0=0x4444;
    uint64_t p1=0x9e3779b97f4a7c15,p2=0x123456789abcdef0;
    int IT=20000000; volatile uint64_t sink=0; double t;
    /* 1 serial adc chain */
    t=now();
    for(int i=0;i<IT;i++){ a0+=p1; a0+=p2; } /* adds write flags, chain on data dep */
    printf("add-chain x1: %.2f ns/step\n",(now()-t)/IT*1e9/2); sink+=a0;
    /* 4 independent add chains */
    uint64_t x1=a0,x2=b0,x3=c0,x4=d0;
    t=now();
    for(int i=0;i<IT;i++){
        x1+=p1; x2+=p2; x3+=p1; x4+=p2;
        x1+=p2; x2+=p1; x3+=p2; x4+=p1;
    }
    printf("add-chain x4: %.2f ns/step\n",(now()-t)/IT*1e9/8); sink+=x1+x2+x3+x4;
    /* adc: true flag-dep chain via __int128 accumulate */
    __uint128_t A0=123, B0=456, C0=789, D0=321;
    t=now();
    for(int i=0;i<IT;i++){ A0+=(__uint128_t)p1*p2; A0+=(__uint128_t)p2*p1; }
    printf("mulx+adc x1: %.2f ns/step\n",(now()-t)/IT*1e9/2); sink+=(uint64_t)A0;
    __uint128_t X1=A0,X2=B0,X3=C0,X4=D0;
    t=now();
    for(int i=0;i<IT;i++){
        X1+=(__uint128_t)p1*p2; X2+=(__uint128_t)p2*p1;
        X3+=(__uint128_t)p1*p2; X4+=(__uint128_t)p2*p1;
        X1+=(__uint128_t)p2*p1; X2+=(__uint128_t)p1*p2;
        X3+=(__uint128_t)p2*p1; X4+=(__uint128_t)p1*p2;
    }
    printf("mulx+adc x4: %.2f ns/step\n",(now()-t)/IT*1e9/8); sink+=(uint64_t)(X1+X2+X3+X4);
    /* carry-save pair accumulate, flag-free */
    uint64_t s1=a0,s2=b0,s3=c0,s4=d0, k1=0,k2=0,k3=0,k4=0;
    t=now();
    for(int i=0;i<IT;i++){
        uint64_t u;
        u=s1^p1; k1=(s1&p1)|((s1|p1)&~(u+p2)); s1=u+p2; /* free-form flagfree */
        u=s2^p2; k2=(s2&p2)|((s2|p2)&~(u+p1)); s2=u+p1;
        u=s3^p1; k3=(s3&p1)|((s3|p1)&~(u+p2)); s3=u+p2;
        u=s4^p2; k4=(s4&p2)|((s4|p2)&~(u+p1)); s4=u+p1;
    }
    printf("csa-style x4: %.2f ns/step\n",(now()-t)/IT*1e9/4); sink+=s1+s2+s3+s4+k1+k2+k3+k4;
    printf("%lu\n",(long)sink);
    return 0;
}
