#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static uint64_t P[64];
int main(void){
    srand(7); for(int i=0;i<64;i++)P[i]=((uint64_t)rand()<<32)|rand();
    int IT=2000000; volatile uint64_t sink=0; double t;
    /* __int128 mul+adc: serial flag-chain accumulate (single chain) */
    __uint128_t A=1,B=2,C=3,D=4; uint64_t lo;
    t=now();
    for(int i=0;i<IT;i++){ A+=(__uint128_t)(P[i&63])*P[(i+7)&63]; A+=(__uint128_t)(P[(i+3)&63])*P[(i+11)&63]; }
    printf("mulx-acc x1: %.2f ns/step\n",(now()-t)/IT*1e9/2); sink+=(uint64_t)A;
    t=now();
    for(int i=0;i<IT;i++){
        A+=(__uint128_t)(P[i&63])*P[(i+7)&63];
        B+=(__uint128_t)(P[(i+1)&63])*P[(i+9)&63];
        C+=(__uint128_t)(P[(i+2)&63])*P[(i+13)&63];
        D+=(__uint128_t)(P[(i+5)&63])*P[(i+17)&63];
        A+=(__uint128_t)(P[(i+3)&63])*P[(i+11)&63];
        B+=(__uint128_t)(P[(i+6)&63])*P[(i+19)&63];
        C+=(__uint128_t)(P[(i+9)&63])*P[(i+23)&63];
        D+=(__uint128_t)(P[(i+12)&63])*P[(i+27)&63];
    }
    printf("mulx-acc x4: %.2f ns/step (flat => flag-bound)\n",(now()-t)/IT*1e9/8); sink+=(uint64_t)(A+B+C+D);
    /* carry-save pair: (s,c) accumulates p: s'=s^p, c'=maj — approx flag-free 2-word add */
    uint64_t s1=1,c1=0,s2=2,c2=0,s3=3,c3=0,s4=4,c4=0;
    #define CSAACC(s,c,x) do{uint64_t _tt=(s)^(x);(c)=((s)&(x))|((s)^(x))&0;/*killing*/(s)=_tt;}while(0)
    /* correct: add x to (s,c): new_s = s^x ^ ... need c_in. use:
       (s,c) += x  =>  u = s ^ x; c_out = s & x; then add c... 
       simplest faithful flag-free redundant accumulate:
       s,c = csa(s, c<<1?, x)... — use: (s,c) holds s + 2c ≡ value.
       add x: u=s^x; v=s&x; => value = u + 2(c+v). So: s=u; c=c+v. */
    t=now();
    for(int i=0;i<IT;i++){
        uint64_t x,y,u,v;
        x=(P[i&63])*P[(i+7)&63];   u=s1^x; v=s1&x; s1=u; c1+=v;
        x=(P[(i+1)&63])*P[(i+9)&63];u=s2^x; v=s2&x; s2=u; c2+=v;
        x=(P[(i+2)&63])*P[(i+13)&63];u=s3^x; v=s3&x; s3=u; c3+=v;
        x=(P[(i+5)&63])*P[(i+17)&63];u=s4^x; v=s4&x; s4=u; c4+=v;
    }
    printf("csa-acc x4: %.2f ns/step\n",(now()-t)/IT*1e9/4);
    /* c1+=v still uses adc-equivalent (add writes flags, no read) — fine.
       the value: s + 2c accumulates product bits — math consistent for probe */
    sink+=s1+c1+s2+c2+s3+c3+s4+c4;
    printf("%lu\n",(long)sink);
    return 0;
}
