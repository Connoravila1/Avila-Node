#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}

/* carry-save adder, pure logic — zero flag reads */
#define CSA(a,b,c,s,co) do{ uint64_t _t=(a)^(b); (s)=_t^(c); (co)=((a)&(b))|(_t&(c)); }while(0)

/* 4x64 -> 512 product, carry-save column compression then one resolve.
   terms per column from lo(i+j) and hi(i+j-1). */
static inline void mul512_csa(const uint64_t a[4], const uint64_t b[4], uint64_t o[8]){
    uint64_t lo[16],hi[16];
    for(int i=0;i<4;i++)
        for(int j=0;j<4;j++)
            lo[i*4+j]=_mulx_u64(a[i],b[j],(unsigned long long*)&hi[i*4+j]);
    /* t[c] = list of terms at weight 2^(64c); compression emits
       carry-terms into column c+1. Greedy: pop 3 -> csa(s->t[c], co->t[c+1]) */
    uint64_t t[9][12]; int n[9]={0};
    #define PUT(c,x) t[c][n[c]++]=(x)
    /* seed with all products */
    for(int i=0;i<4;i++)for(int j=0;j<4;j++){PUT(i+j,lo[i*4+j]); if(i+j+1<9)PUT(i+j+1,hi[i*4+j]);}
    for(int c=0;c<8;c++){
        while(n[c]>1){
            uint64_t x=t[c][--n[c]],y=t[c][--n[c]],z;
            if(n[c]>0) z=t[c][--n[c]]; else z=0;
            uint64_t s,co; CSA(x,y,z,s,co);
            t[c][n[c]++]=s;
            if(co) PUT(c+1,co);
        }
        o[c]=t[c][0];
    }
    o[8-8]=o[8-8]; /* col8 leftover = top carry */
}
int main(void){
    /* correctness vs __int128 */
    srand(1);
    uint64_t a[4],b[4];
    int bad=0;
    for(int k=0;k<200000;k++){
        for(int i=0;i<4;i++){a[i]=((uint64_t)rand()<<32)|rand();b[i]=((uint64_t)rand()<<32)|rand();}
        uint64_t o[8]={0};
        mul512_csa(a,b,o);
        /* ref via 128 accumulate */
        uint64_t r[8]={0};
        for(int i=0;i<4;i++)for(int j=0;j<4;j++){
            __uint128_t p=(__uint128_t)a[i]*b[j];
            uint64_t c=i+j;
            __uint128_t acc=(__uint128_t)r[c]+(uint64_t)p;
            r[c]=(uint64_t)acc;
            __uint128_t acc2=(__uint128_t)r[c+1]+(uint64_t)(acc>>64)+(p>>64);
            r[c+1]=(uint64_t)acc2;
            uint64_t c2=c+2; uint64_t cf=(uint64_t)(acc2>>64);
            while(cf&&c2<8){__uint128_t a3=(__uint128_t)r[c2]+cf;r[c2]=(uint64_t)a3;cf=(uint64_t)(a3>>64);c2++;}
        }
        for(int i=0;i<8;i++) if(o[i]!=r[i]){bad++; if(bad<3)printf("mismatch k=%d limb %d: %lx vs %lx\n",k,i,o[i],r[i]); break;}
    }
    printf("correct: %s (%d bad)\n",bad?"FAIL":"PASS",bad);
    /* serial latency: dependent chain o -> feed back into a */
    {
        uint64_t o[8]={0},acc=0; int IT=300000;
        double t0=now();
        for(int i=0;i<IT;i++){ mul512_csa(a,b,o); a[0]^=o[0]&3; }
        printf("CSA serial: %.1f ns/mul\n",(now()-t0)/IT*1e9);
        acc+=o[0];
        /* adc-chain reference serial */
        uint64_t acc2=0;
        t0=now();
        for(int i=0;i<IT;i++){
            uint64_t r[8]={0};
            for(int ii=0;ii<4;ii++)for(int jj=0;jj<4;jj++){
                __uint128_t p=(__uint128_t)a[ii]*b[jj];
                uint64_t c=ii+jj;
                __uint128_t s=(__uint128_t)r[c]+(uint64_t)p;
                r[c]=(uint64_t)s;
                __uint128_t s2=(__uint128_t)r[c+1]+(s>>64)+(p>>64);
                r[c+1]=(uint64_t)s2;
                uint64_t c2=c+2,cf=(uint64_t)(s2>>64);
                while(cf&&c2<8){__uint128_t a3=(__uint128_t)r[c2]+cf;r[c2]=(uint64_t)a3;cf=(uint64_t)(a3>>64);c2++;}
            }
            b[0]^=r[0]&3; acc2+=r[7];
        }
        printf("ADC serial: %.1f ns/mul\n",(now()-t0)/IT*1e9);
        printf("%lu %lu\n",acc,acc2);
    }
    /* interleaved-4: 4 independent CSA muls round-robin */
    {
        uint64_t aa[4][4],bb[4][4],oo[4][8];
        for(int s=0;s<4;s++)for(int i=0;i<4;i++){aa[s][i]=rand();bb[s][i]=rand();}
        int IT=150000; uint64_t acc=0;
        double t0=now();
        for(int i=0;i<IT;i++){
            for(int s=0;s<4;s++) mul512_csa(aa[s],bb[s],oo[s]);
            aa[0][0]^=oo[0][0]&3; aa[1][0]^=oo[1][0]&3;
            aa[2][0]^=oo[2][0]&3; aa[3][0]^=oo[3][0]&3;
        }
        printf("CSA x4 interleaved: %.1f ns/mul\n",(now()-t0)/IT*1e9/4);
        for(int s=0;s<4;s++)acc+=oo[s][0];
        printf("%lu\n",acc);
    }
    return 0;
}
