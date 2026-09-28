/* fe_mul4 latency-optimized: memory-resident accumulators,
   column-streaming resolve, minimal live regs. */
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
typedef vi fe4[5];
#define M52v _mm256_set1_epi64x((1LL<<52)-1)
#define M48v _mm256_set1_epi64x((1LL<<48)-1)
static const int64_t B_HI = 0x4670000000000000LL;
static const int64_t B_LO = 0x4330000000000000LL;
static inline vd i2d(vi x){
    vi b=_mm256_add_epi64(x,_mm256_set1_epi64x(B_LO));
    return _mm256_sub_pd(_mm256_castsi256_pd(b),_mm256_set1_pd(0x1p52));
}
static inline vi d2bits(vd x){
    return _mm256_sub_epi64(_mm256_castpd_si256(x),_mm256_set1_epi64x(B_LO));
}
/* products streamed column-order; acc lives as an array (compiler may
   keep hot ones in regs). Resolve interleaved: after col c products,
   its accumulator chain can start while later products compute —
   emit manually so the dependency is visible early. */
#include "v4.inc"
static inline void unused_mul4v3(fe4 r, const fe4 ai, const fe4 bi){
    vd a[5],b[5];
    for(int i=0;i<5;i++){a[i]=i2d(ai[i]);b[i]=i2d(bi[i]);}
    vd C1=_mm256_set1_pd(0x1p104), C2=_mm256_set1_pd(0x1p104+0x1p52);
    static const int np[9]={1,2,3,4,5,4,3,2,1};
    /* acc[c] as explicit locals in memory array — GCC will promote what
       it can; order: for column c, need products (i,j) i+j=c. Walk
       anti-diagonals. acc[9] gets hi-parts of col8 products. */
    int64_t accs[10][4] __attribute__((aligned(32)));
    for(int c=0;c<9;c++){
        int nl=np[c], nh=c?np[c-1]:0;
        _mm256_store_si256((vi*)accs[c],
            _mm256_set1_epi64x(-((int64_t)nl*B_LO+(int64_t)nh*B_HI)));
    }
    _mm256_store_si256((vi*)accs[9],
        _mm256_set1_epi64x(-(int64_t)np[8]*B_HI));
    for(int c=0;c<9;c++)
        for(int i=(c<5?0:c-4);i<5 && i<=c;i++){
            int j=c-i; if(j<0||j>4)continue;
            vd hi=_mm256_fmadd_pd(a[i],b[j],C1);
            vd ad=_mm256_sub_pd(C2,hi);
            vd lo=_mm256_fmadd_pd(a[i],b[j],ad);
            /* lo-bits -> acc[c], hi-bits -> acc[c+1] */
            _mm256_store_si256((vi*)accs[c],
                _mm256_add_epi64(_mm256_load_si256((vi*)accs[c]),
                                 _mm256_castpd_si256(lo)));
            _mm256_store_si256((vi*)accs[c+1],
                _mm256_add_epi64(_mm256_load_si256((vi*)accs[c+1]),
                                 _mm256_castpd_si256(hi)));
        }
    vi O[10],car=_mm256_setzero_si256(),m52=M52v;
    for(int c=0;c<10;c++){
        vi t=_mm256_add_epi64(_mm256_load_si256((vi*)accs[c]),car);
        O[c]=_mm256_and_si256(t,m52);
        car=_mm256_srli_epi64(t,52);
    }
    /* fold high columns c>=5: out*16C (2^260-based) -> low */
    vd c16=_mm256_set1_pd((double)(16ULL*0x1000003D1ULL));
    vi F[6]; for(int i=0;i<6;i++)F[i]=_mm256_setzero_si256();
    for(int c=5;c<10;c++){
        vd od=i2d(O[c]);
        vd h=_mm256_fmadd_pd(od,c16,C1);
        vd ad=_mm256_sub_pd(C2,h);
        vd l=_mm256_fmadd_pd(od,c16,ad);
        F[c-5]=_mm256_add_epi64(F[c-5],d2bits(l));
        F[c-4]=_mm256_add_epi64(F[c-4],
            _mm256_sub_epi64(_mm256_castpd_si256(h),_mm256_set1_epi64x(B_HI)));
    }
    {
        vi x4=_mm256_srli_epi64(O[4],48);
        vi lo=_mm256_mul_epu32(x4,_mm256_set1_epi64x(977));
        vi hi=_mm256_slli_epi64(x4,32);
        vi g=_mm256_add_epi64(lo,hi);
        F[0]=_mm256_add_epi64(F[0],_mm256_and_si256(g,m52));
        F[1]=_mm256_add_epi64(F[1],_mm256_srli_epi64(g,52));
    }
    for(int it=0;it<3;it++){
        vd od=i2d(F[5]);
        vd h=_mm256_fmadd_pd(od,c16,C1);
        vd ad=_mm256_sub_pd(C2,h);
        vd l=_mm256_fmadd_pd(od,c16,ad);
        F[0]=_mm256_add_epi64(F[0],d2bits(l));
        F[1]=_mm256_add_epi64(F[1],
            _mm256_sub_epi64(_mm256_castpd_si256(h),_mm256_set1_epi64x(B_HI)));
        F[5]=_mm256_setzero_si256();
    }
    vi c2=_mm256_setzero_si256(),m48=M48v; { vi t;
        t=_mm256_add_epi64(O[0],F[0]); t=_mm256_add_epi64(t,c2);
        r[0]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[1],F[1]); t=_mm256_add_epi64(t,c2);
        r[1]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[2],F[2]); t=_mm256_add_epi64(t,c2);
        r[2]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(O[3],F[3]); t=_mm256_add_epi64(t,c2);
        r[3]=_mm256_and_si256(t,m52); c2=_mm256_srli_epi64(t,52);
        t=_mm256_and_si256(O[4],m48); t=_mm256_add_epi64(t,F[4]); t=_mm256_add_epi64(t,c2);
        r[4]=_mm256_and_si256(t,m48); c2=_mm256_srli_epi64(t,48);
    }
    for(int it=0;it<2;it++){
        vi lo=_mm256_mul_epu32(c2,_mm256_set1_epi64x(977));
        vi hi=_mm256_slli_epi64(c2,32);
        vi g=_mm256_add_epi64(lo,hi);
        vi t=_mm256_add_epi64(r[0],_mm256_and_si256(g,m52));
        r[0]=_mm256_and_si256(t,m52);
        vi cc=_mm256_add_epi64(_mm256_srli_epi64(t,52),_mm256_srli_epi64(g,52));
        t=_mm256_add_epi64(r[1],cc); r[1]=_mm256_and_si256(t,m52); cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(r[2],cc); r[2]=_mm256_and_si256(t,m52); cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(r[3],cc); r[3]=_mm256_and_si256(t,m52); cc=_mm256_srli_epi64(t,52);
        t=_mm256_add_epi64(r[4],cc); r[4]=_mm256_and_si256(t,m48); c2=_mm256_srli_epi64(t,48);
        (void)c2;
    }
}
static void norm4(uint64_t v[4][5]){
    S(fe) f;
    for(int l=0;l<4;l++){
        for(int i=0;i<5;i++)f.n[i]=v[l][i];
        S(fe_normalize)(&f);
        for(int i=0;i<5;i++)v[l][i]=f.n[i];
    }
}
static void ref_mul(uint64_t r[4][5], const uint64_t a[4][5], const uint64_t b[4][5]){
    S(fe) fa,fb,fr;
    for(int l=0;l<4;l++){
        for(int i=0;i<5;i++){fa.n[i]=a[l][i];fb.n[i]=b[l][i];}
        S(fe_mul)(&fr,&fa,&fb); S(fe_normalize)(&fr);
        for(int i=0;i<5;i++)r[l][i]=fr.n[i];
    }
}
int main(void){
    fesetround(FE_TOWARDZERO);
    srand(1);
    uint64_t a[4][5],b[4][5],r[4][5],rr[4][5];
    int bad=0;
    for(int t=0;t<200000;t++){
        for(int l=0;l<4;l++)
            for(int i=0;i<5;i++){
                a[l][i]=((uint64_t)rand()<<21|rand())&((1ULL<<52)-1);
                b[l][i]=((uint64_t)rand()<<21|rand())&((1ULL<<52)-1);
                if(i==4){a[l][i]&=(1ULL<<48)-1;b[l][i]&=(1ULL<<48)-1;}
            }
        ref_mul(r,(const uint64_t(*)[5])a,(const uint64_t(*)[5])b);
        fe4 av,bv;
        for(int i=0;i<5;i++){
            av[i]=_mm256_set_epi64x(a[3][i],a[2][i],a[1][i],a[0][i]);
            bv[i]=_mm256_set_epi64x(b[3][i],b[2][i],b[1][i],b[0][i]);
        }
        fe4 rv;
        fe4_mul4v4(rv,av,bv);
        int64_t tmp[4];
        for(int i=0;i<5;i++){
            _mm256_storeu_si256((vi*)tmp,rv[i]);
            for(int l=0;l<4;l++)rr[l][i]=(uint64_t)tmp[l];
        }
        norm4(rr);
        if(memcmp(r,rr,sizeof(r))){bad++;if(bad<5){
            printf("mismatch t=%d\n",t);
            for(int l=0;l<1;l++){
                printf("  got :");for(int i=0;i<5;i++)printf(" %013lx",rr[l][i]);
                printf("\n  want:");for(int i=0;i<5;i++)printf(" %013lx",r[l][i]);
                printf("\n");
            }
        }}
    }
    printf("v3 correct: %d/200000\n",200000-bad);
    int ITERS=1000000;
    double t0=now_wall();
    for(int i=0;i<ITERS;i++){
        fe4 av,bv;
        for(int k=0;k<5;k++){
            av[k]=_mm256_set_epi64x(a[3][k],a[2][k],a[1][k],a[0][k]);
            bv[k]=_mm256_set_epi64x(b[3][k],b[2][k],b[1][k],b[0][k]);
        }
        fe4 rv;
        fe4_mul4v4(rv,av,bv);
        int64_t tmp[4];
        for(int k=0;k<5;k++){
            _mm256_storeu_si256((vi*)tmp,rv[k]);
            for(int l=0;l<4;l++)a[l][k]=(uint64_t)tmp[l]^0x1000;
        }
        b[0][0]^=1;
    }
    double d1=now_wall()-t0;
    printf("chain: %.1f ns/group = %.2f ns/mul-equiv\n",d1/ITERS*1e9,d1/ITERS*1e9/4);
    uint64_t aa[4][5],bb[4][5],cc[4][5];
    memcpy(aa,a,sizeof(aa));memcpy(bb,b,sizeof(bb));
    t0=now_wall();
    volatile int64_t acc=0;
    for(int i=0;i<ITERS;i++){
        fe4 av,bv;
        for(int k=0;k<5;k++){
            av[k]=_mm256_set_epi64x(aa[3][k],aa[2][k],aa[1][k],aa[0][k]);
            bv[k]=_mm256_set_epi64x(bb[3][k],bb[2][k],bb[1][k],bb[0][k]);
        }
        fe4 rv;
        fe4_mul4v4(rv,av,bv);
        int64_t tmp[4];
        for(int k=0;k<5;k++){
            _mm256_storeu_si256((vi*)tmp,rv[k]);
            acc+=tmp[k&3];
        }
    }
    double d2=now_wall()-t0;
    printf("indep: %.1f ns/group = %.2f ns/mul-equiv\n",d2/ITERS*1e9,d2/ITERS*1e9/4);
    printf("acc %ld\n",(long)acc);
    return 0;
}
