/* reproduce the failing fused lane-add in isolation, bisect intermediates */
#define USE_FIELD_10X26 1
#define USE_NUM_NONE 1
#define USE_SCALAR_8X32 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SCHNORRSIG 1
#define SECP256K1_CONTEXT_NONE 1
#define VERIFY 1
#define SECP256K1_BUILD 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <immintrin.h>
#include <fenv.h>
#include "secp256k1.c"
#define S(x) rustsecp256k1_v0_10_0_##x
typedef __m256i vi;
typedef __m256d vd;
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
static inline void fold16C(vi out, vi *lo, vi *hi){
    vd od=i2d(out);
    vd c16=_mm256_set1_pd((double)(16ULL*0x1000003D1ULL));
    vd h=_mm256_fmadd_pd(od,c16,_mm256_set1_pd(0x1p104));
    vd ad=_mm256_sub_pd(_mm256_set1_pd(0x1p104+0x1p52),h);
    vd l=_mm256_fmadd_pd(od,c16,ad);
    *hi=_mm256_sub_epi64(_mm256_castpd_si256(h),_mm256_set1_epi64x(B_HI));
    *lo=d2bits(l);
}
static inline vi mulC_small(vi x){
    vi lo=_mm256_mul_epu32(x,_mm256_set1_epi64x(977));
    vi hi=_mm256_slli_epi64(x,32);
    return _mm256_add_epi64(lo,hi);
}
static inline void fe4_norm(fe4 t){
    vi m52=M52v,m48=M48v; vi c;
    c=_mm256_srli_epi64(t[0],52); t[0]=_mm256_and_si256(t[0],m52); t[1]=_mm256_add_epi64(t[1],c);
    c=_mm256_srli_epi64(t[1],52); t[1]=_mm256_and_si256(t[1],m52); t[2]=_mm256_add_epi64(t[2],c);
    c=_mm256_srli_epi64(t[2],52); t[2]=_mm256_and_si256(t[2],m52); t[3]=_mm256_add_epi64(t[3],c);
    c=_mm256_srli_epi64(t[3],52); t[3]=_mm256_and_si256(t[3],m52); t[4]=_mm256_add_epi64(t[4],c);
    vi c4=_mm256_srli_epi64(t[4],48); t[4]=_mm256_and_si256(t[4],m48);
    for(int it=0;it<2;it++){
        vi g=mulC_small(c4);
        vi x=_mm256_add_epi64(t[0],_mm256_and_si256(g,m52));
        t[0]=_mm256_and_si256(x,m52);
        vi cc=_mm256_add_epi64(_mm256_srli_epi64(x,52),_mm256_srli_epi64(g,52));
        x=_mm256_add_epi64(t[1],cc); t[1]=_mm256_and_si256(x,m52); cc=_mm256_srli_epi64(x,52);
        x=_mm256_add_epi64(t[2],cc); t[2]=_mm256_and_si256(x,m52); cc=_mm256_srli_epi64(x,52);
        x=_mm256_add_epi64(t[3],cc); t[3]=_mm256_and_si256(x,m52); cc=_mm256_srli_epi64(x,52);
        x=_mm256_add_epi64(t[4],cc); t[4]=_mm256_and_si256(t[4],m48); c4=_mm256_srli_epi64(x,48);
    }
}
static inline void fe4_add(fe4 r, const fe4 a, const fe4 b){
    for(int i=0;i<5;i++)r[i]=_mm256_add_epi64(a[i],b[i]);
    fe4_norm(r);
}
static const uint64_t FE4_P4[5] = {
    0xFFFFBFFFFF0BCULL, 0xFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFULL, 0x3FFFFFFFFFFFFULL
};
static inline void fe4_neg(fe4 r, const fe4 a){
    vi bor=_mm256_setzero_si256(), one=_mm256_set1_epi64x(1);
    vi base=_mm256_set1_epi64x(1LL<<52);
    for(int i=0;i<5;i++){
        vi av=_mm256_add_epi64(a[i],bor);
        vi d=_mm256_sub_epi64(_mm256_set1_epi64x(FE4_P4[i]),av);
        vi msk=_mm256_cmpgt_epi64(av,_mm256_set1_epi64x(FE4_P4[i]));
        r[i]=_mm256_add_epi64(d,_mm256_and_si256(msk,base));
        bor=_mm256_and_si256(msk,one);
    }
    fe4_norm(r);
}
#include "ezw_body.c"

typedef struct { fe4 x,y,z; } gej4;
typedef struct { fe4 x,y; } ge4;
static inline void fe4_sub(fe4 r, const fe4 a, const fe4 b){
    fe4 nb; fe4_neg(nb,b); fe4_add(r,a,nb);
}

static void pv(const char *n, const uint64_t x[5]){
    printf("  %s=%llx %llx %llx %llx %llx\n",n,
        (unsigned long long)x[0],(unsigned long long)x[1],
        (unsigned long long)x[2],(unsigned long long)x[3],
        (unsigned long long)x[4]);
}
/* extract lane l limbs */
static void ln(fe4 v, int l, uint64_t o[5]){
    int64_t t[4]; int i;
    for(i=0;i<5;i++){
        _mm256_storeu_si256((vi*)t,v[i]);
        o[i]=(uint64_t)t[l];
    }
}

/* scalar fe from limbs */
static S(fe) sfe(const uint64_t x[5]){
    S(fe) f; int i;
    memset(&f,0,sizeof f);
    for(i=0;i<5;i++) f.n[i]=x[i];
    f.magnitude=1; f.normalized=0;
    return f;
}
static void checkf(const char *n, fe4 v, int l, const S(fe) *want){
    uint64_t o[5]; S(fe) w=*want; int i;
    ln(v,l,o);
    /* mod-p compare via normalizes_to_zero */
    { S(fe) m=sfe(o),d;
      S(fe_negate)(&d,&m,16); S(fe_add)(&d,&w);
      i=S(fe_normalizes_to_zero_var)(&d);
      printf("%s: %s\n",n,i?"EQ":"NE");
    }
    (void)w;
}

int main(void){
    fesetround(FE_TOWARDZERO);
    /* sanity: fe4_sqr4 on small input */
    {
        fe4 v,r4s; int i; S(fe) sv,sr;
        for(i=0;i<5;i++) v[i]=_mm256_set1_epi64x(i==0?7:0);
        fe4_sqr4(r4s,v);
        { uint64_t o[5]; ln(r4s,0,o);
          printf("sqr(7) limb0=%llx\n",(unsigned long long)o[0]); }
        memset(&sv,0,sizeof sv); sv.n[0]=7; sv.magnitude=1;
        S(fe_sqr)(&sr,&sv); S(fe_normalize)(&sr);
        printf("want limb0=%llx\n",(unsigned long long)sr.n[0]);
        /* fe4_mul4 sanity */
        fe4_mul4(r4s,v,v);
        { uint64_t o[5]; ln(r4s,0,o);
          printf("mul(7,7) limb0=%llx\n",(unsigned long long)o[0]); }
    }
    /* crafted round-boundary products */
    {
        uint64_t tv[][2]={
            {0xFFFFFFFFFFFFFULL,0x4000000000000ULL},   /* P mod 2^52 = 3*2^50 -> round UP */
            {0xFFFFFFFFFFFFFULL,0x8000000000002ULL},   /* P mod 2^52 ~ 2^51 -> boundary */
            {0xFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFULL},
            {0xaf5f6eb335552ULL,0xc5813a65683eaULL},   /* the real nz pair */
            {0xFFFFFFFFFFFFFULL,0x8000000000000ULL},
        };
        int k;
        for(k=0;k<5;k++){
            fe4 va,vb,rr; int i; uint64_t o[5];
            S(fe) sa,sb,sr,d;
            for(i=0;i<5;i++){
                va[i]=_mm256_set1_epi64x(i==0?(int64_t)tv[k][0]:0);
                vb[i]=_mm256_set1_epi64x(i==0?(int64_t)tv[k][1]:0);
            }
            fe4_mul4(rr,va,vb); ln(rr,0,o);
            memset(&sa,0,sizeof sa);sa.n[0]=tv[k][0];sa.magnitude=1;
            memset(&sb,0,sizeof sb);sb.n[0]=tv[k][1];sb.magnitude=1;
            S(fe_mul)(&sr,&sa,&sb);
            { S(fe) m=sfe(o);
              S(fe_negate)(&d,&m,16); S(fe_add)(&d,&sr);
              i=S(fe_normalizes_to_zero_var)(&d); }
            printf("mul k=%d %llx*%llx: %s\n",k,
              (unsigned long long)tv[k][0],(unsigned long long)tv[k][1],
              i?"EQ":"NE");
        }
    }
    /* bisect: sqr on nz with progressively more limbs enabled */
    {
        uint64_t nz[5]={0xaf5f6eb335552ULL,0xc5813a65683eaULL,
                        0xbee42c45e2cc3ULL,0x800097c2e572cULL,0x99bcab51d5e3ULL};
        int mask;
        for(mask=1;mask<32;mask=(mask<<1)|1){
            fe4 v,r4s; int i; S(fe) sv,sr,d; uint64_t o[5];
            memset(&sv,0,sizeof sv); sv.magnitude=1;
            for(i=0;i<5;i++){
                uint64_t x=(mask>>i&1)?nz[i]:0;
                v[i]=_mm256_set1_epi64x((int64_t)x);
                sv.n[i]=x;
            }
            fe4_sqr4(r4s,v); ln(r4s,0,o);
            { S(fe) m=sfe(o);
              S(fe_sqr)(&sr,&sv);
              S(fe_negate)(&d,&m,16); S(fe_add)(&d,&sr);
              i=S(fe_normalizes_to_zero_var)(&d);
              if(!i){ int j;S(fe_normalize)(&sr);
                printf("  got :");for(j=0;j<5;j++)printf("%llx ",(unsigned long long)o[j]);
                printf("\n  want:");for(j=0;j<5;j++)printf("%llx ",(unsigned long long)sr.n[j]);
                printf("\n"); } }
            printf("sqr mask=%02x: %s\n",mask,i?"EQ":"NE");
        }
    }
    /* W11 BAD lane3 bucket20: nn = -? bucket entry, pq = point */
    uint64_t nz[5]={0xaf5f6eb335552ULL,0xc5813a65683eaULL,
                    0xbee42c45e2cc3ULL,0x800097c2e572cULL,0x99bcab51d5e3ULL};
    uint64_t nx[5]={0xc626c07f6915ULL,0xebff72641f1a7ULL,
                    0x7efa1df3f0da3ULL,0x9c3f28ddba9f7ULL,0xd5bc978ed68aULL};
    uint64_t ny[5]={0x30e9fa9109c64ULL,0xdd5195d1dc6a8ULL,
                    0xeeb21b236f04cULL,0xc49c148d74262ULL,0x6e72cec0694eULL};
    uint64_t px[5]={0x556031a056cc7ULL,0xa03fb22798e67ULL,
                    0x4b4c2f89830c6ULL,0x67243ab8b2e3ULL,0x13df2f7305d2ULL};
    uint64_t py[5]={0x8355fcad982daULL,0x791e35daecb8cULL,
                    0x375be8bbaf0cULL,0x8d708b7282e43ULL,0xe462e8b7d2e6ULL};
    int i,j;
    gej4 a4,r4; ge4 b4;
    /* load lane3 = bad lane; fill lanes 0-2 with the same values for iso */
    for(j=0;j<4;j++){
        for(i=0;i<5;i++){
            int64_t t[4]; int l2;
            /* build vector with lane j = value */
            _mm256_storeu_si256((vi*)t,a4.x[i]);
            t[j]=(int64_t)nx[i]; a4.x[i]=_mm256_loadu_si256((vi*)t);
            _mm256_storeu_si256((vi*)t,a4.y[i]);
            t[j]=(int64_t)ny[i]; a4.y[i]=_mm256_loadu_si256((vi*)t);
            _mm256_storeu_si256((vi*)t,a4.z[i]);
            t[j]=(int64_t)nz[i]; a4.z[i]=_mm256_loadu_si256((vi*)t);
            _mm256_storeu_si256((vi*)t,b4.x[i]);
            t[j]=(int64_t)px[i]; b4.x[i]=_mm256_loadu_si256((vi*)t);
            _mm256_storeu_si256((vi*)t,b4.y[i]);
            t[j]=(int64_t)py[i]; b4.y[i]=_mm256_loadu_si256((vi*)t);
        }
    }
    /* scalar reference intermediates */
    {
        S(fe) X=sfe(nx),Y=sfe(ny),Z=sfe(nz),BX=sfe(px),BY=sfe(py);
        S(fe) z12,u2,s2,h,ii,h2,h3,t,rx,ry,rz;
        S(fe_sqr)(&z12,&Z);
        S(fe_mul)(&u2,&BX,&z12);
        S(fe_mul)(&s2,&BY,&z12); S(fe_mul)(&s2,&s2,&Z);
        S(fe_negate)(&h,&X,1); S(fe_add)(&h,&u2);
        S(fe_negate)(&ii,&s2,1); S(fe_add)(&ii,&Y);
        S(fe_mul)(&rz,&Z,&h);
        S(fe_sqr)(&h2,&h); S(fe_negate)(&h2,&h2,1);
        S(fe_mul)(&h3,&h2,&h);
        S(fe_mul)(&t,&X,&h2);
        S(fe_sqr)(&rx,&ii);
        S(fe_add)(&rx,&h3); S(fe_add)(&rx,&t); S(fe_add)(&rx,&t);
        S(fe_add)(&t,&rx);
        S(fe_mul)(&ry,&t,&ii);
        S(fe_mul)(&h3,&h3,&Y);
        S(fe_add)(&ry,&h3);
        /* fused lane-0 intermediates */
        { fe4 z12b,u2b,s2b,hb,ib,h2b,h3b,tb;
          { uint64_t o[5]; ln(a4.z,0,o);
            printf("a4.z lane0: ");int j;for(j=0;j<5;j++)printf("%llx ",(unsigned long long)o[j]);printf("\n");
            printf("nz       : ");for(j=0;j<5;j++)printf("%llx ",(unsigned long long)nz[j]);printf("\n"); }
          fe4_sqr4(z12b,a4.z); checkf("z12",z12b,0,&z12);
          fe4_mul4(u2b,b4.x,z12b); checkf("u2",u2b,0,&u2);
          fe4_mul4(s2b,b4.y,z12b); fe4_mul4(s2b,s2b,a4.z);
          checkf("s2",s2b,0,&s2);
          fe4_sub(hb,u2b,a4.x); checkf("h",hb,0,&h);
          fe4_sub(ib,a4.y,s2b); checkf("i",ib,0,&ii);
          fe4_mul4(r4.z,a4.z,hb); checkf("r.z",r4.z,0,&rz);
          { S(fe) h2s; uint64_t o[5]; int j;
            S(fe_sqr)(&h2s,&h);
            fe4_sqr4(h2b,hb); checkf("h2pre",h2b,0,&h2s);
            ln(h2b,0,o); printf("h2sqr limb:");for(j=0;j<5;j++)printf(" %llx",(unsigned long long)o[j]);printf("\n");
            fe4_neg(h2b,h2b); checkf("h2",h2b,0,&h2);
            ln(h2b,0,o); printf("h2neg limb:");for(j=0;j<5;j++)printf(" %llx",(unsigned long long)o[j]);printf("\n"); }
          fe4_mul4(h3b,h2b,hb); checkf("h3",h3b,0,&h3);
          fe4_mul4(tb,a4.x,h2b); checkf("t",tb,0,&t);
          fe4_sqr4(r4.x,ib); fe4_add(r4.x,r4.x,h3b);
          fe4_add(r4.x,r4.x,tb); fe4_add(r4.x,r4.x,tb);
          checkf("r.x",r4.x,0,&rx);
          fe4_add(tb,tb,r4.x);
          fe4_mul4(r4.y,tb,ib); fe4_mul4(h3b,h3b,a4.y);
          fe4_add(r4.y,r4.y,h3b); checkf("r.y",r4.y,0,&ry);
        }
    }
    return 0;
}
