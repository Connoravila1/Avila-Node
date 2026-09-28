/* MIT-licensed research harness, not linked into Avila Node.
 *
 * MSM cost probe: what does a fused-4 Jacobian+affine add cost per lane
 * when the adds are INDEPENDENT (MSM bucket accumulation), versus the
 * scalar secp256k1_5x52 path? Bucket adds into a memory-resident table
 * are the real access pattern — the ladder's serial-chain timing does not
 * apply.
 *
 *   1. correctness: gej4_add_ge4 vs scalar gej_add_ge_var, compared in
 *      AFFINE coordinates (Jacobian scalings differ legitimately).
 *   2. serial fused-4 add latency (chained dependency).
 *   3. K interleaved independent fused-4 streams, K in {1,2,4} — the
 *      ROB-overlap question the ledger left open.
 *   4. bucket-table mock: gather 4 scalar gej buckets -> gej4, add,
 *      scatter back — the real Pippenger access pattern.
 *   5. scalar equivalents for all of the above.
 *
 * Build: same recipe as msm_decomp_bench.c (see that header).
 * Run under tools/guard_run.sh --max 2048, pinned core.
 */
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
static inline void fe4_load(fe4 t, const uint64_t a[4][5]){
    for(int i=0;i<5;i++)
        t[i]=_mm256_set_epi64x(a[3][i],a[2][i],a[1][i],a[0][i]);
}
static inline void fe4_store(uint64_t r[4][5], const fe4 t){
    int64_t tmp[4];
    for(int i=0;i<5;i++){_mm256_storeu_si256((vi*)tmp,t[i]);for(int l=0;l<4;l++)r[l][i]=(uint64_t)tmp[l];}
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
    /* base-2^52 borrow: wrapped limbs need +2^52, not the raw 2^64 word. */
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
static inline void fe4_mul_int(fe4 r, const fe4 a, int k){
    vi kk=_mm256_set1_epi64x(k),m32=_mm256_set1_epi64x(0xffffffff);
    for(int i=0;i<5;i++){
        vi alo=_mm256_and_si256(a[i],m32);
        vi ahi=_mm256_srli_epi64(a[i],32);
        r[i]=_mm256_add_epi64(_mm256_mul_epu32(alo,kk),
              _mm256_slli_epi64(_mm256_mul_epu32(ahi,kk),32));
    }
    fe4_norm(r);
}
static inline void fe4_half(fe4 r, const fe4 a){
    vi odd=_mm256_and_si256(a[0],_mm256_set1_epi64x(1));
    vi usep=_mm256_cmpeq_epi64(odd,_mm256_set1_epi64x(1));
    vi p0=_mm256_and_si256(usep,_mm256_set1_epi64x(0xFFFFEFFFFFC2FULL));
    vi p1=_mm256_and_si256(usep,_mm256_set1_epi64x(0xFFFFFFFFFFFFFULL));
    vi p4=_mm256_and_si256(usep,_mm256_set1_epi64x(0xFFFFFFFFFFFFULL));
    vi t0=_mm256_add_epi64(a[0],p0), t1=_mm256_add_epi64(a[1],p1);
    vi t2=_mm256_add_epi64(a[2],p1), t3=_mm256_add_epi64(a[3],p1);
    vi t4=_mm256_add_epi64(a[4],p4);
    vi c;
    c=_mm256_srli_epi64(t0,52); t0=_mm256_and_si256(t0,M52v); t1=_mm256_add_epi64(t1,c);
    c=_mm256_srli_epi64(t1,52); t1=_mm256_and_si256(t1,M52v); t2=_mm256_add_epi64(t2,c);
    c=_mm256_srli_epi64(t2,52); t2=_mm256_and_si256(t2,M52v); t3=_mm256_add_epi64(t3,c);
    c=_mm256_srli_epi64(t3,52); t3=_mm256_and_si256(t3,M52v); t4=_mm256_add_epi64(t4,c);
    r[0]=_mm256_or_si256(_mm256_srli_epi64(t0,1),
          _mm256_slli_epi64(_mm256_and_si256(t1,_mm256_set1_epi64x(1)),51));
    r[1]=_mm256_or_si256(_mm256_srli_epi64(t1,1),
          _mm256_slli_epi64(_mm256_and_si256(t2,_mm256_set1_epi64x(1)),51));
    r[2]=_mm256_or_si256(_mm256_srli_epi64(t2,1),
          _mm256_slli_epi64(_mm256_and_si256(t3,_mm256_set1_epi64x(1)),51));
    r[3]=_mm256_or_si256(_mm256_srli_epi64(t3,1),
          _mm256_slli_epi64(_mm256_and_si256(t4,_mm256_set1_epi64x(1)),51));
    r[4]=_mm256_srli_epi64(t4,1);
}
#include "ezw_body.c"

typedef struct { fe4 x,y,z; } gej4;
typedef struct { fe4 x,y; } ge4;
static inline void fe4_sub(fe4 r, const fe4 a, const fe4 b){
    fe4 nb; fe4_neg(nb,b); fe4_add(r,a,nb);
}
static void gej4_add_ge4(gej4 *r, const gej4 *a, const ge4 *b){
    fe4 z12,u2,s2,h,i,h2,h3,t;
    fe4_sqr4(z12,a->z);
    fe4_mul4(u2,b->x,z12);
    fe4_mul4(s2,b->y,z12);
    fe4_mul4(s2,s2,a->z);
    fe4_sub(h,u2,a->x);
    fe4_sub(i,a->y,s2);
    fe4_mul4(r->z,a->z,h);
    fe4_sqr4(h2,h);
    fe4_neg(h2,h2);
    fe4_mul4(h3,h2,h);
    fe4_mul4(t,a->x,h2);
    fe4_sqr4(r->x,i);
    fe4_add(r->x,r->x,h3);
    fe4_add(r->x,r->x,t);
    fe4_add(r->x,r->x,t);
    fe4_add(t,t,r->x);
    fe4_mul4(r->y,t,i);
    fe4_mul4(h3,h3,a->y);
    fe4_add(r->y,r->y,h3);
}

/* affine equality check: gej (x,y,z) ~ (x/z^2, y/z^3) */
static int gej_eq_affine(const S(gej) *a, const S(ge) *b){
    S(fe) zi,zi2,x2,y2;
    S(gej) an=*a;
    S(fe_inv_var)(&zi,&an.z);
    S(fe_sqr)(&zi2,&zi);
    S(fe_mul)(&x2,&an.x,&zi2);
    S(fe_mul)(&zi2,&zi2,&zi);
    S(fe_mul)(&y2,&an.y,&zi2);
    S(fe_normalize)(&x2); S(fe_normalize)(&y2);
    { S(ge) bn=*b; S(fe_normalize)(&bn.x); S(fe_normalize)(&bn.y);
      return !memcmp(x2.n,bn.x.n,40) && !memcmp(y2.n,bn.y.n,40); }
}

static void rand_scalar(S(scalar) *s, uint64_t seed){
    unsigned char b[32];
    S(sha256) h;
    int ov;
    S(sha256_initialize)(&h);
    S(sha256_write)(&h,(unsigned char*)&seed,8);
    S(sha256_write)(&h,(unsigned char*)&seed,8);
    S(sha256_finalize)(&h,b);
    do { S(scalar_set_b32)(s,b,&ov); b[0]++; } while(ov||S(scalar_is_zero)(s));
}

/* k*G as gej: ecmult(r,a,na,ng) = na*a + ng*G -> na=0 (a still read) */
static void kG(S(gej) *r, uint64_t seed){
    S(scalar) k,zero;
    S(gej) gj;
    rand_scalar(&k,seed);
    S(scalar_set_int)(&zero,0);
    S(gej_set_ge)(&gj,&S(ge_const_g));
    S(ecmult)(r,&gj,&zero,&k);
}

static void gej_to_ge(S(ge) *out, const S(gej) *a){
    S(fe) zinv;
    S(fe_inv_var)(&zinv,&a->z);
    S(ge_set_gej_zinv)(out,a,&zinv);
}

int main(void){
    fesetround(FE_TOWARDZERO);
    const int NPOINTS=1024;
    S(gej) *pts=calloc(NPOINTS,sizeof(S(gej)));
    S(ge)  *aff=calloc(NPOINTS,sizeof(S(ge)));
    for(int i=0;i<NPOINTS;i++){
        S(gej) g;
        kG(&pts[i],0x1234+i);
        kG(&g,0x9999+i); gej_to_ge(&aff[i],&g);
    }

    /* ---------- 1. correctness of gej4_add_ge4 (affine compare) ------ */
    {
        int bad=0,degen=0,realbad=0;
        for(int t=0;t<4000;t++){
            uint64_t ax[4][5],ay[4][5],az[4][5],bx[4][5],by[4][5];
            uint64_t ox[4][5],oy[4][5],oz[4][5];
            S(gej) ref[4];
            for(int l=0;l<4;l++){
                const S(gej) *a=&pts[(t*4+l)%NPOINTS];
                const S(ge)  *b=&aff[(t*7+l*3)%NPOINTS];
                S(gej) an=*a;
                S(fe_normalize)(&an.x); S(fe_normalize)(&an.y); S(fe_normalize)(&an.z);
                for(int i=0;i<5;i++){ax[l][i]=an.x.n[i];ay[l][i]=an.y.n[i];az[l][i]=an.z.n[i];}
                S(ge) bn=*b; S(fe_normalize)(&bn.x); S(fe_normalize)(&bn.y);
                for(int i=0;i<5;i++){bx[l][i]=bn.x.n[i];by[l][i]=bn.y.n[i];}
                S(gej_add_ge_var)(&ref[l],a,b,NULL);
            }
            gej4 a4,r4; ge4 b4;
            fe4_load(a4.x,(const uint64_t(*)[5])ax);
            fe4_load(a4.y,(const uint64_t(*)[5])ay);
            fe4_load(a4.z,(const uint64_t(*)[5])az);
            fe4_load(b4.x,(const uint64_t(*)[5])bx);
            fe4_load(b4.y,(const uint64_t(*)[5])by);
            gej4_add_ge4(&r4,&a4,&b4);
            fe4_store(ox,r4.x); fe4_store(oy,r4.y); fe4_store(oz,r4.z);
            for(int l=0;l<4;l++){
                S(gej) f4;
                S(ge) af_ref;
                for(int i=0;i<5;i++){f4.x.n[i]=ox[l][i];f4.y.n[i]=oy[l][i];f4.z.n[i]=oz[l][i];}
                f4.infinity=0;
                gej_to_ge(&af_ref,&ref[l]);
                if(!gej_eq_affine(&f4,&af_ref)){
                    int z0=0, zp=0;
                    static const uint64_t pl[5]={0xFFFFEFFFFFC2FULL,0xFFFFFFFFFFFFFULL,
                      0xFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFULL};
                    for(int i=0;i<5;i++){ if(oz[l][i]==0)z0++; }
                    for(int i=0;i<5;i++){ if(oz[l][i]==pl[i])zp++; }
                    if(z0==5||zp==5)degen++; else realbad++;
                    bad++;
                }
            }
        }
        printf("add4 correctness: %d bad / 16000 = %d degenerate, %d real errors\n",
               bad,degen,realbad);
    }

    /* ---------- 2. serial fused-4 add vs serial scalar add ---------- */
    {
        int ITERS=20000;
        uint64_t ax[4][5],ay[4][5],az[4][5],bx[4][5],by[4][5];
        for(int l=0;l<4;l++){
            S(gej) a=pts[l]; S(fe_normalize)(&a.x);S(fe_normalize)(&a.y);S(fe_normalize)(&a.z);
            for(int i=0;i<5;i++){ax[l][i]=a.x.n[i];ay[l][i]=a.y.n[i];az[l][i]=a.z.n[i];}
            S(ge) b=aff[l]; for(int i=0;i<5;i++){bx[l][i]=b.x.n[i];by[l][i]=b.y.n[i];}
        }
        gej4 a4,r4; ge4 b4;
        fe4_load(a4.x,(const uint64_t(*)[5])ax);
        fe4_load(a4.y,(const uint64_t(*)[5])ay);
        fe4_load(a4.z,(const uint64_t(*)[5])az);
        fe4_load(b4.x,(const uint64_t(*)[5])bx);
        fe4_load(b4.y,(const uint64_t(*)[5])by);
        double t0=now_wall();
        for(int i=0;i<ITERS;i++){ gej4_add_ge4(&r4,&a4,&b4); a4=r4; }
        double d1=now_wall()-t0;
        volatile uint64_t sk=r4.x[0][0];(void)sk;
        printf("serial fused add4 : %7.1f ns/add4 = %6.1f ns/lane-add\n",
               d1/ITERS*1e9, d1/ITERS*1e9/4);
        S(gej) g=pts[0]; S(ge) b=aff[0];
        t0=now_wall();
        for(int i=0;i<ITERS;i++) S(gej_add_ge_var)(&g,&g,&b,NULL);
        double d2=now_wall()-t0;
        volatile uint64_t sk2=g.x.n[0]+g.y.n[0];(void)sk2;
        printf("serial scalar add : %7.1f ns/add  -> fused lane ratio %.2fx\n",
               d2/ITERS*1e9, d2/(d1/4));
    }

    /* ---------- 3. K independent fused-4 streams (ROB overlap test) --- */
    {
        int ITERS=20000;
        uint64_t ax[4][5],ay[4][5],az[4][5],bx[4][5],by[4][5];
        gej4 acc4[4]; ge4 b4;
        for(int str=0;str<4;str++){
            for(int l=0;l<4;l++){
                S(gej) a=pts[(str*4+l)%NPOINTS];
                S(fe_normalize)(&a.x);S(fe_normalize)(&a.y);S(fe_normalize)(&a.z);
                for(int i=0;i<5;i++){ax[l][i]=a.x.n[i];ay[l][i]=a.y.n[i];az[l][i]=a.z.n[i];}
            }
            fe4_load(acc4[str].x,(const uint64_t(*)[5])ax);
            fe4_load(acc4[str].y,(const uint64_t(*)[5])ay);
            fe4_load(acc4[str].z,(const uint64_t(*)[5])az);
        }
        for(int l=0;l<4;l++){
            S(ge) b=aff[l];
            for(int i=0;i<5;i++){bx[l][i]=b.x.n[i];by[l][i]=b.y.n[i];}
        }
        fe4_load(b4.x,(const uint64_t(*)[5])bx);
        fe4_load(b4.y,(const uint64_t(*)[5])by);

        {
            S(gej) sg[4]; for(int j=0;j<4;j++) sg[j]=pts[j];
            S(ge) sb=aff[0];
            double t0=now_wall();
            for(int i=0;i<ITERS;i++)
                for(int j=0;j<4;j++) S(gej_add_ge_var)(&sg[j],&sg[j],&sb,NULL);
            double ds=now_wall()-t0;
            volatile uint64_t s=sg[0].x.n[0];(void)s;
            printf("scalar indep x4   : %7.1f ns/add\n", ds/(ITERS*4)*1e9);
        }
        {
            gej4 tmp0,tmp1,tmp2,tmp3;
            double t0=now_wall();
            for(int i=0;i<ITERS;i++){
                gej4_add_ge4(&tmp0,&acc4[0],&b4); acc4[0]=tmp0;
            }
            double d1=now_wall()-t0;
            volatile uint64_t s=acc4[0].x[0][0];(void)s;
            printf("fused indep x1    : %7.1f ns/add4 = %6.1f ns/lane-add\n",
                   d1/ITERS*1e9, d1/ITERS*1e9/4);
            t0=now_wall();
            for(int i=0;i<ITERS;i++){
                gej4_add_ge4(&tmp0,&acc4[0],&b4); acc4[0]=tmp0;
                gej4_add_ge4(&tmp1,&acc4[1],&b4); acc4[1]=tmp1;
            }
            double d2=now_wall()-t0;
            printf("fused indep x2    : %7.1f ns/add4 = %6.1f ns/lane-add\n",
                   d2/(ITERS*2)*1e9, d2/(ITERS*8)*1e9);
            t0=now_wall();
            for(int i=0;i<ITERS;i++){
                gej4_add_ge4(&tmp0,&acc4[0],&b4); acc4[0]=tmp0;
                gej4_add_ge4(&tmp1,&acc4[1],&b4); acc4[1]=tmp1;
                gej4_add_ge4(&tmp2,&acc4[2],&b4); acc4[2]=tmp2;
                gej4_add_ge4(&tmp3,&acc4[3],&b4); acc4[3]=tmp3;
            }
            double d4=now_wall()-t0;
            printf("fused indep x4    : %7.1f ns/add4 = %6.1f ns/lane-add\n",
                   d4/(ITERS*4)*1e9, d4/(ITERS*16)*1e9);
        }
    }

    /* ---------- 4. bucket-table mock (real MSM access pattern) ------- */
    {
        const int WB=4096;
        const int NTERMS=1<<15;
        int REPS=20;
        uint32_t *idx=calloc(NTERMS,sizeof(uint32_t));
        uint32_t st=0x9e3779b9;
        for(int i=0;i<NTERMS;i++){ st^=st<<13;st^=st>>17;st^=st<<5; idx[i]=st&(WB-1);}

        /* scalar bucket mock */
        {
            S(gej) *stable=calloc(WB,sizeof(S(gej)));
            for(int g=0;g<WB;g++) stable[g]=pts[g%NPOINTS];
            double t0=now_wall();
            for(int r=0;r<REPS;r++){
                for(int i=0;i<NTERMS;i++)
                    S(gej_add_ge_var)(&stable[idx[i]],&stable[idx[i]],
                                      &aff[i%NPOINTS],NULL);
            }
            double d=now_wall()-t0;
            volatile uint64_t s2=stable[0].x.n[0];(void)s2;
            printf("scalar bucket loop : %7.1f ns/add\n",
                   d/(REPS*(double)NTERMS)*1e9);
            free(stable);
        }

        /* fused bucket mock: gather 4 scalar gej buckets -> gej4 -> add
           -> scatter. terms process 4-at-a-time, each to its own bucket. */
        {
            S(gej) *stable=calloc(WB,sizeof(S(gej)));
            for(int g=0;g<WB;g++) stable[g]=pts[g%NPOINTS];
            double t0=now_wall();
            for(int r=0;r<REPS;r++){
                for(int i=0;i<NTERMS;i+=4){
                    gej4 a4,r4; ge4 b4;
                    uint64_t ax[4][5],ay[4][5],az[4][5],bx[4][5],by[4][5];
                    for(int l=0;l<4;l++){
                        S(gej) *bk=&stable[idx[i+l]];
                        S(fe_normalize)(&bk->x);S(fe_normalize)(&bk->y);S(fe_normalize)(&bk->z);
                        for(int j=0;j<5;j++){ax[l][j]=bk->x.n[j];ay[l][j]=bk->y.n[j];az[l][j]=bk->z.n[j];}
                        const S(ge) *b=&aff[(i+l)%NPOINTS];
                        for(int j=0;j<5;j++){bx[l][j]=b->x.n[j];by[l][j]=b->y.n[j];}
                    }
                    fe4_load(a4.x,(const uint64_t(*)[5])ax);
                    fe4_load(a4.y,(const uint64_t(*)[5])ay);
                    fe4_load(a4.z,(const uint64_t(*)[5])az);
                    fe4_load(b4.x,(const uint64_t(*)[5])bx);
                    fe4_load(b4.y,(const uint64_t(*)[5])by);
                    gej4_add_ge4(&r4,&a4,&b4);
                    uint64_t ox[4][5],oy[4][5],oz[4][5];
                    fe4_store(ox,r4.x); fe4_store(oy,r4.y); fe4_store(oz,r4.z);
                    for(int l=0;l<4;l++){
                        S(gej) *bk=&stable[idx[i+l]];
                        for(int j=0;j<5;j++){bk->x.n[j]=ox[l][j];bk->y.n[j]=oy[l][j];bk->z.n[j]=oz[l][j];}
                    }
                }
            }
            double d=now_wall()-t0;
            volatile uint64_t s=stable[0].x.n[0];(void)s;
            printf("fused bucket loop  : %7.1f ns/group = %6.1f ns/lane-add "
                   "(incl gather/scatter)\n",
                   d/(REPS*(double)(NTERMS/4))*1e9, d/(REPS*(double)NTERMS)*1e9);
            free(stable);
        }
        free(idx);
    }
    free(pts); free(aff);
    return 0;
}
