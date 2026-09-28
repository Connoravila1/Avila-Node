/* MIT-licensed research harness, not linked into Avila Node.
 *
 * Does instruction-level interleaving of two independent fused-4 adds
 * recover the throughput mode (~7-15ns/mul-equiv), or do register spills
 * eat the gain? Whole-formula fusion measured ~270ns/lane-add with 0%
 * overlap for sequential fused ops (>ROB). This probe alternates the
 * FIELD OPS of two adds: every ~450-uop window holds independent work.
 *
 * Build: same recipe as msm_add4_probe.c.
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
static inline void fe4_sub(fe4 r, const fe4 a, const fe4 b){
    fe4 nb; fe4_neg(nb,b); fe4_add(r,a,nb);
}
#include "ezw_body.c"

typedef struct { fe4 x,y,z; } gej4;
typedef struct { fe4 x,y; } ge4;

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

/* Two adds, FIELD-OP interleaved: every ~700-uop mul blob alternates
   chains, so the ROB always holds work from both. */
static void gej4_add_ge4_x2(gej4 *r0, const gej4 *a0, const ge4 *b0,
                            gej4 *r1, const gej4 *a1, const ge4 *b1){
    fe4 z12a,u2a,s2a,ha,ia,h2a,h3a,ta;
    fe4 z12b,u2b,s2b,hb,ib,h2b,h3b,tb;
    fe4_sqr4(z12a,a0->z);      fe4_sqr4(z12b,a1->z);
    fe4_mul4(u2a,b0->x,z12a);  fe4_mul4(u2b,b1->x,z12b);
    fe4_mul4(s2a,b0->y,z12a);  fe4_mul4(s2b,b1->y,z12b);
    fe4_mul4(s2a,s2a,a0->z);   fe4_mul4(s2b,s2b,a1->z);
    fe4_sub(ha,u2a,a0->x);     fe4_sub(hb,u2b,a1->x);
    fe4_sub(ia,a0->y,s2a);     fe4_sub(ib,a1->y,s2b);
    fe4_mul4(r0->z,a0->z,ha);  fe4_mul4(r1->z,a1->z,hb);
    fe4_sqr4(h2a,ha);          fe4_sqr4(h2b,hb);
    fe4_neg(h2a,h2a);          fe4_neg(h2b,h2b);
    fe4_mul4(h3a,h2a,ha);      fe4_mul4(h3b,h2b,hb);
    fe4_mul4(ta,a0->x,h2a);    fe4_mul4(tb,a1->x,h2b);
    fe4_sqr4(r0->x,ia);        fe4_sqr4(r1->x,ib);
    fe4_add(r0->x,r0->x,h3a);  fe4_add(r1->x,r1->x,h3b);
    fe4_add(r0->x,r0->x,ta);   fe4_add(r1->x,r1->x,tb);
    fe4_add(r0->x,r0->x,ta);   fe4_add(r1->x,r1->x,tb);
    fe4_add(ta,ta,r0->x);      fe4_add(tb,tb,r1->x);
    fe4_mul4(r0->y,ta,ia);     fe4_mul4(r1->y,tb,ib);
    fe4_mul4(h3a,h3a,a0->y);   fe4_mul4(h3b,h3b,a1->y);
    fe4_add(r0->y,r0->y,h3a);  fe4_add(r1->y,r1->y,h3b);
}

static void gej_to_ge(S(ge) *out, const S(gej) *a){
    S(fe) zinv;
    S(fe_inv_var)(&zinv,&a->z);
    S(ge_set_gej_zinv)(out,a,&zinv);
}
static void rand_scalar(S(scalar) *s, uint64_t seed){
    unsigned char b[32]; S(sha256) h; int ov;
    S(sha256_initialize)(&h);
    S(sha256_write)(&h,(unsigned char*)&seed,8);
    S(sha256_write)(&h,(unsigned char*)&seed,8);
    S(sha256_finalize)(&h,b);
    do { S(scalar_set_b32)(s,b,&ov); b[0]++; } while(ov||S(scalar_is_zero)(s));
}
static void kG(S(gej) *r, uint64_t seed){
    S(scalar) k,zero; S(gej) gj;
    rand_scalar(&k,seed);
    S(scalar_set_int)(&zero,0);
    S(gej_set_ge)(&gj,&S(ge_const_g));
    S(ecmult)(r,&gj,&zero,&k);
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
    /* load fused operands */
    gej4 a4[4]; ge4 b4[2];
    for(int g=0;g<4;g++){
        uint64_t ax[4][5],ay[4][5],az[4][5];
        for(int l=0;l<4;l++){
            S(gej) a=pts[g*4+l];S(fe_normalize)(&a.x);S(fe_normalize)(&a.y);S(fe_normalize)(&a.z);
            for(int i=0;i<5;i++){ax[l][i]=a.x.n[i];ay[l][i]=a.y.n[i];az[l][i]=a.z.n[i];}
        }
        fe4_load(a4[g].x,(const uint64_t(*)[5])ax);
        fe4_load(a4[g].y,(const uint64_t(*)[5])ay);
        fe4_load(a4[g].z,(const uint64_t(*)[5])az);
    }
    for(int g=0;g<2;g++){
        uint64_t bx[4][5],by[4][5];
        for(int l=0;l<4;l++){
            S(ge) b=aff[g*4+l];
            for(int i=0;i<5;i++){bx[l][i]=b.x.n[i];by[l][i]=b.y.n[i];}
        }
        fe4_load(b4[g].x,(const uint64_t(*)[5])bx);
        fe4_load(b4[g].y,(const uint64_t(*)[5])by);
    }

    /* correctness of the interleaved version */
    {
        int bad=0;
        for(int t=0;t<4000;t++){
            uint64_t ax[4][5],ay[4][5],az[4][5],bx[4][5],by[4][5];
            uint64_t ox[4][5],oy[4][5],oz[4][5];
            S(gej) ref[4];
            gej4 ra4,rb4; ge4 c4;
            int t0=(t*3)%NPOINTS, t1=(t*5+1)%NPOINTS;
            for(int l=0;l<4;l++){
                S(gej) a=pts[(t0+l)%NPOINTS];
                S(fe_normalize)(&a.x);S(fe_normalize)(&a.y);S(fe_normalize)(&a.z);
                for(int i=0;i<5;i++){ax[l][i]=a.x.n[i];ay[l][i]=a.y.n[i];az[l][i]=a.z.n[i];}
                S(ge) b=aff[(t1+l)%NPOINTS];
                for(int i=0;i<5;i++){bx[l][i]=b.x.n[i];by[l][i]=b.y.n[i];}
                S(gej_add_ge_var)(&ref[l],&pts[(t0+l)%NPOINTS],&aff[(t1+l)%NPOINTS],NULL);
            }
            fe4_load(ra4.x,(const uint64_t(*)[5])ax);
            fe4_load(ra4.y,(const uint64_t(*)[5])ay);
            fe4_load(ra4.z,(const uint64_t(*)[5])az);
            for(int l=0;l<4;l++){
                S(gej) a=pts[(t0+l+37)%NPOINTS];
                S(fe_normalize)(&a.x);S(fe_normalize)(&a.y);S(fe_normalize)(&a.z);
                for(int i=0;i<5;i++){ax[l][i]=a.x.n[i];ay[l][i]=a.y.n[i];az[l][i]=a.z.n[i];}
            }
            fe4_load(rb4.x,(const uint64_t(*)[5])ax);
            fe4_load(rb4.y,(const uint64_t(*)[5])ay);
            fe4_load(rb4.z,(const uint64_t(*)[5])az);
            fe4_load(c4.x,(const uint64_t(*)[5])bx);
            fe4_load(c4.y,(const uint64_t(*)[5])by);
            gej4_add_ge4_x2(&ra4,&ra4,&c4, &rb4,&rb4,&c4);
            fe4_store(ox,rb4.x); fe4_store(oy,rb4.y); fe4_store(oz,rb4.z);
            for(int l=0;l<4;l++){
                S(gej) f4; S(ge) af_ref;
                for(int i=0;i<5;i++){f4.x.n[i]=ox[l][i];f4.y.n[i]=oy[l][i];f4.z.n[i]=oz[l][i];}
                f4.infinity=0;
                /* compare second add's result against its own reference */
                S(gej) refb; S(gej) aa=pts[(t0+l+37)%NPOINTS];
                S(gej_add_ge_var)(&refb,&aa,&aff[(t1+l)%NPOINTS],NULL);
                gej_to_ge(&af_ref,&refb);
                S(fe) zi,zi2,x2,y2;
                S(fe_inv_var)(&zi,&f4.z); S(fe_sqr)(&zi2,&zi);
                S(fe_mul)(&x2,&f4.x,&zi2); S(fe_mul)(&zi2,&zi2,&zi);
                S(fe_mul)(&y2,&f4.y,&zi2);
                S(fe_normalize)(&x2);S(fe_normalize)(&y2);
                S(fe_normalize)(&af_ref.x);S(fe_normalize)(&af_ref.y);
                if(memcmp(x2.n,af_ref.x.n,40)||memcmp(y2.n,af_ref.y.n,40))bad++;
            }
        }
        printf("x2-interleaved add correctness: %d bad lanes / 16000\n",bad);
    }

    /* timing: sequential vs il2 interleaved, on the real MSM pattern —
       INDEPENDENT adds scattered over a memory-resident bucket table */
    {
        const int WB=4096;
        const int NG=4000;          /* groups of 8 lane-adds */
        int REPS=25;
        S(gej) *stable=calloc(WB,sizeof(S(gej)));
        for(int g=0;g<WB;g++) stable[g]=pts[g%NPOINTS];
        uint32_t *idx=calloc(NG*8,sizeof(uint32_t));
        uint32_t st=0x9e3779b9;
        for(int i=0;i<NG*8;i++){ st^=st<<13;st^=st>>17;st^=st<<5; idx[i]=st&(WB-1);}

#define GATHER4(A4,I0) do{ \
            uint64_t ax[4][5],ay[4][5],az[4][5]; \
            for(int l=0;l<4;l++){ S(gej)*bk=&stable[idx[(I0)+l]]; \
                for(int j=0;j<5;j++){ax[l][j]=bk->x.n[j];ay[l][j]=bk->y.n[j];az[l][j]=bk->z.n[j];} } \
            fe4_load(A4.x,(const uint64_t(*)[5])ax); \
            fe4_load(A4.y,(const uint64_t(*)[5])ay); \
            fe4_load(A4.z,(const uint64_t(*)[5])az); }while(0)
#define SCATTER4(A4,I0) do{ \
            uint64_t ax[4][5],ay[4][5],az[4][5]; \
            fe4_store(ax,A4.x); fe4_store(ay,A4.y); fe4_store(az,A4.z); \
            for(int l=0;l<4;l++){ S(gej)*bk=&stable[idx[(I0)+l]]; \
                for(int j=0;j<5;j++){bk->x.n[j]=ax[l][j];bk->y.n[j]=ay[l][j];bk->z.n[j]=az[l][j];} } }while(0)
#define LOADB4(B4,I0) do{ \
            uint64_t bx[4][5],by[4][5]; \
            for(int l=0;l<4;l++){const S(ge)*b=&aff[((I0)+l)%NPOINTS]; \
                for(int j=0;j<5;j++){bx[l][j]=b->x.n[j];by[l][j]=b->y.n[j];} } \
            fe4_load(B4.x,(const uint64_t(*)[5])bx); \
            fe4_load(B4.y,(const uint64_t(*)[5])by); }while(0)

        /* sequential: two fused-4 adds per group of 8 */
        {
            double t=now_wall();
            for(int r=0;r<REPS;r++){
                for(int g=0;g<NG;g++){
                    gej4 a0,r0,a1,r1; ge4 b0,b1;
                    GATHER4(a0,g*8); GATHER4(a1,g*8+4);
                    LOADB4(b0,g*8); LOADB4(b1,g*8+4);
                    gej4_add_ge4(&r0,&a0,&b0);
                    gej4_add_ge4(&r1,&a1,&b1);
                    SCATTER4(r0,g*8); SCATTER4(r1,g*8+4);
                }
            }
            double d=now_wall()-t;
            volatile uint64_t s=stable[0].x.n[0];(void)s;
            printf("seq bucket pairs : %7.1f ns/8lane = %6.1f ns/lane-add\n",
                   d/(REPS*(double)NG)*1e9, d/(REPS*(double)NG*8)*1e9);
        }
        /* interleaved: one x2 fused call per group of 8 */
        {
            double t=now_wall();
            for(int r=0;r<REPS;r++){
                for(int g=0;g<NG;g++){
                    gej4 a0,r0,a1,r1; ge4 b0,b1;
                    GATHER4(a0,g*8); GATHER4(a1,g*8+4);
                    LOADB4(b0,g*8); LOADB4(b1,g*8+4);
                    gej4_add_ge4_x2(&r0,&a0,&b0, &r1,&a1,&b1);
                    SCATTER4(r0,g*8); SCATTER4(r1,g*8+4);
                }
            }
            double d=now_wall()-t;
            volatile uint64_t s=stable[0].x.n[0];(void)s;
            printf("il2 bucket pairs : %7.1f ns/8lane = %6.1f ns/lane-add\n",
                   d/(REPS*(double)NG)*1e9, d/(REPS*(double)NG*8)*1e9);
        }
        free(stable); free(idx);
    }
    free(pts); free(aff);
    return 0;
}
