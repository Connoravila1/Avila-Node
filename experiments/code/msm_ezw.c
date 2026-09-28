/* MIT-licensed research harness, not linked into Avila Node.
 *
 * The fused-4 MSM engine: Pippenger bucket accumulation whose inner
 * loop runs the proven gej4_add_ge4 (EZW-4 lanes) over FOUR per-lane
 * scalar bucket tables, versus scalar ecmult_multi_var as ground truth.
 *
 * Layout: term k feeds lane (k mod 4). Its wnaf digit at each window
 * routes to bucket (|d|-1)/2 with the point negated for d<0 — exactly
 * pippenger_wnaf semantics (skew fixup at window 0, per-window Horner
 * step of 2^WBITS via the trailing double in the sweep tail).
 *
 * Degenerate lanes (the requirement msm_add4_probe found):
 *   - empty bucket (never written): fused add's garbage is overwritten
 *     with the point itself (select on a seen-bitset);
 *   - collision lanes (h==0: P+P or P+(-P)): detected by a zero-z' lane
 *     in the fused result and redone scalar-side via gej_add_ge_var.
 *
 * The per-window fold (running_sum sweep + result accumulation) runs
 * scalar per lane — correctness first; its share is reported so the
 * accumulate-vs-fold split is visible.
 *
 * Build: same recipe as msm_decomp_bench.c. Run under guard, pinned.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
static inline void fe4_add(fe4 r, const fe4 a, const fe4 b){
    for(int i=0;i<5;i++)r[i]=_mm256_add_epi64(a[i],b[i]);
    fe4_norm(r);
}
static const uint64_t FE4_P4[5] = {
    0xFFFFBFFFFF0BCULL, 0xFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFULL, 0x3FFFFFFFFFFFFULL
};
static inline void fe4_neg(fe4 r, const fe4 a){
    /* base-2^52 borrow: when a[i]+bor > P4[i], the limb wraps — add back
     * one limb unit (2^52), NOT the raw 2^64 word. The old version left
     * the wrapped value for fe4_norm, which interpreted the borrow as a
     * +4095 carry — double-counting it and corrupting the result. */
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
#include "ezw_body.c"

typedef struct { fe4 x,y,z; } gej4;
typedef struct { fe4 x,y; } ge4;
static inline void fe4_sub(fe4 r, const fe4 a, const fe4 b){
    fe4 nb; fe4_neg(nb,b); fe4_add(r,a,nb);
}
/* proven non-degenerate fused add (msm_add4_probe: 0 bad/16000) */
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

static void rand_scalar(S(scalar) *s, uint64_t seed){
    unsigned char b[32];
    S(sha256) h;
    int ov;
    S(sha256_initialize)(&h);
    S(sha256_write)(&h,(unsigned char*)&seed,8);
    S(sha256_write)(&h,(unsigned char*)&seed,8);
    S(sha256_finalize)(&h,b);
    do { S(scalar_set_b32)(s,b,&ov); b[0]++; } while(ov);
}
static void rand_point(S(ge) *out, uint64_t seed){
    S(scalar) k,zero; S(gej) gj,r; S(fe) zinv;
    rand_scalar(&k,seed);
    S(scalar_set_int)(&zero,0);
    S(gej_set_ge)(&gj,&S(ge_const_g));
    S(ecmult)(&r,&gj,&zero,&k);
    S(fe_inv_var)(&zinv,&r.z);
    S(ge_set_gej_zinv)(out,&r,&zinv);
}

/* ---------------- fused-4 MSM ---------------- */
#ifndef BW
#define BW 12
#endif
#define WBITS (BW+1)                 /* wnaf window: 13 bits */
#define NBUCK ECMULT_TABLE_SIZE(BW+2)/* 8192: |digit|<=16383 -> idx<=8191 */
#define NWIN WNAF_SIZE(WBITS)        /* 10 digits for 128-bit halves */

typedef struct { uint16_t buck; uint16_t term; } AddItem; /* term|0x8000 => neg */

typedef struct {
    S(gej) *tab[4];
    uint8_t *seen[4];
    uint8_t *hot[4];   /* scalar-written (magnitude-2) slots needing normalize */
    int *wnaf;
    int8_t *skews;
    int scalar_mode;
    int norm_gather;
    int debug;
    uint64_t degen;
    double t_accum, t_fold;
    S(gej) *trace;   /* if set: r after each window's fold */
    int shadow;      /* if set: scalar-shadow check of each fused lane-add */
} Msm4;

static void msm4_clear(Msm4 *m){
    for(int l=0;l<4;l++){
        for(int g=0;g<NBUCK;g++) S(gej_set_infinity)(&m->tab[l][g]);
        memset(m->seen[l],0,(NBUCK+7)/8);
        memset(m->hot[l],0,(NBUCK+7)/8);
    }
}
static inline int lane_seen(Msm4 *m,int l,int b){
    return (m->seen[l][b>>3]>>(b&7))&1;
}
static inline void lane_mark(Msm4 *m,int l,int b){
    m->seen[l][b>>3]|=(uint8_t)(1u<<(b&7));
}
static inline int lane_hot(Msm4 *m,int l,int b){
    return (m->hot[l][b>>3]>>(b&7))&1;
}
static inline void lane_mark_hot(Msm4 *m,int l,int b){
    m->hot[l][b>>3]|=(uint8_t)(1u<<(b&7));
}
static inline void lane_clear_hot(Msm4 *m,int l,int b){
    m->hot[l][b>>3]&=(uint8_t)~(1u<<(b&7));
}

/* insert scalar field element (or small int pattern) into lane l of fe4 */
static inline void lane_set5(vi *v,int l,const uint64_t src[5]){
    int64_t tmp[4];
    for(int i=0;i<5;i++){
        _mm256_storeu_si256((vi*)tmp,v[i]); tmp[l]=(int64_t)src[i];
        v[i]=_mm256_loadu_si256((vi*)tmp);
    }
}
static inline void lane_get5(uint64_t dst[5],const vi *v,int l){
    int64_t tmp[4];
    for(int i=0;i<5;i++){
        _mm256_storeu_si256((vi*)tmp,v[i]); dst[i]=(uint64_t)tmp[l];
    }
}

/* gather: a4 lane l <- lane table entry; b4 lane l <- point (negated if
 * the term carries the sign bit). Dead lanes duplicate lane 0 — the
 * caller masks them at scatter and fixup. */
static void gather4(gej4 *a4, ge4 *b4, Msm4 *m, const AddItem it[4],
                    int lane_mask, const S(ge) *points,
                    S(gej) *nn, S(ge) *pq){
    /* copy the 4 lane operands into scalars first, then transpose via
     * set_epi64x — much cheaper than per-lane store/load round-trips. */
    int l;
    for(l=0;l<4;l++){
        int used=(lane_mask>>l)&1;
        uint16_t b = used ? it[l].buck : (it[0].buck & (NBUCK-1));
        uint16_t tm = (uint16_t)(used ? it[l].term : it[0].term) & 0x7fff;
        nn[l]=m->tab[l][b];
        pq[l]=points[tm];
        if(used && (it[l].term&0x8000)){
            S(ge) nn2;
            S(ge_neg)(&nn2,&pq[l]);
            pq[l]=nn2;
            S(fe_normalize)(&pq[l].y);  /* fe_negate leaves magnitude-2 */
        }
        if(used && lane_hot(m,l,b)){
            S(fe_normalize)(&nn[l].x);S(fe_normalize)(&nn[l].y);
            S(fe_normalize)(&nn[l].z);
        }
    }
    for(int i=0;i<5;i++){
        a4->x[i]=_mm256_set_epi64x((int64_t)nn[3].x.n[i],(int64_t)nn[2].x.n[i],
                                   (int64_t)nn[1].x.n[i],(int64_t)nn[0].x.n[i]);
        a4->y[i]=_mm256_set_epi64x((int64_t)nn[3].y.n[i],(int64_t)nn[2].y.n[i],
                                   (int64_t)nn[1].y.n[i],(int64_t)nn[0].y.n[i]);
        a4->z[i]=_mm256_set_epi64x((int64_t)nn[3].z.n[i],(int64_t)nn[2].z.n[i],
                                   (int64_t)nn[1].z.n[i],(int64_t)nn[0].z.n[i]);
        b4->x[i]=_mm256_set_epi64x((int64_t)pq[3].x.n[i],(int64_t)pq[2].x.n[i],
                                   (int64_t)pq[1].x.n[i],(int64_t)pq[0].x.n[i]);
        b4->y[i]=_mm256_set_epi64x((int64_t)pq[3].y.n[i],(int64_t)pq[2].y.n[i],
                                   (int64_t)pq[1].y.n[i],(int64_t)pq[0].y.n[i]);
    }
}

static void scatter4(const gej4 *r4, Msm4 *m, const AddItem it[4], int lane_mask){
    for(int l=0;l<4;l++){
        uint64_t x[5],y[5],z[5];
        if(!((lane_mask>>l)&1)) continue;
        lane_get5(x,r4->x,l); lane_get5(y,r4->y,l); lane_get5(z,r4->z,l);
        memcpy(m->tab[l][it[l].buck].x.n,x,40);
        memcpy(m->tab[l][it[l].buck].y.n,y,40);
        memcpy(m->tab[l][it[l].buck].z.n,z,40);
        m->tab[l][it[l].buck].infinity=0;
        lane_mark(m,l,it[l].buck);
        lane_clear_hot(m,l,it[l].buck);
    }
}

/* per-lane fixup: unseen bucket -> result is the point itself; a zero-z'
 * lane on a seen bucket is a collision -> scalar redo (covers P+P and
 * P+(-P)->inf). Resolved lanes are written DIRECTLY to the table so the
 * gej infinity flag survives (lane_set5 carries only limbs and would
 * lose it); the returned mask tells scatter4 which lanes to skip. */
static int fixup4(gej4 *r4, Msm4 *m, const AddItem it[4], int lane_mask,
                  const S(ge) *points){
    int resolved=0;
    for(int l=0;l<4;l++){
        uint64_t z[5]; int allzero=1;
        S(ge) pt;
        if(!((lane_mask>>l)&1)) continue;
        lane_get5(z,r4->z,l);
        {   S(fe) zf; int i;
            for(i=0;i<5;i++) zf.n[i]=z[i];
            S(fe_normalize)(&zf);   /* folds p-form reps to canonical 0 */
            allzero=1;
            for(i=0;i<5;i++) if(zf.n[i]!=0){allzero=0;break;}
        }
        pt=points[it[l].term&0x7fff];
        if(it[l].term&0x8000){
            S(ge) nn;S(ge_neg)(&nn,&pt);pt=nn;
            S(fe_normalize)(&pt.y);
        }
        if(m->debug) fprintf(stderr,"fixup l=%d buck=%d term=%d seen=%d z'=0=%d\n",
            l,it[l].buck,it[l].term,lane_seen(m,l,it[l].buck),allzero);
        if(!lane_seen(m,l,it[l].buck)){
            /* bucket was empty: result = the point itself (affine->gej) */
            S(gej_set_ge)(&m->tab[l][it[l].buck],&pt);
            lane_mark(m,l,it[l].buck);
            resolved|=1<<l;
        } else if(allzero){
            S(gej) s;
            S(gej_add_ge_var)(&s,&m->tab[l][it[l].buck],&pt,NULL);
            m->tab[l][it[l].buck]=s;
            lane_mark(m,l,it[l].buck);
            lane_mark_hot(m,l,it[l].buck);
            resolved|=1<<l;
            m->degen++;
        }
    }
    return resolved;
}

/* the fused-4 MSM proper. n input terms -> 2n endo-split terms, term
 * index t -> lane t&3. wnaf per split term (128-bit, WBITS window). */
static void msm4(Msm4 *m, S(gej) *r, const S(scalar) *sc, const S(ge) *pt,
                 size_t n){
    int i;
    size_t np,n2=2*n;
    AddItem *lists[4];
    size_t cnt[4];
    double t0;
    S(scalar) *ss=malloc(n2*sizeof(S(scalar)));
    S(ge) *pp=malloc(n2*sizeof(S(ge)));
    int *wnaf=malloc(n2*NWIN*sizeof(int));
    int8_t *skews=malloc(n2);
    for(int l=0;l<4;l++)
        lists[l]=malloc((n2/4+8)*sizeof(AddItem));

    /* endo split: term np -> split terms 2np (s1,p1) and 2np+1 (s2,p2) */
    for(np=0;np<n;np++){
        if(S(scalar_is_zero)(&sc[np])||S(ge_is_infinity)(&pt[np])){
            memset(&wnaf[2*np*NWIN],0,2*NWIN*sizeof(int));
            skews[2*np]=skews[2*np+1]=0;
            S(ge_set_infinity)(&pp[2*np]); S(ge_set_infinity)(&pp[2*np+1]);
            S(scalar_set_int)(&ss[2*np],0); S(scalar_set_int)(&ss[2*np+1],0);
            continue;
        }
        ss[2*np]=sc[np];
        pp[2*np]=pt[np];
        S(ecmult_endo_split)(&ss[2*np],&ss[2*np+1],&pp[2*np],&pp[2*np+1]);
        /* ge_mul_lambda leaves magnitude-2 coords; normalize once so
         * gather can feed them to fused ops without re-normalizing */
        S(fe_normalize)(&pp[2*np].x); S(fe_normalize)(&pp[2*np].y);
        S(fe_normalize)(&pp[2*np+1].x); S(fe_normalize)(&pp[2*np+1].y);
    }
    for(np=0;np<n2;np++){
        if(S(scalar_is_zero)(&ss[np])||S(ge_is_infinity)(&pp[np])){
            memset(&wnaf[np*NWIN],0,NWIN*sizeof(int));
            skews[np]=0;
            continue;
        }
        skews[np]=(int8_t)S(wnaf_fixed)(&wnaf[np*NWIN],&ss[np],WBITS);
    }
    S(gej_set_infinity)(r);

    for(i=NWIN-1;i>=0;i--){
        msm4_clear(m);
        /* build per-lane add lists */
        for(int l=0;l<4;l++) cnt[l]=0;
        for(np=0;np<n2;np++){
            int nn=wnaf[np*NWIN+i];
            int l=(int)(np&3);
            if(i==0 && skews[np]){
                S(ge) tmp;
                S(ge_neg)(&tmp,&pp[np]);
                S(gej_add_ge_var)(&m->tab[l][0],&m->tab[l][0],&tmp,NULL);
                lane_mark(m,l,0);
                lane_mark_hot(m,l,0);
            }
            if(nn>0){
                lists[l][cnt[l]++]=(AddItem){(uint16_t)((nn-1)/2),(uint16_t)np};
            } else if(nn<0){
                lists[l][cnt[l]++]=(AddItem){(uint16_t)((-nn-1)/2),(uint16_t)(np|0x8000)};
            }
        }
        /* fused accumulate: group s takes items[s] of each lane */
        t0=now_wall();
        if(m->scalar_mode){
            for(int l=0;l<4;l++){
                size_t sstep;
                for(sstep=0;sstep<cnt[l];sstep++){
                    AddItem it=lists[l][sstep];
                    S(ge) p2=pp[it.term&0x7fff];
                    if(it.term&0x8000){S(ge) nn;S(ge_neg)(&nn,&p2);p2=nn;}
                    S(gej_add_ge_var)(&m->tab[l][it.buck],&m->tab[l][it.buck],&p2,NULL);
                }
            }
        } else {
            int mx=(int)cnt[0];
            int sstep;
            for(int l=1;l<4;l++) if((int)cnt[l]>mx) mx=(int)cnt[l];
            for(sstep=0;sstep<mx;sstep++){
                AddItem it[4]; gej4 a4,r4; ge4 b4;
                S(gej) nn[4]; S(ge) pq[4];
                int lane_mask=0;
                for(int l=0;l<4;l++){
                    if(sstep<(int)cnt[l]){ it[l]=lists[l][sstep]; lane_mask|=1<<l; }
                    else { it[l].buck=0; it[l].term=0; }
                }
                gather4(&a4,&b4,m,it,lane_mask,pp,nn,pq);
                gej4_add_ge4(&r4,&a4,&b4);
                if(m->shadow){
                    for(int l=0;l<4;l++){
                        S(gej) ex; S(gej) mine; uint64_t t5[5]; int j2;
                        if(!((lane_mask>>l)&1)) continue;
                        S(gej_add_ge_var)(&ex,&nn[l],&pq[l],NULL);
                        for(j2=0;j2<5;j2++){t5[j2]=0;}
                        { int64_t tt[4];
                          for(j2=0;j2<4;j2++)tt[j2]=_mm256_extract_epi64(r4.x[0],j2);
                          (void)tt; }
                        memset(&mine,0,sizeof mine);
                        lane_get5(mine.x.n,r4.x,l);
                        lane_get5(mine.y.n,r4.y,l);
                        lane_get5(mine.z.n,r4.z,l);
                        mine.infinity=0;
                        /* compare via affine z-projection */
                        { S(ge) e1,e2; S(fe) z1,z2,zl;
                          S(ge_set_gej)(&e1,&ex);
                          if(lane_seen(m,l,it[l].buck)&&
                             !(  mine.z.n[0]==0&&mine.z.n[1]==0&&
                                 mine.z.n[2]==0&&mine.z.n[3]==0&&
                                 mine.z.n[4]==0)){
                              S(fe_inv_var)(&zl,&mine.z);
                              S(ge_set_gej_zinv)(&e2,&mine,&zl);
                              if(memcmp(e1.x.n,e2.x.n,40)||
                                 memcmp(e1.y.n,e2.y.n,40)){
                                  int j3;
                                  fprintf(stderr,
                                    "W%d BAD l=%d buck=%d term=%d hot=%d\n",
                                    i,l,it[l].buck,it[l].term,
                                    lane_hot(m,l,it[l].buck));
                                  fprintf(stderr,"  nn.z=");for(j3=0;j3<5;j3++)fprintf(stderr,"%llx ",(unsigned long long)nn[l].z.n[j3]);
                                  fprintf(stderr,"\n  nn.x=");for(j3=0;j3<5;j3++)fprintf(stderr,"%llx ",(unsigned long long)nn[l].x.n[j3]);
                                  fprintf(stderr,"\n  nn.y=");for(j3=0;j3<5;j3++)fprintf(stderr,"%llx ",(unsigned long long)nn[l].y.n[j3]);
                                  fprintf(stderr,"\n  pq.x=");for(j3=0;j3<5;j3++)fprintf(stderr,"%llx ",(unsigned long long)pq[l].x.n[j3]);
                                  fprintf(stderr,"\n  pq.y=");for(j3=0;j3<5;j3++)fprintf(stderr,"%llx ",(unsigned long long)pq[l].y.n[j3]);
                                  fprintf(stderr,"\n");
                              }
                          }
                        }
                    }
                }
                lane_mask &= ~fixup4(&r4,m,it,lane_mask,pp);
                scatter4(&r4,m,it,lane_mask);
            }
        }
        m->t_accum += now_wall()-t0;
        /* fold: per lane, acc_lane = 2*inner + run0; r = 2^WBITS*r + Σacc_l */
        t0=now_wall();
        {
            S(gej) acc;
            int l,j;
            S(gej_set_infinity)(&acc);
            for(l=0;l<4;l++){
                S(gej) running,inner;
                S(gej_set_infinity)(&running);
                S(gej_set_infinity)(&inner);
                for(j=NBUCK-1;j>0;j--){
                    S(gej_add_var)(&running,&running,&m->tab[l][j],NULL);
                    S(gej_add_var)(&inner,&inner,&running,NULL);
                }
                S(gej_add_var)(&running,&running,&m->tab[l][0],NULL);
                S(gej_double_var)(&inner,&inner,NULL);
                S(gej_add_var)(&inner,&inner,&running,NULL);
                S(gej_add_var)(&acc,&acc,&inner,NULL);
            }
            for(j=0;j<WBITS;j++) S(gej_double_var)(r,r,NULL);
            S(gej_add_var)(r,r,&acc,NULL);
        }
        m->t_fold += now_wall()-t0;
        if(m->trace) m->trace[i]=*r;
    }
    for(int l=0;l<4;l++) free(lists[l]);
    free(ss);free(pp);free(wnaf);free(skews);
}

/* scalar truth via ecmult_multi_var */
static const S(scalar) *CB_SC;
static const S(ge) *CB_PT;
static int truth_cb(S(scalar) *sc, S(ge) *pt, size_t idx, void *data){
    (void)data; *sc=CB_SC[idx]; *pt=CB_PT[idx]; return 1;
}

/* brute-force ground truth: per-term ecmult + adds */
static void brute(S(gej) *r, const S(scalar) *sc, const S(ge) *pt, size_t n){
    size_t i;
    S(gej_set_infinity)(r);
    for(i=0;i<n;i++){
        S(gej) a,t;
        S(scalar) z;
        S(scalar_set_int)(&z,0);
        S(gej_set_ge)(&a,&pt[i]);
        S(ecmult)(&t,&a,&sc[i],&z);
        S(gej_add_var)(r,r,&t,NULL);
    }
}

static int gej_same(const S(gej) *a, const S(gej) *b){
    if(S(gej_is_infinity)(a)&&S(gej_is_infinity)(b)) return 1;
    S(ge) a1,a2; S(fe) z;
    S(fe_inv_var)(&z,&a->z); S(ge_set_gej_zinv)(&a1,a,&z);
    S(fe_inv_var)(&z,&b->z); S(ge_set_gej_zinv)(&a2,b,&z);
    S(fe_normalize)(&a1.x);S(fe_normalize)(&a1.y);
    S(fe_normalize)(&a2.x);S(fe_normalize)(&a2.y);
    return !memcmp(a1.x.n,a2.x.n,40)&&!memcmp(a1.y.n,a2.y.n,40);
}

int main(void){
    fesetround(FE_TOWARDZERO);
    const int N=16384;
    S(scalar) *sc=calloc(N,sizeof(S(scalar)));
    S(ge) *pt=calloc(N,sizeof(S(ge)));
    void *cm; S(context) *ctx;
    S(scratch) scratch;
    int i;
    fprintf(stderr,"generating %d terms (untimed)...\n",N);
    for(i=0;i<N;i++){
        rand_scalar(&sc[i],0xabc000u+(uint64_t)i);
        rand_point(&pt[i],0x777000u+(uint64_t)i);
    }
    /* a few engineered degenerates: point doubles and negations */
    sc[5]=sc[6]; pt[6]=pt[5];                 /* same term twice  */
    pt[7]=pt[8]; S(ge_neg)(&pt[8],&pt[7]);    /* same point, d negs*/

    memset(&scratch,0,sizeof scratch);
    memcpy(scratch.magic,"scratch",8);
    scratch.data=calloc(1,64u<<20);
    scratch.max_size=64u<<20;
    cm=calloc(1,S(context_preallocated_size)(SECP256K1_CONTEXT_NONE));
    ctx=S(context_preallocated_create)(cm,SECP256K1_CONTEXT_NONE);

    Msm4 m;
    memset(&m,0,sizeof m);
    m.wnaf=calloc(N*NWIN,sizeof(int));
    m.skews=calloc(N,1);
    for(int l=0;l<4;l++){
        m.tab[l]=calloc(NBUCK,sizeof(S(gej)));
        m.seen[l]=calloc((NBUCK+7)/8,1);
        m.hot[l]=calloc((NBUCK+7)/8,1);
    }

    /* ---- wnaf reconstruction check for the k=7 random scalar ---- */
    {
        S(scalar) s1; int w[32]={0}; int skew; int i;
        rand_scalar(&s1,0xdead+7);
        skew=S(wnaf_fixed)(w,&s1,WBITS);
        /* reconstruct: acc = Σ w[i]·2^(13i) - skew (mod n) */
        {
            S(scalar) acc; S(scalar_set_int)(&acc,0);
            for(i=0;i<NWIN;i++){
                int d=w[i]; int sh=i*WBITS;
                /* apply digit at bit position: acc += d << sh */
                if(d!=0){
                    S(scalar) t; int j;
                    S(scalar_set_int)(&t, d>0?(unsigned)d:(unsigned)(-d));
                    for(j=0;j<sh;j++) S(scalar_add)(&t,&t,&t); /* t=|d|·2^sh mod n */
                    if(d<0) S(scalar_negate)(&t,&t);
                    S(scalar_add)(&acc,&acc,&t);
                }
            }
            if(skew){ S(scalar) one; S(scalar_set_int)(&one,1);
                      S(scalar_add)(&acc,&acc,&one); }
            printf("wnaf reconstruct==scalar: %s\n",
                   memcmp(acc.d,s1.d,32)==0?"YES":"NO");
        }
        /* also dump digits */
        fprintf(stderr,"wnaf: "); for(i=0;i<NWIN;i++) fprintf(stderr,"%d ",w[i]);
        fprintf(stderr," skew=%d\n",skew);
    }

    /* ---- micro-test: n=4, all scalars = 1 -> sum of the 4 points ---- */
    {
        S(scalar) ones[4]; S(gej) exp,mine; S(scalar) z0;
        int k;
        S(scalar_set_int)(&z0,0);
        S(gej_set_infinity)(&exp);
        for(k=0;k<4;k++){
            S(gej) a;
            S(scalar_set_int)(&ones[k],1);
            S(gej_set_ge)(&a,&pt[k]);
            S(gej_add_var)(&exp,&exp,&a,NULL);
        }
        m.scalar_mode=1;
        msm4(&m,&mine,ones,pt,4);
        printf("n=4 s=1  scal4: %s\n", gej_same(&exp,&mine)?"MATCH":"MISMATCH");
        m.scalar_mode=0;
        msm4(&m,&mine,ones,pt,4);
        printf("n=4 s=1  msm4 : %s\n", gej_same(&exp,&mine)?"MATCH":"MISMATCH");
    }

    /* ---- micro-test 2: single term, scalar values that exercise
       skew/digits: {1,2,3,8191, random-ish, 2^13-1, 2^13} ---- */
    {
        int k; int fails=0;
        for(k=0;k<8;k++){
            S(scalar) s1; S(gej) exp,mine;
            S(scalar) z0; S(scalar_set_int)(&z0,0);
            switch(k){
                case 0: S(scalar_set_int)(&s1,1); break;
                case 1: S(scalar_set_int)(&s1,2); break;
                case 2: S(scalar_set_int)(&s1,3); break;
                case 3: S(scalar_set_int)(&s1,8191); break;
                case 4: S(scalar_set_int)(&s1,4096); break;
                case 5: S(scalar_set_int)(&s1,8192); break;
                case 6: S(scalar_set_int)(&s1,65536); break;
                default: rand_scalar(&s1,0xdead+k); break;
            }
            { S(gej) a,t; S(gej_set_ge)(&a,&pt[k]);
              S(ecmult)(&t,&a,&s1,&z0); exp=t; }
            if(k==5){
                S(scalar) h1,h2; S(ge) q1,q2;
                h1=s1; q1=pt[k];
                S(ecmult_endo_split)(&h1,&h2,&q1,&q2);
                { unsigned char b[32]; S(scalar_get_b32)(b,&h1);
                  fprintf(stderr,"k5 s1=%02x%02x%02x%02x..%02x%02x\n",
                    b[0],b[1],b[2],b[3],b[30],b[31]);
                  S(scalar_get_b32)(b,&h2);
                  fprintf(stderr,"k5 s2=%02x%02x%02x%02x..%02x%02x\n",
                    b[0],b[1],b[2],b[3],b[30],b[31]); }
            }
            m.scalar_mode=1;
            msm4(&m,&mine,&s1,&pt[k],1);
            if(!gej_same(&exp,&mine)){ fails++;
                printf("n=1 k=%d scal4: MISMATCH\n",k); }
            { S(gej) *ts=calloc(NWIN,sizeof(S(gej)));
              S(gej) *tf=calloc(NWIN,sizeof(S(gej))); (void)ts;(void)tf; }
            m.scalar_mode=0; m.norm_gather=1; m.debug=(k==5);
            msm4(&m,&mine,&s1,&pt[k],1);
            if(!gej_same(&exp,&mine)){ fails++;
                printf("n=1 k=%d msm4 : MISMATCH\n",k); }
            m.debug=0;
        }
        printf("n=1 scalar sweep: %d fails\n",fails);
    }

    /* ---- debug bisect: small N vs brute force ---- */
    {
        size_t szs[8]={8,64,512,2048,4096,8192,12288,16384};
        int k;
        m.scalar_mode=1;
        for(k=0;k<8;k++){
            S(gej) b,mine;
            brute(&b,sc,pt,szs[k]);
            m.t_accum=0;m.t_fold=0;m.degen=0;
            msm4(&m,&mine,sc,pt,szs[k]);
            printf("N=%4zu brute-vs-scal4: %s\n",szs[k],
                   gej_same(&b,&mine)?"MATCH":"MISMATCH");
            if(!gej_same(&b,&mine)) break;
        }
        m.scalar_mode=0;
        for(k=0;k<8;k++){
            S(gej) b,mine;
            brute(&b,sc,pt,szs[k]);
            m.t_accum=0;m.t_fold=0;m.degen=0;
            msm4(&m,&mine,sc,pt,szs[k]);
            printf("N=%4zu brute-vs-msm4 : %s (degen=%llu)\n",szs[k],
                   gej_same(&b,&mine)?"MATCH":"MISMATCH",
                   (unsigned long long)m.degen);
            if(!gej_same(&b,&mine)){
                /* find first divergent window: trace scalar vs fused */
                S(gej) ts[NWIN],tf[NWIN]; int w;
                m.scalar_mode=1; m.trace=ts;
                { S(gej) junk; msm4(&m,&junk,sc,pt,szs[k]); }
                m.scalar_mode=0; m.trace=tf; m.shadow=1;
                { S(gej) junk; msm4(&m,&junk,sc,pt,szs[k]); }
                m.trace=NULL; m.shadow=0;
                for(w=NWIN-1;w>=0;w--)
                    if(!gej_same(&ts[w],&tf[w])) break;
                printf("   first divergent window i=%d\n",w);
                break;
            }
        }
    }

    {
        S(gej) truth,mine; S(scalar) zero;
        S(scalar_set_int)(&zero,0);
        CB_SC=sc; CB_PT=pt;
        {
            double t0=now_wall();
            int ok=S(ecmult_multi_var)(&ctx->error_callback,&scratch,&truth,
                                       &zero,truth_cb,NULL,N);
            double d=now_wall()-t0;
            printf("scalar ecmult_multi_var: ok=%d  %.1f us (%.2f us/term)\n",
                   ok,d*1e6,d*1e6/N);
        }
        for(m.norm_gather=1;m.norm_gather>=0;m.norm_gather--){
            double t0=now_wall();
            m.t_accum=0;m.t_fold=0;m.degen=0;
            msm4(&m,&mine,sc,pt,N);
            double d=now_wall()-t0;
            printf("fused msm4 ng=%d     : %.1f us (%.2f us/term)\n",
                   m.norm_gather,d*1e6,d*1e6/N);
            printf("  accum=%.1f us  fold=%.1f us  degen=%llu\n",
                   m.t_accum*1e6,m.t_fold*1e6,(unsigned long long)m.degen);
        }
        m.norm_gather=0;
        {
            S(ge) a1,a2; S(fe) z;
            int eq;
            if(S(gej_is_infinity)(&truth)&&S(gej_is_infinity)(&mine)){
                printf("both infinity: MATCH\n");
            } else {
                S(fe_inv_var)(&z,&truth.z); S(ge_set_gej_zinv)(&a1,&truth,&z);
                S(fe_inv_var)(&z,&mine.z);  S(ge_set_gej_zinv)(&a2,&mine,&z);
                S(fe_normalize)(&a1.x);S(fe_normalize)(&a1.y);
                S(fe_normalize)(&a2.x);S(fe_normalize)(&a2.y);
                eq=!memcmp(a1.x.n,a2.x.n,40)&&!memcmp(a1.y.n,a2.y.n,40);
                printf("fused MSM vs truth : %s\n",eq?"MATCH":"MISMATCH");
            }
        }
        /* repeat timing (median of 3) */
        {
            int r; double ts[5];
            for(r=0;r<5;r++){
                S(gej) rr;
                double t0=now_wall();
                m.t_accum=0;m.t_fold=0;m.degen=0;
                msm4(&m,&rr,sc,pt,N);
                ts[r]=now_wall()-t0;
                if(r==0)mine=rr;
            }
            /* sort for median */
            for(int a=0;a<5;a++)for(int b=a+1;b<5;b++)
                if(ts[b]<ts[a]){double t=ts[a];ts[a]=ts[b];ts[b]=t;}
            printf("fused msm4 median  : %.1f us (%.2f us/term)\n",
                   ts[2]*1e6,ts[2]*1e6/N);
        }
    }
    return 0;
}
