static inline void fe4_mul4v4(fe4 r, const fe4 ai, const fe4 bi){
    vd a[5],b[5];
    for(int i=0;i<5;i++){a[i]=i2d(ai[i]);b[i]=i2d(bi[i]);}
    vd C1=_mm256_set1_pd(0x1p104), C2=_mm256_set1_pd(0x1p104+0x1p52);
    vi m52=M52v, car=_mm256_setzero_si256();
    vd c16=_mm256_set1_pd((double)(16ULL*0x1000003D1ULL));
    vi F[6]; for(int i=0;i<6;i++)F[i]=_mm256_setzero_si256();
    static const int NP[9]={1,2,3,4,5,4,3,2,1};
    vi O[10];
    vi A_cur =_mm256_set1_epi64x(-(int64_t)NP[0]*B_LO);
    vi A_next=_mm256_set1_epi64x(-((int64_t)NP[1]*B_LO+(int64_t)NP[0]*B_HI));
    for(int c=0;c<9;c++){
        for(int i=(c<5?0:c-4);i<5 && i<=c;i++){
            int j=c-i;
            vd hi=_mm256_fmadd_pd(a[i],b[j],C1);
            vd ad=_mm256_sub_pd(C2,hi);
            vd lo=_mm256_fmadd_pd(a[i],b[j],ad);
            A_cur =_mm256_add_epi64(A_cur ,_mm256_castpd_si256(lo));
            A_next=_mm256_add_epi64(A_next,_mm256_castpd_si256(hi));
        }
        vi t=_mm256_add_epi64(A_cur,car);
        O[c]=_mm256_and_si256(t,m52);
        car=_mm256_srli_epi64(t,52);
        A_cur=A_next;
        int nl=(c+2<=8)?NP[c+2]:0, nh=(c+1<=8)?NP[c+1]:0;
        A_next=_mm256_set1_epi64x(-((int64_t)nl*B_LO+(int64_t)nh*B_HI));
    }
    O[9]=_mm256_add_epi64(A_cur,car);
    /* tail identical to v2 */
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
        vi g=_mm256_add_epi64(_mm256_mul_epu32(x4,_mm256_set1_epi64x(977)),
                              _mm256_slli_epi64(x4,32));
        F[0]=_mm256_add_epi64(F[0],_mm256_and_si256(g,m52));
        F[1]=_mm256_add_epi64(F[1],_mm256_srli_epi64(g,52));
    }
    {
        vd od=i2d(F[5]);
        vd h=_mm256_fmadd_pd(od,c16,C1);
        vd ad=_mm256_sub_pd(C2,h);
        vd l=_mm256_fmadd_pd(od,c16,ad);
        F[0]=_mm256_add_epi64(F[0],d2bits(l));
        F[1]=_mm256_add_epi64(F[1],
            _mm256_sub_epi64(_mm256_castpd_si256(h),_mm256_set1_epi64x(B_HI)));
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
        vi g=_mm256_add_epi64(_mm256_mul_epu32(c2,_mm256_set1_epi64x(977)),
                              _mm256_slli_epi64(c2,32));
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
