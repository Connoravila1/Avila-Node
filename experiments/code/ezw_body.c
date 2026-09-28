/* shared kernels: fe4_mul4 / fe4_sqr4 factored out of ezw2.c */
static void fe4_mul4(fe4 r, const fe4 ai, const fe4 bi){
    vd a[5],b[5];
    for(int i=0;i<5;i++){a[i]=i2d(ai[i]);b[i]=i2d(bi[i]);}
    vd C1=_mm256_set1_pd(0x1p104), C2=_mm256_set1_pd(0x1p104+0x1p52);
    /* ONE accumulator per column: acc[c] = Σ lo-bits(products at c) +
       Σ hi-bits(products at c-1). init = -(n_lo*B_LO + n_hi*B_HI) where
       n_lo = pairs(i+j=c), n_hi = pairs(i+j=c-1). pairs c: 1,2,3,4,5,4,3,2,1 */
    static const int np[9]={1,2,3,4,5,4,3,2,1};
    vi acc[10];
    for(int c=0;c<9;c++){
        int nl=np[c], nh=c?np[c-1]:0;
        acc[c]=_mm256_set1_epi64x(-((int64_t)nl*B_LO+(int64_t)nh*B_HI));
    }
    acc[9]=_mm256_set1_epi64x(-(int64_t)np[8]*B_HI); /* col9: only hi of col8 */
    for(int i=0;i<5;i++) for(int j=0;j<5;j++){
        int c=i+j;
        vd hi=_mm256_fmadd_pd(a[i],b[j],C1);
        vd ad=_mm256_sub_pd(C2,hi);
        vd lo=_mm256_fmadd_pd(a[i],b[j],ad);
        acc[c]  =_mm256_add_epi64(acc[c]  ,_mm256_castpd_si256(lo));
        acc[c+1]=_mm256_add_epi64(acc[c+1],_mm256_castpd_si256(hi));
    }
    /* carry-resolve */
    vi O[10],car=_mm256_setzero_si256(),m52=M52v;
    for(int c=0;c<10;c++){
        vi t=_mm256_add_epi64(acc[c],car);
        O[c]=_mm256_and_si256(t,m52);
        car=_mm256_srli_epi64(t,52);
    }
    vi F[6]; for(int i=0;i<6;i++)F[i]=_mm256_setzero_si256();
    for(int c=5;c<10;c++){
        vi lo,hi; fold16C(O[c],&lo,&hi);
        F[c-5]=_mm256_add_epi64(F[c-5],lo);
        F[c-4]=_mm256_add_epi64(F[c-4],hi);
    }
    {
        vi x4=_mm256_srli_epi64(O[4],48);
        vi g =mulC_small(x4);
        F[0]=_mm256_add_epi64(F[0],_mm256_and_si256(g,m52));
        F[1]=_mm256_add_epi64(F[1],_mm256_srli_epi64(g,52));
    }
    for(int it=0;it<3;it++){
        vi lo,hi; fold16C(F[5],&lo,&hi);
        F[0]=_mm256_add_epi64(F[0],lo);
        F[1]=_mm256_add_epi64(F[1],hi);
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
        vi g=mulC_small(c2);
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
static void fe4_sqr4(fe4 r, const fe4 ai){
    vd a[5];
    for(int i=0;i<5;i++)a[i]=i2d(ai[i]);
    vd C1=_mm256_set1_pd(0x1p104), C2=_mm256_set1_pd(0x1p104+0x1p52);
    static const int nd[9]={1,0,1,0,1,0,1,0,1}, no[9]={0,1,1,2,2,2,1,1,0};
    vi Ho[9],Lo[9],Hd[9],Ld[9];
    for(int k=0;k<9;k++){
        Ho[k]=_mm256_set1_epi64x(-(int64_t)no[k]*B_HI);
        Lo[k]=_mm256_set1_epi64x(-(int64_t)no[k]*B_LO);
        Hd[k]=_mm256_set1_epi64x(-(int64_t)nd[k]*B_HI);
        Ld[k]=_mm256_set1_epi64x(-(int64_t)nd[k]*B_LO);
    }
    for(int i=0;i<5;i++){
        { vd hi=_mm256_fmadd_pd(a[i],a[i],C1);
          vd ad=_mm256_sub_pd(C2,hi);
          vd lo=_mm256_fmadd_pd(a[i],a[i],ad);
          int c=2*i;
          Hd[c]=_mm256_add_epi64(Hd[c],_mm256_castpd_si256(hi));
          Ld[c]=_mm256_add_epi64(Ld[c],_mm256_castpd_si256(lo)); }
        for(int j=i+1;j<5;j++){
            vd hi=_mm256_fmadd_pd(a[i],a[j],C1);
            vd ad=_mm256_sub_pd(C2,hi);
            vd lo=_mm256_fmadd_pd(a[i],a[j],ad);
            int c=i+j;
            Ho[c]=_mm256_add_epi64(Ho[c],_mm256_castpd_si256(hi));
            Lo[c]=_mm256_add_epi64(Lo[c],_mm256_castpd_si256(lo));
        }
    }
    vi O[10],car=_mm256_setzero_si256(),m52=M52v;
    for(int c=0;c<9;c++){
        vi lo=_mm256_add_epi64(Ld[c],_mm256_add_epi64(Lo[c],Lo[c]));
        vi hh=_mm256_add_epi64(c?Hd[c-1]:_mm256_setzero_si256(),
                                 c?_mm256_add_epi64(Ho[c-1],Ho[c-1]):_mm256_setzero_si256());
        vi t=_mm256_add_epi64(_mm256_add_epi64(lo,hh),car);
        O[c]=_mm256_and_si256(t,m52);
        car=_mm256_srli_epi64(t,52);
    }
    { vi hh=_mm256_add_epi64(Hd[8],_mm256_add_epi64(Ho[8],Ho[8]));
      O[9]=_mm256_add_epi64(hh,car); }
    vi F[6]; for(int i=0;i<6;i++)F[i]=_mm256_setzero_si256();
    for(int c=5;c<10;c++){
        vi lo,hi; fold16C(O[c],&lo,&hi);
        F[c-5]=_mm256_add_epi64(F[c-5],lo);
        F[c-4]=_mm256_add_epi64(F[c-4],hi);
    }
    {
        vi x4=_mm256_srli_epi64(O[4],48);
        vi g =mulC_small(x4);
        F[0]=_mm256_add_epi64(F[0],_mm256_and_si256(g,m52));
        F[1]=_mm256_add_epi64(F[1],_mm256_srli_epi64(g,52));
    }
    for(int it=0;it<3;it++){
        vi lo,hi; fold16C(F[5],&lo,&hi);
        F[0]=_mm256_add_epi64(F[0],lo);
        F[1]=_mm256_add_epi64(F[1],hi);
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
        vi g=mulC_small(c2);
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
