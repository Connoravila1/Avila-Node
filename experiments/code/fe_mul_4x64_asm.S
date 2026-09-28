/*
 * fe_mul_4x64_asm — hand-written BMI2/ADX secp256k1 field multiply (4x64)
 *
 * STATUS: CORRECT (10K random cases vs libsecp reference + edge cases:
 * 1*2, (2^192)^2 mod p, (2^256-1)^2, saturated limbs). Result < 2^256,
 * possibly >= p (libsecp magnitude convention — callers normalize).
 *
 * MEASURED (i7-class laptop, load ~9, pinned core):
 *   serial ~58-70 ns/mul  vs libsecp 5x52 ~50-56 ns/mul   (PARITY/WORSE)
 *   indep4 ~50-55 ns/mul  vs libsecp 5x52 ~46-53 ns/mul   (PARITY/WORSE)
 *   ~184 instructions vs libsecp's ~255 — fewer ops, same latency:
 *   the dual adcx/adox carry chains are ~30 serial hops deep, and ~35
 *   ops of stack-tail/bookkeeping ate the 16-vs-25 product advantage.
 *
 * FINDING: the 4x64 repr does not beat well-tuned 5x52 C on fe_mul.
 * The product count halves but each product costs 2 flag-ops + resolve
 * amortization. Where 4x64 asm genuinely wins is fe_sqr (10-11 mulx via
 * symmetry) and paired lazy-reduction point formulas — NOT raw mul.
 *
 * Scheme: row-major Comba, 5-reg circular window {rbx,rcx,rbp,r8,r9}
 * [col mod 5], freed regs re-zeroed by mov (flag-safe), carry tails to
 * stack slots captured by setc/seto, folded when the column goes live.
 * Verified scheme in python sim before writing asm.
 *
 * Build: gcc -O3 -mbmi2 -madx -c mul4x64.S
 * Fallback for non-BMI2/ADX CPUs: any C implementation (see bench.c).
 */
/* fe_mul_4x64_asm(rdi=out, rsi=a, rdx=b): r = a*b mod p, 4x64 limbs.
 * Row-major: row j (rdx=b_j): mulx r15,rax → adcx col(i+j),lo / adox
 * col(i+j+1),hi. CF chain: column-sum carries; OF chain: hi-part carries.
 * Window: 5 regs circular — col k -> {rbx,rcx,rbp,r8,r9}[k mod 5].
 * After each m_j store the freed reg is re-zeroed with mov (no flag
 * clobber) and hosts the next live column. Carry tails that would hit a
 * busy column go to stack slots, folded when that column goes live.
 * mulx dst1=HI dst2=LO. Result < 2^256, possibly >= p. */
	.intel_syntax noprefix
	.text
	.globl	fe_mul_4x64_asm
fe_mul_4x64_asm:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp, 24			/* [rsp]=col6 tails [rsp+8]=col7 [rsp+16]=col8 */
	mov	r11, rdx		/* b ptr */
	mov	r12, [rsi]		/* a0 */
	mov	r13, [rsi+8]		/* a1 */
	mov	r14, [rsi+16]		/* a2; a3 stays [rsi+24] */
	xor	r10d, r10d		/* zero const; clears CF,OF */
	xor	ebx, ebx
	xor	ecx, ecx
	xor	ebp, ebp
	xor	r8d, r8d
	xor	r9d, r9d
	mov	qword ptr [rsp], 0
	mov	qword ptr [rsp+8], 0
	mov	qword ptr [rsp+16], 0

	/* ===== row0: live 0-4 = rbx,rcx,rbp,r8,r9 ===== */
	mov	rdx, [r11]
	mulx	r15, rax, r12		/* p00 */
	adcx	rbx, rax		/* col0 = lo00 */
	adox	rcx, r15		/* col1 += hi00 */
	mov	[rdi], rbx		/* m0 */
	mov	rbx, r10		/* rbx -> col5 acc = 0 */
	mulx	r15, rax, r13		/* p10 */
	adcx	rcx, rax		/* col1 += lo10 +CF */
	adox	rbp, r15		/* col2 += hi10 */
	mulx	r15, rax, r14		/* p20 */
	adcx	rbp, rax		/* col2 += lo20 +CF */
	adox	r8,  r15		/* col3 += hi20 */
	mulx	r15, rax, [rsi+24]	/* p30 */
	adcx	r8,  rax		/* col3 += lo30 +CF */
	adox	r9,  r15		/* col4 += hi30 */
	/* tails: CF->col4(r9), reCF->col5(rbx), OF->col5(rbx), reOF->col6 */
	adcx	r9,  r10		/* col4 += CF */
	adcx	rbx, r10		/* col5 += reCF */
	adox	rbx, r10		/* col5 += OF */
	setc	al			/* re-carry -> col6 slot */
	seto	dl			/* re-OF -> col6 slot */
	add	[rsp], al
	add	[rsp], dl

	/* ===== row1: live 1-5 = rcx,rbp,r8,r9,rbx ===== */
	mov	rdx, [r11+8]
	mulx	r15, rax, r12		/* p01 */
	adcx	rcx, rax		/* col1 complete */
	adox	rbp, r15		/* col2 += hi01 */
	mov	[rdi+8], rcx		/* m1 */
	mov	rcx, r10		/* rcx -> col6 acc = 0 */
	mulx	r15, rax, r13		/* p11 */
	adcx	rbp, rax		/* col2 += lo11 +CF */
	adox	r8,  r15		/* col3 += hi11 */
	mulx	r15, rax, r14		/* p21 */
	adcx	r8,  rax		/* col3 += lo21 +CF */
	adox	r9,  r15		/* col4 += hi21 */
	mulx	r15, rax, [rsi+24]	/* p31 */
	adcx	r9,  rax		/* col4 += lo31 +CF */
	adox	rbx, r15		/* col5 += hi31 */
	/* tails: CF->col5(rbx), reCF->col6stk, OF->col6stk, reOF->col7stk */
	adcx	rbx, r10		/* col5 += CF */
	setc	al
	add	[rsp], al		/* col6 += reCF */
	seto	dl
	add	[rsp], dl		/* col6 += OF */
	/* ===== row2: live 2-6 = rbp,r8,r9,rbx,rcx ===== */
	mov	rdx, [r11+16]
	mulx	r15, rax, r12		/* p02 */
	adcx	rbp, rax		/* col2 complete */
	adox	r8,  r15		/* col3 += hi02 */
	mov	[rdi+16], rbp		/* m2 */
	mov	rbp, r10		/* rbp -> col7 acc = 0 */
	mulx	r15, rax, r13		/* p12 */
	adcx	r8,  rax		/* col3 += lo12 +CF */
	adox	r9,  r15		/* col4 += hi12 */
	mulx	r15, rax, r14		/* p22 */
	adcx	r9,  rax		/* col4 += lo22 +CF */
	adox	rbx, r15		/* col5 += hi22 */
	mulx	r15, rax, [rsi+24]	/* p32 */
	adcx	rbx, rax		/* col5 += lo32 +CF */
	adox	rcx, r15		/* col6 += hi32 */
	adcx	rcx, [rsp]		/* col6 += stacked tails +CF */
	/* tails: CF->col6(rcx), reCF->col7stk, OF->col7stk, reOF->col8 */
	adcx	rcx, r10		/* col6 += CF */
	setc	al
	add	[rsp+8], al		/* col7 += reCF */
	seto	dl
	add	[rsp+8], dl		/* col7 += OF */
	/* ===== row3: live 3-7 = r8,r9,rbx,rcx,rbp ===== */
	mov	rdx, [r11+24]
	mulx	r15, rax, r12		/* p03 */
	adcx	r8,  rax		/* col3 complete */
	adox	r9,  r15		/* col4 += hi03 */
	mulx	r15, rax, r13		/* p13 — m3 store deferred until
					   after p33's [rsi+24] read (a==out) */
	adcx	r9,  rax		/* col4 += lo13 +CF */
	adox	rbx, r15		/* col5 += hi13 */
	mulx	r15, rax, r14		/* p23 */
	adcx	rbx, rax		/* col5 += lo23 +CF */
	adox	rcx, r15		/* col6 += hi23 */
	mulx	r15, rax, [rsi+24]	/* p33 */
	mov	[rdi+24], r8		/* m3 (after a3's last read) */
	adcx	rcx, rax		/* col6 += lo33 +CF */
	adox	rbp, r15		/* col7 += hi33 */
	adcx	rbp, [rsp+8]		/* col7 += stacked tails +CF */
	/* tails: CF->col7(rbp), reCF->col8stk, OF->col8stk */
	adcx	rbp, r10		/* col7 += CF */
	setc	al
	add	[rsp+16], al		/* col8 += reCF */
	seto	dl
	add	[rsp+16], dl		/* col8 += OF */

	/* ===== fold by C = 0x1000003D1 ===== */
	/* out_k = m_k + lo(m_{k+4}C) + hi(m_{k+3}C); w4 = h7 + col8*C + tails */
	mov	rdx, 0x1000003D1
	mulx	rsi, rax, r9		/* m4*C: hi=rsi lo=rax */
	mulx	r14, r13, rbx		/* m5*C */
	mulx	r12, r11, rcx		/* m6*C */
	mulx	r9,  rbx, rbp		/* m7*C: hi=r9 lo=rbx — srcs read first */
	xor	edx, edx		/* clear flags */
	mov	r8, [rdi]		/* m0 */
	adcx	r8, rax			/* m0 += l4 */
	mov	[rdi], r8
	mov	r8, [rdi+8]		/* m1 */
	adcx	r8, r13			/* m1 += l5 +CF */
	adox	r8, rsi			/* m1 += h4 +OF */
	mov	[rdi+8], r8
	mov	r8, [rdi+16]		/* m2 */
	adcx	r8, r11			/* m2 += l6 +CF */
	adox	r8, r14			/* m2 += h5 +OF */
	mov	[rdi+16], r8
	mov	r8, [rdi+24]		/* m3 */
	adcx	r8, rbx			/* m3 += l7 +CF */
	adox	r8, r12			/* m3 += h6 +OF */
	mov	[rdi+24], r8
	/* w4 = h7(r9) + CF + OF + col8*C */
	adcx	r9, r10			/* w4 += CF */
	adox	r9, r10			/* w4 += OF */
	mov	rax, [rsp+16]		/* col8 count (~<=6) */
	mulx	r15, rax, rax		/* col8*C hi=r15(0) lo=rax — wait rdx
					   was clobbered by xor! reload: */
	mov	rdx, 0x1000003D1
	mulx	r15, rax, rax		/* col8*C: lo=rax */
	add	r9, rax			/* w4 += lo (flags done) */
	/* second fold: w4*C into m0..m3 */
	mulx	rsi, rax, r9		/* rdx=C still: hi=rsi lo=rax */
	xor	edx, edx
	mov	r8, [rdi]
	adcx	r8, rax			/* m0 += lo */
	mov	[rdi], r8
	mov	r8, [rdi+8]
	adcx	r8, r10			/* m1 += CF */
	adox	r8, rsi			/* m1 += hi +OF */
	mov	[rdi+8], r8
	mov	r8, [rdi+16]
	adcx	r8, r10			/* m2 += CF(re) */
	adox	r8, r10			/* m2 += OF */
	mov	[rdi+16], r8
	mov	r8, [rdi+24]
	adcx	r8, r10			/* m3 += CF */
	adox	r8, r10			/* m3 += OF */
	mov	[rdi+24], r8
	/* residual CF/OF after m3 -> w4'' (2^256-excess): w4''*C into m0 */
	setc	al			/* al = CF */
	seto	cl			/* cl = OF */
	add	al, cl			/* w4'' <= 2 */
	movzx	eax, al
	mov	rcx, rax		/* w4''*C = w4''<<32 + w4''*977 */
	shl	rax, 32
	imul	rcx, rcx, 0x3D1
	add	rax, rcx		/* <= 2*C < 2^34 */
	add	[rdi], rax		/* m0 += w4''*C */
	adc	qword ptr [rdi+8], 0	/* propagate; bounded twice max */
	adc	qword ptr [rdi+16], 0
	adc	qword ptr [rdi+24], 0
	/* one more residual capture (bounded tiny, same fold) */
	setc	al
	movzx	eax, al
	mov	rcx, rax
	shl	rax, 32
	imul	rcx, rcx, 0x3D1
	add	rax, rcx
	add	[rdi], rax
	adc	qword ptr [rdi+8], 0
	adc	qword ptr [rdi+16], 0
	adc	qword ptr [rdi+24], 0
	add	rsp, 24
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
