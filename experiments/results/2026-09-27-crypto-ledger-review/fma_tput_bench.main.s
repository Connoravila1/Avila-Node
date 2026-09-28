.LFB7303:
	.cfi_startproc
	endbr64
	leaq	8(%rsp), %r10
	.cfi_def_cfa 10, 0
	andq	$-32, %rsp
	movl	$1, %edi
	pushq	-8(%r10)
	pushq	%rbp
	movq	%rsp, %rbp
	.cfi_escape 0x10,0x6,0x2,0x76,0
	pushq	%r13
	pushq	%r12
	pushq	%r10
	.cfi_escape 0xf,0x3,0x76,0x68,0x6
	.cfi_escape 0x10,0xd,0x2,0x76,0x78
	.cfi_escape 0x10,0xc,0x2,0x76,0x70
	pushq	%rbx
	subq	$112, %rsp
	.cfi_escape 0x10,0x3,0x2,0x76,0x60
	movq	%fs:40, %rsi
	movq	%rsi, -56(%rbp)
	leaq	-80(%rbp), %rsi
	call	clock_gettime@PLT
	vxorpd	%xmm5, %xmm5, %xmm5
	vcvtsi2sdq	-72(%rbp), %xmm5, %xmm0
	vcvtsi2sdq	-80(%rbp), %xmm5, %xmm1
	vmulsd	.LC2(%rip), %xmm0, %xmm0
	movl	$200000000, %eax
	vbroadcastsd	.LC1(%rip), %ymm2
	vaddsd	%xmm1, %xmm0, %xmm6
	vbroadcastsd	.LC4(%rip), %ymm1
	vbroadcastsd	.LC6(%rip), %ymm0
	vmovsd	%xmm6, -104(%rbp)
	.p2align 4
	.p2align 4
	.p2align 3
.L2:
	vfmadd132pd	%ymm1, %ymm0, %ymm2
	vfmadd132pd	%ymm1, %ymm0, %ymm2
	subq	$2, %rax
	jne	.L2
	leaq	-80(%rbp), %rsi
	movl	$1, %edi
	movl	$3, %ebx
	vmovapd	%ymm2, -144(%rbp)
	vzeroupper
	call	clock_gettime@PLT
	vxorpd	%xmm3, %xmm3, %xmm3
	vcvtsi2sdq	-72(%rbp), %xmm3, %xmm0
	vcvtsi2sdq	-80(%rbp), %xmm3, %xmm1
	vmulsd	.LC2(%rip), %xmm0, %xmm0
	vmovsd	.LC7(%rip), %xmm6
	leaq	.LC10(%rip), %rsi
	movl	$2, %edi
	movl	$2, %eax
	movl	$23, %r12d
	vaddsd	%xmm1, %xmm0, %xmm0
	vsubsd	-104(%rbp), %xmm0, %xmm0
	vdivsd	%xmm0, %xmm6, %xmm0
	vdivsd	.LC8(%rip), %xmm0, %xmm0
	vmulsd	.LC9(%rip), %xmm0, %xmm1
	call	__printf_chk@PLT
	leaq	-80(%rbp), %rsi
	movl	$1, %edi
	vmovapd	-144(%rbp), %ymm2
	vextractf128	$0x1, %ymm2, %xmm0
	vunpckhpd	%xmm0, %xmm0, %xmm0
	vaddsd	%xmm0, %xmm2, %xmm1
	vmovsd	%xmm1, -88(%rbp)
	vzeroupper
	call	clock_gettime@PLT
	vxorpd	%xmm3, %xmm3, %xmm3
	vcvtsi2sdq	-72(%rbp), %xmm3, %xmm0
	vmulsd	.LC2(%rip), %xmm0, %xmm0
	vcvtsi2sdq	-80(%rbp), %xmm3, %xmm1
	movl	$200000000, %eax
	movabsq	$-2401053089206453570, %rcx
	movabsq	$-2401053089206453563, %rdx
	vaddsd	%xmm1, %xmm0, %xmm7
	vmovsd	%xmm7, -104(%rbp)
	.p2align 4
	.p2align 4
	.p2align 3
.L3:
	imulq	%rcx, %rbx
	imulq	%rdx, %r12
	subq	$1, %rax
	jne	.L3
	leaq	-80(%rbp), %rsi
	movl	$1, %edi
	addq	%r12, %rbx
	call	clock_gettime@PLT
	vxorpd	%xmm4, %xmm4, %xmm4
	vcvtsi2sdq	-72(%rbp), %xmm4, %xmm0
	vcvtsi2sdq	-80(%rbp), %xmm4, %xmm1
	vmulsd	.LC2(%rip), %xmm0, %xmm0
	movl	$2, %edi
	movl	$1, %eax
	vmovsd	.LC7(%rip), %xmm7
	leaq	.LC11(%rip), %rsi
	vaddsd	%xmm1, %xmm0, %xmm0
	vsubsd	-104(%rbp), %xmm0, %xmm0
	vdivsd	%xmm0, %xmm7, %xmm0
	vdivsd	.LC8(%rip), %xmm0, %xmm0
	call	__printf_chk@PLT
	movq	%rbx, -80(%rbp)
	movq	-80(%rbp), %rax
	vmovsd	-88(%rbp), %xmm1
	testq	%rax, %rax
	js	.L4
	vxorpd	%xmm4, %xmm4, %xmm4
	vcvtsi2sdq	%rax, %xmm4, %xmm0
.L5:
	vaddsd	%xmm1, %xmm0, %xmm0
	vcvttsd2sil	%xmm0, %eax
	movq	-56(%rbp), %rdx
	subq	%fs:40, %rdx
	jne	.L12
	addq	$112, %rsp
	popq	%rbx
	popq	%r10
	.cfi_remember_state
	.cfi_def_cfa 10, 0
	popq	%r12
	popq	%r13
	popq	%rbp
	leaq	-8(%r10), %rsp
	.cfi_def_cfa 7, 8
	ret
.L4:
	.cfi_restore_state
	movq	%rax, %rdx
	andl	$1, %eax
	vxorpd	%xmm6, %xmm6, %xmm6
	shrq	%rdx
	orq	%rax, %rdx
	vcvtsi2sdq	%rdx, %xmm6, %xmm0
	vaddsd	%xmm0, %xmm0, %xmm0
	jmp	.L5
.L12:
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE7303: