# Row-major 4x64 carry-chain simulator — used to verify the flag
# discipline of fe_mul_4x64_asm.S before writing the asm.
# Models CF (adcx) and OF (adox) as independent carry chains over a
# column array; row j adds a[i]*b[j] products: lo->col i+j via adcx,
# hi->col i+j+1 via adox; row ends resolve pending CF/OF into the
# next columns. Matches the asm's structure exactly.
M=(1<<64)-1
def sim_rowmajor(a,b):
    m=[0]*10; CF=OF=0
    def adcx(idx,s):
        nonlocal CF; t=m[idx]+s+CF; CF=1 if t>M else 0; m[idx]=t&M
    def adox(idx,s):
        nonlocal OF; t=m[idx]+s+OF; OF=1 if t>M else 0; m[idx]=t&M
    for j in range(4):
        for i in range(4):
            lo=(a[i]*b[j])&M; hi=(a[i]*b[j])>>64
            adcx(i+j,lo); adox(i+j+1,hi)
        adcx(j+4,0); adcx(j+5,0)
        adox(j+5,0); adox(j+6,0)
    return m
if __name__ == "__main__":
    import random
    for t in range(100000):
        a=[random.getrandbits(64) for _ in range(4)]
        b=[random.getrandbits(64) for _ in range(4)]
        got=sim_rowmajor(a,b)
        prod=sum(a[i]<<(64*i) for i in range(4))*sum(b[i]<<(64*i) for i in range(4))
        want=[(prod>>(64*i))&M for i in range(8)]+[0,0]
        assert got==want, (a,b)
    print("rowmajor scheme: 100K cases correct")
