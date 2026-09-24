"""First-spy simulation for selfish-stem relay.

Model: N nodes, each with K random outbound links (random-regular-ish
graph). A fraction f of nodes are spies. A victim node V originates a
tx. Propagation: node receiving a tx inv announces to all its links
after a per-link delay (inv relay ~ uniform 2-5s poisson-ish, modeled
uniform). The first spy to see the tx records the *sender* as a suspect.

Without stem: V announces to all K neighbors at t=0 — a spy neighbor
of V learns it from V directly; the sender (V) is correctly named.

With 1-hop stem: V sends ONLY to stem peer S at t=0. S fluffs to its
neighbors at t=D (D ~ U[2,15]s). V fluffs its own links at t=D too
(the implementation fluffs after the same delay). Spies connected to
V now see V announce ~simultaneously with everyone else — V looks like
a relayer, not the source. But note: if V's own fluff at t=D still
reaches a spy BEFORE S's propagation wave reaches that spy, the spy
still flags V. The question the sim answers: how often does a spy's
*earliest* observation point at V?

Metric: over R runs, P(spy names V) = fraction of runs where the
earliest spy observation arrived on a link whose sender is V.
"""
import random, heapq

N = 300          # nodes
K = 8            # outbound links each
F = 0.15         # spy fraction
R = 4000         # runs
LINK_DELAY = (1.5, 4.0)   # per-link inv relay delay, seconds (uniform)

def run(stem: bool) -> bool:
    g = {i: random.sample([j for j in range(N) if j != i], K) for i in range(N)}
    inbound = {i: set() for i in range(N)}
    for i, outs in g.items():
        for j in outs:
            inbound[j].add(i)
    spies = set(random.sample(range(N), int(N * F)))
    if not spies:
        return False
    v = random.randrange(N)

    # Event sim: (time, sender, receiver)
    seen_by = {}            # node -> earliest (t, sender)
    pq = []
    if stem:
        s = random.choice(g[v])  # stem hop is an outbound peer
        heapq.heappush(pq, (0.0, v, s))
        # V's own fluff after stem delay
        d = random.uniform(2.0, 15.0)
        for nb in g[v]:
            heapq.heappush(pq, (d + random.uniform(*LINK_DELAY), v, nb))
    else:
        for nb in g[v]:
            heapq.heappush(pq, (0.0 + random.uniform(*LINK_DELAY), v, nb))

    done = set()
    first_spy_obs = None  # (t, sender)
    while pq:
        t, src, dst = heapq.heappop(pq)
        if dst in done:
            continue
        done.add(dst)
        if dst in spies:
            if first_spy_obs is None or t < first_spy_obs[0]:
                first_spy_obs = (t, src)
            continue  # spies don't re-propagate (conservative: they log only)
        for nb in g[dst]:
            if nb not in done:
                heapq.heappush(pq, (t + random.uniform(*LINK_DELAY), dst, nb))
    return first_spy_obs is not None and first_spy_obs[1] == v

for stem in (False, True):
    hits = sum(run(stem) for _ in range(R))
    print(f"stem={stem}: P(first spy names origin) = {hits/R:.3f}")
