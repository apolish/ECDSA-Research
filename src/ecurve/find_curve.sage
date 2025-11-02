p = 1241690119
F = GF(p)

print("🔍 Starting search for elliptic curves with large prime-order subgroups...")

min_n = 10^8  # limit for a large prime order

for a in range(50):
    for b in range(1, 50):
        try:
            E = EllipticCurve(F, [a, b])
            N = E.order()
            factors = factor(N)
            for f, m in factors:
                if f > min_n and f.is_prime():
                    n = f
                    h = N // n
                    print(f"🧩 Found suitable curve: a={a}, b={b}, #E={N}, n={n}, h={h}")
                    for attempt in range(50):
                        P = E.random_point()
                        G = h * P
                        if G.order() == n and G[0] > 1000 and G[1] > 1000:
                            print("✅ Found generator:")
                            print(f"G = ({G[0]}, {G[1]})")
                            print(f"G.order() = {G.order()}")
                            break
                    break  # one simple divisor per curve is enough
        except Exception as e:
            continue
