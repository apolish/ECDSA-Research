1. HYP-001 on independent uniform triples (a, s_zk, s) < 2^bits
   2^17 : gated 0.511 %   weak form 1.091 % (x2.13)   ungated 8.02 %
   2^64 : gated 0.483 %   weak form 1.081 % (x2.24)   ungated 8.01 %
            q = floor(a/w) in the gated population:
              q=1: 0.4363   Gauss-Kuzmin 0.4150   1/(q(q+1)) 0.5000
              q=2: 0.1691   Gauss-Kuzmin 0.1699   1/(q(q+1)) 0.1667
              q=3: 0.0923   Gauss-Kuzmin 0.0931   1/(q(q+1)) 0.0833
              q=4: 0.0558   Gauss-Kuzmin 0.0589   1/(q(q+1)) 0.0500
              q=5: 0.0395   Gauss-Kuzmin 0.0406   1/(q(q+1)) 0.0333
   2^256: gated 0.503 %   weak form 1.097 % (x2.18)   ungated 8.02 %
   2^512: gated 0.500 %   weak form 1.105 % (x2.21)   ungated 8.05 %
   [7.7s]
2. Case-B formula event built directly (README Known issue 3)
   secp17k1: 200/200 keys recovered by the B formula; labels {'D': 200}; 4.5 nonce trials each; 1 ms each
   secp256k1: 20/20 keys recovered by the B formula; labels {'D': 20}; 4.5 nonce trials each; 359 ms each
   [7.5s]
3. Class-A construction on secp256k1
   1.02 nonces per signature over 60; P = k*r odd 35, even 25
   [4.9s]
4. Unverified common-key search over random 4-transaction bundles
   150 bundles: 3.81 impostors per bundle unverified, 0.00 verified
   [17.3s]
