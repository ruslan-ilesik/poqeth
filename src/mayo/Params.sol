// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// Constants and parameters are declared here according to the specified security levels
// See the note below
contract Params {
    struct MayoParams {
        uint prime;
        uint prime_bits;
        uint m;
        uint n;
        uint o;
        uint k;
        uint kc2;
        uint monomials;
        uint p1monomials;
        uint p2monomials;
        uint seed_bytes;
        uint hash_bytes;
        uint oil_space_bytes;
        uint pk_bytes;
        uint sk_bytes;
        uint sk_exp_bytes;
        uint p1_bytes;
        uint p2_bytes;
    }

    MayoParams public MAYO1_params;

    constructor() {
        MAYO1_params = MayoParams({
            prime: 31,
            prime_bits: 5,
            m: 60, // 60
            n: 62, // 62
            o: 6, // 6
            k: 10, // 10
            monomials: 0, // 1953; n*n triangular mx item count
            kc2: 0, // 55; k*k triangular mx item count
            p1monomials: 0, // 1932
            p2monomials: 0, // 21; o*o triangular mx item count
            seed_bytes: 16,
            hash_bytes: 32,
            oil_space_bytes: 0, // 336
            pk_bytes: 0, // 1276
            sk_bytes: 0, // 32
            sk_exp_bytes: 0, // 136416
            p1_bytes: 0, // 115920
            p2_bytes: 0 // 1260
        });
        // Calculate dependent fields
        MAYO1_params.monomials = (MAYO1_params.n * (MAYO1_params.n + 1)) / 2;
        MAYO1_params.kc2 = (MAYO1_params.k * (MAYO1_params.k + 1)) / 2;
        MAYO1_params.p1monomials =
            ((MAYO1_params.n - MAYO1_params.o) *
                (MAYO1_params.n - MAYO1_params.o + 1)) /
            2 +
            (MAYO1_params.n - MAYO1_params.o) *
            MAYO1_params.o;
        MAYO1_params.p2monomials = (MAYO1_params.o * (MAYO1_params.o + 1)) / 2;
        MAYO1_params.p1_bytes = MAYO1_params.m * MAYO1_params.p1monomials;
        MAYO1_params.p2_bytes = MAYO1_params.m * MAYO1_params.p2monomials;
        MAYO1_params.oil_space_bytes =
            MAYO1_params.o *
            (MAYO1_params.n - MAYO1_params.o);
        MAYO1_params.sk_exp_bytes =
            MAYO1_params.p1_bytes +
            MAYO1_params.oil_space_bytes +
            (MAYO1_params.m *
                (MAYO1_params.n - MAYO1_params.o) *
                MAYO1_params.o);
        MAYO1_params.pk_bytes =
            MAYO1_params.seed_bytes +
            (MAYO1_params.m * MAYO1_params.o * (MAYO1_params.o + 1)) /
            2;
        MAYO1_params.sk_bytes = 2 * MAYO1_params.seed_bytes;
    }

    // NOTE --- Declare here the required parameterlist ---
    function getParams() public view returns (MayoParams memory) {
        return MAYO1_params; // <----------------- Change this to the desired parameter set
    }
}
