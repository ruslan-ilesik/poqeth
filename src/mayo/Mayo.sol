// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Utils.sol";
import "./Params.sol";

contract Mayo {
    Utils public utils;
    Params.MayoParams public params;

    constructor(Params.MayoParams memory _params) {
        params = _params;
        utils = new Utils(params);
    }

    function sample_oil_space(
        Params.MayoParams memory par,
        bytes memory seed,
        bytes memory oil_space
    ) public view returns (bytes memory) {
        oil_space = utils.reduce(
            utils.expand(seed, par.oil_space_bytes),
            par.prime
        );
        return oil_space;
    }

    function keygen(
        Params.MayoParams memory par,
        bytes calldata random_seed
    ) public view returns (bytes memory, bytes memory) {
        bytes memory pk = new bytes(par.pk_bytes);
        bytes memory sk = new bytes(par.sk_bytes);
        bytes memory new_seed = utils.reduce(
            utils.expand(random_seed, par.seed_bytes * 2),
            par.prime
        );
        for (uint i = 0; i < par.seed_bytes * 2; i++) {
            sk[i] = new_seed[i];
        }
        for (uint i = 0; i < par.seed_bytes; i++) {
            pk[i] = sk[i];
        }
        bytes memory P1 = new bytes(par.p1_bytes);
        P1 = expand_pk(par, pk);

        bytes memory oil_space = new bytes(par.oil_space_bytes);
        bytes memory private_seed = new bytes(par.seed_bytes);
        for (uint i = 0; i < par.seed_bytes; i++) {
            private_seed[i] = sk[i + par.seed_bytes];
        }
        oil_space = sample_oil_space(par, private_seed, oil_space);

        bytes memory pk_p2 = new bytes(pk.length - par.seed_bytes);
        bytes memory P2 = new bytes(par.p2_bytes);
        P2 = computeP2(par, oil_space, P1, pk_p2);
        for (uint i = 0; i < par.p2_bytes; i++) {
            pk[par.seed_bytes + i] = P2[i];
        }
        return (pk, sk);
    }

    function computeP2(
        Params.MayoParams memory par,
        bytes memory oil_space,
        bytes memory P1,
        bytes memory P2
    ) public view returns (bytes memory) {
        bytes memory temp = new bytes(par.m * (par.n - par.o) * par.o);
        uint p1_counter = 0;
        for (uint i = 0; i < par.n - par.o; ++i) {
            for (uint j = 0; j < par.o; ++j) {
                bytes memory p1_slice = new bytes(
                    par.p1_bytes - p1_counter * par.m
                );
                for (uint k = 0; k < p1_slice.length; k++) {
                    p1_slice[k] = P1[p1_counter * par.m + k];
                }
                bytes memory oil_space_slice = new bytes(
                    par.oil_space_bytes - (j * (par.n - par.o) + i)
                );
                for (uint k = 0; k < oil_space_slice.length; k++) {
                    oil_space_slice[k] = oil_space[
                        (j * (par.n - par.o) + i) + k
                    ];
                }
                bytes memory vec = utils.linear_combination(
                    p1_slice,
                    oil_space_slice,
                    par.n - par.o - i,
                    par.prime,
                    par.m
                );
                bytes memory temp_slice = new bytes(
                    temp.length - (i * par.o + j) * par.m
                );
                for (uint k = 0; k < temp_slice.length; k++) {
                    temp_slice[k] = temp[(i * par.o + j) * par.m + k];
                }
                temp_slice = utils.add_vectors(par, temp_slice, vec);
                for (uint k = 0; k < temp_slice.length; k++) {
                    temp[(i * par.o + j) * par.m + k] = temp_slice[k];
                }
            }
            p1_counter += par.n - par.o - i;
        }

        for (uint i = 0; i < par.n - par.o; ++i) {
            for (uint j = 0; j < par.o; j++) {
                bytes memory temp_slice = new bytes(
                    temp.length - (i * par.o + j) * par.m
                );
                for (uint k = 0; k < temp_slice.length; k++) {
                    temp_slice[k] = temp[(i * par.o + j) * par.m + k];
                }
                bytes memory p1_slice = new bytes(
                    par.p1_bytes - p1_counter * par.m
                );
                for (uint k = 0; k < p1_slice.length; k++) {
                    p1_slice[k] = P1[p1_counter * par.m + k];
                }
                temp_slice = utils.add_vectors(par, temp_slice, p1_slice);
                for (uint k = 0; k < temp_slice.length; k++) {
                    temp[(i * par.o + j) * par.m + k] = temp_slice[k];
                }
                p1_counter++;
            }
        }

        bytes memory tempt = new bytes(par.m * (par.n - par.o) * par.o);
        for (uint i = 0; i < par.o; ++i) {
            for (uint j = 0; j < par.n - par.o; j++) {
                for (uint k = 0; k < par.m; k++) {
                    tempt[(i * (par.n - par.o) + j) * par.m + k] = temp[
                        (j * par.o + i) * par.m + k
                    ];
                }
            }
        }

        uint counter = 0;
        for (uint i = 0; i < par.o; ++i) {
            for (uint j = i; j < par.o; ++j) {
                bytes memory tempt_slice = new bytes(
                    tempt.length - (j * (par.n - par.o)) * par.m
                );
                for (uint k = 0; k < tempt_slice.length; k++) {
                    tempt_slice[k] = tempt[(j * (par.n - par.o)) * par.m + k];
                }
                bytes memory oil_space_slice = new bytes(
                    par.oil_space_bytes - i * (par.n - par.o)
                );
                for (uint k = 0; k < oil_space_slice.length; k++) {
                    oil_space_slice[k] = oil_space[i * (par.n - par.o) + k];
                }
                bytes memory vec = utils.linear_combination(
                    tempt_slice,
                    oil_space_slice,
                    par.n - par.o,
                    par.prime,
                    par.m
                );
                for (uint k = 0; k < vec.length; k++) {
                    P2[counter * par.m + k] = vec[k];
                }
                if (j != i) {
                    bytes memory tempt_slice2 = new bytes(
                        tempt.length - (i * (par.n - par.o)) * par.m
                    );
                    for (uint k = 0; k < tempt_slice2.length; k++) {
                        tempt_slice2[k] = tempt[
                            (i * (par.n - par.o)) * par.m + k
                        ];
                    }
                    bytes memory oil_space_slice2 = new bytes(
                        par.oil_space_bytes - j * (par.n - par.o)
                    );
                    for (uint k = 0; k < oil_space_slice2.length; k++) {
                        oil_space_slice2[k] = oil_space[
                            j * (par.n - par.o) + k
                        ];
                    }
                    bytes memory vec2 = utils.linear_combination(
                        tempt_slice2,
                        oil_space_slice2,
                        par.n - par.o,
                        par.prime,
                        par.m
                    );
                    vec2 = utils.add_vectors(par, vec, vec2);
                    for (uint k = 0; k < par.m; k++) {
                        P2[counter * par.m + k] = vec2[k];
                    }
                }
                counter++;
            }
        }

        // P2 = -P2
        P2 = utils.negate(P2, par.prime);
        return P2;
    }

    function expand_pk(
        Params.MayoParams memory par,
        bytes memory pk
    ) public view returns (bytes memory) {
        return utils.reduce(utils.expand(pk, par.p1_bytes), par.prime);
    }

    function sample_vinegar(
        Params.MayoParams memory par,
        bytes memory inputs,
        bytes calldata random_seed
    ) public view returns (bytes memory) {
        bytes memory randomness = utils.expand(
            random_seed,
            uint32(par.n) * par.k
        );
        uint c = 0;
        for (uint i = 0; i < par.k; i++) {
            for (uint j = 0; j < par.n - par.o; j++) {
                while (
                    uint(uint8(randomness[c])) % (1 << par.prime_bits) >=
                    par.prime
                ) {
                    c++;
                }
                inputs[i * par.n + j] = randomness[c];
                c++;
            }
            require(
                c < par.n * par.k,
                "Counter exceeds the maximum allowed value"
            );
        }
        return inputs;
    }

    function multiply_extension_field(
        Params.MayoParams memory par,
        bytes memory A,
        bytes memory B,
        bytes memory output
    ) public pure returns (bytes memory) {
        int[] memory Temp = new int[](2 * par.m - 1);
        for (uint i = 0; i < par.m; i++) {
            for (uint j = 0; j < par.m; j++) {
                Temp[i + j] += int(uint(uint8(A[i]))) * int(uint(uint8(B[j])));
            }
        }
        return reduce_extension(par, Temp, output);
    }

    function sample_oil(
        Params.MayoParams memory par,
        bytes memory rhs,
        bytes memory linear,
        bytes memory solution,
        bytes calldata random_seed
    ) public view returns (bytes memory) {
        if (par.k * par.o > 8 * 8 - 1) {
            revert("Error: K*O > 8*8 - 1 not supported");
        }
        uint32[] memory aug_matrix = new uint32[](uint32(par.m) * 8 * 8);
        for (uint i = 0; i < par.m; i++) {
            for (uint j = 0; j < par.k * par.o; j++) {
                aug_matrix[i * 64 + j] = uint32(uint8(linear[j * par.m + i]));
            }
            aug_matrix[i * 64 + par.k * par.o] = uint32(uint8(rhs[i]));
        }
        aug_matrix = utils.gauss_reduction(par, aug_matrix);
        uint col = par.k * par.o;
        int row = int(par.m - 1);
        while (row >= 0) {
            uint col2 = 0;
            while (aug_matrix[uint(row) * 64 + col2] % par.prime == 0) {
                col2++;
                if (col2 == par.k * par.o + 1) {
                    break;
                }
            }
            if (col2 == par.k * par.o + 1) {
                row--;
                continue;
            }
            if (col2 == par.k * par.o) {
                revert("Error: col2 == K*O");
            }
            while (col > col2 + 1) {
                col--;
                solution[col] = utils.random_element(par, random_seed);

                for (uint i = 0; i < par.m; i++) {
                    aug_matrix[i * 64 + par.k * par.o] =
                        (uint16(aug_matrix[i * 64 + par.k * par.o]) +
                            uint16(par.prime - uint8(solution[col])) *
                            aug_matrix[i * 64 + col]) %
                        uint32(par.prime);
                }
            }
            col--;
            solution[col] = bytes1(
                uint8(aug_matrix[uint(row) * 64 + par.k * par.o])
            );
            for (uint i = 0; i < par.m; i++) {
                aug_matrix[i * 64 + par.k * par.o] =
                    (uint16(aug_matrix[i * 64 + par.k * par.o]) +
                        uint16(par.prime - uint8(solution[col])) *
                        uint16(aug_matrix[i * 64 + col])) %
                    uint32(par.prime);
            }
            row--;
        }
        return solution;
    }

    function compute_bilinear_part(
        Params.MayoParams memory par,
        bytes memory P1,
        bytes memory oil_space,
        bytes memory bilinear
    ) public view returns (bytes memory) {
        bytes memory bilinear_temp = new bytes(par.m * (par.n - par.o) * par.o);
        bytes memory P1P1T = new bytes(
            par.m * (par.n - par.o) * (par.n - par.o)
        );
        uint counter = 0;
        for (uint i = 0; i < par.n - par.o; ++i) {
            for (uint j = i; j < par.n - par.o; ++j) {
                for (uint k = 0; k < par.m; k++) {
                    P1P1T[par.m * (i * (par.n - par.o) + j) + k] = P1[
                        counter * par.m + k
                    ];
                }
                if (j == i) {
                    bytes memory P1P1T_slice = new bytes(
                        P1P1T.length - (par.m * (i * (par.n - par.o) + j))
                    );
                    for (uint k = 0; k < P1P1T_slice.length; k++) {
                        P1P1T_slice[k] = P1P1T[
                            par.m * (i * (par.n - par.o) + j) + k
                        ];
                    }
                    P1P1T_slice = utils.add_vectors(
                        par,
                        P1P1T_slice,
                        P1P1T_slice
                    );
                } else {
                    for (uint k = 0; k < par.m; k++) {
                        P1P1T[par.m * (j * (par.n - par.o) + i) + k] = P1[
                            counter * par.m + k
                        ];
                    }
                }
                counter++;
            }
        }
        for (uint i = 0; i < par.n - par.o; ++i) {
            for (uint j = 0; j < par.o; ++j) {
                bytes memory P1P1T_slice = new bytes(
                    P1P1T.length - (par.m * i * (par.n - par.o))
                );
                for (uint k = 0; k < P1P1T_slice.length; k++) {
                    P1P1T_slice[k] = P1P1T[i * par.m * (par.n - par.o) + k];
                }
                bytes memory oil_space_slice = new bytes(
                    par.oil_space_bytes - j * (par.n - par.o)
                );
                for (uint k = 0; k < oil_space_slice.length; k++) {
                    oil_space_slice[k] = oil_space[j * (par.n - par.o) + k];
                }
                bytes memory vec = utils.linear_combination(
                    P1P1T_slice,
                    oil_space_slice,
                    par.n - par.o,
                    par.prime,
                    par.m
                );
                for (uint k = 0; k < vec.length; k++) {
                    bilinear_temp[(i * par.o + j) * par.m + k] = vec[k];
                }
            }
        }
        for (uint i = 0; i < par.n - par.o; ++i) {
            // P1' part
            for (uint j = 0; j < par.o; j++) {
                bytes memory bilinear_temp_slice = new bytes(
                    bilinear_temp.length - (i * par.o + j) * par.m
                );
                for (uint k = 0; k < bilinear_temp_slice.length; k++) {
                    bilinear_temp_slice[k] = bilinear_temp[
                        (i * par.o + j) * par.m + k
                    ];
                }
                bytes memory P1_slice = new bytes(
                    P1.length - par.m * (counter + i * par.o + j)
                );
                for (uint k = 0; k < P1_slice.length; k++) {
                    P1_slice[k] = P1[par.m * (counter + i * par.o + j) + k];
                }
                bilinear_temp_slice = utils.add_vectors(
                    par,
                    bilinear_temp_slice,
                    P1_slice
                );
                for (uint k = 0; k < bilinear_temp_slice.length; k++) {
                    bilinear_temp[
                        (i * par.o + j) * par.m + k
                    ] = bilinear_temp_slice[k];
                }
            }
        }

        // transpose bilinear_temp
        for (uint i = 0; i < par.n - par.o; ++i) {
            for (uint j = 0; j < par.o; ++j) {
                for (uint k = 0; k < par.m; k++) {
                    bilinear[
                        (j * (par.n - par.o) + i) * par.m + k
                    ] = bilinear_temp[(i * par.o + j) * par.m + k];
                }
            }
        }
        return bilinear;
    }

    function add_oil(
        Params.MayoParams memory par,
        bytes memory inputs,
        bytes memory oil,
        bytes memory oil_space
    ) public pure returns (bytes memory) {
        for (uint k = 0; k < par.k; ++k) {
            // copy oil to signature
            for (uint i = 0; i < par.o; ++i) {
                inputs[k * par.n + par.n - par.o + i] = oil[k * par.o + i];
            }
            for (uint i = 0; i < par.n - par.o; ++i) {
                uint32 t = uint32(uint8(inputs[uint(k) * par.n + i]));
                for (uint j = 0; j < par.o; ++j) {
                    t +=
                        uint32(uint8(inputs[k * par.n + par.n - par.o + j])) *
                        uint32(uint8(oil_space[j * (par.n - par.o) + i]));
                }
                inputs[k * par.n + i] = bytes1(uint8(t % par.prime));
            }
        }
        return inputs;
    }

    function message_digest(
        Params.MayoParams memory par,
        bytes memory sig,
        bytes calldata m
    ) public view returns (bytes memory) {
        bytes memory buffer = new bytes(par.seed_bytes + par.hash_bytes);
        for (uint i = 0; i < par.seed_bytes; i++) {
            buffer[i] = sig[i];
        }
        bytes32 keccak = keccak256(m);
        for (uint i = 0; i < par.hash_bytes; i++) {
            buffer[par.seed_bytes + i] = keccak[i];
        }
        bytes memory digest = utils.expand(buffer, par.m);
        return utils.reduce(digest, par.prime);
    }

    function evaluateP(
        Params.MayoParams memory par,
        bytes memory input,
        bytes memory P1,
        bytes memory P2
    ) public view returns (bytes memory) {
        uint m = par.m;
        uint n = par.n;
        uint o = par.o;
        uint prime = par.prime;
        uint p1monomials = par.p1monomials;
        uint p2monomials = par.p2monomials;
        uint monomials = par.monomials;

        bytes memory products = new bytes(monomials);
        uint counter = 0;
        // vinegar x vinegar
        for (uint i = 0; i < n - o; ++i) {
            for (uint j = i; j < n - o; ++j) {
                products[counter++] = bytes1(
                    uint8(
                        (uint(uint8(input[i])) * uint(uint8(input[j]))) % prime
                    )
                );
            }
        }
        // vinegar x oil
        for (uint i = 0; i < n - o; ++i) {
            for (uint j = n - o; j < n; ++j) {
                products[counter++] = bytes1(
                    uint8(
                        (uint(uint8(input[i])) * uint(uint8(input[j]))) % prime
                    )
                );
            }
        }
        // oil x oil
        for (uint i = n - o; i < n; ++i) {
            for (uint j = i; j < n; ++j) {
                products[counter++] = bytes1(
                    uint8(
                        (uint(uint8(input[i])) * uint(uint8(input[j]))) % prime
                    )
                );
            }
        }
        bytes memory part1 = utils.linear_combination(
            P1,
            products,
            p1monomials,
            prime,
            m
        );
        bytes memory productsSlice = new bytes(products.length - p1monomials);
        for (uint i = 0; i < productsSlice.length; i++) {
            productsSlice[i] = products[p1monomials + i];
        }

        bytes memory part2 = utils.linear_combination(
            P2,
            productsSlice,
            p2monomials,
            prime,
            m
        );
        bytes memory output = utils.add_vectors(par, part1, part2);
        return output;
    }

    function evaluateP_vinegar(
        Params.MayoParams memory par,
        bytes memory input,
        bytes memory P1
    ) public view returns (bytes memory) {
        bytes memory products = new bytes(
            (par.n - par.o * (par.n - par.o + 1)) / 2
        );
        uint counter = 0;
        for (uint i = 0; i < par.n - par.o; ++i) {
            for (uint j = i; j < par.n - par.o; ++j) {
                products[counter] = bytes1(
                    uint8(
                        (uint32(uint8(input[i])) * uint32(uint8(input[j]))) %
                            par.prime
                    )
                );
                counter++;
            }
        }
        return
            utils.linear_combination(
                P1,
                products,
                (par.n - par.o * (par.n - par.o + 1)) / 2,
                par.prime,
                par.m
            );
    }

    function reduce_extension(
        Params.MayoParams memory par,
        int[] memory input,
        bytes memory output
    ) public pure returns (bytes memory) {
        if (par.m == 60 && par.prime == 31) {
            // reduce mod x^60 + x^2 + 3x+ 27
            for (uint i = 118; i > 59; --i) {
                input[i - 60] -= input[i] * 27;
                input[i - 59] -= input[i] * 3;
                input[i - 58] -= input[i];
            }
        } else if (par.m == 63 && par.prime == 31) {
            // reduce mod x^63 + x^2 + 2
            for (uint i = 124; i > 62; --i) {
                input[i - 63] -= input[i] * 2;
                input[i - 61] -= input[i];
            }
        } else {
            revert("Parameters not supported (M, prime)");
        }
        for (uint i = 0; i < par.m; ++i) {
            output[i] = bytes1(
                uint8(
                    uint(
                        ((input[i] % int(par.prime)) +
                            int(par.prime) +
                            int(uint(uint8(output[i])))) % int(par.prime)
                    )
                )
            );
        }
        return output;
    }

    function merge_outputs(
        Params.MayoParams memory par,
        bytes memory outputs,
        bytes memory merged
    ) public pure returns (bytes memory) {
        if (par.kc2 > par.m) {
            revert("KC2 > M not supported");
        }
        int[] memory Temp = new int[](2 * par.m - 1);
        for (uint k = 0; k < par.kc2; ++k) {
            for (uint i = 0; i < par.m; ++i) {
                Temp[i + k] += int(uint(uint8(outputs[k * par.m + i])));
            }
        }
        return reduce_extension(par, Temp, merged);
    }

    function expand_sk(
        Params.MayoParams memory par,
        bytes memory sk,
        bytes memory sk_exp
    ) public view returns (bytes memory) {
        bytes memory exp = expand_pk(par, sk);
        for (uint i = 0; i < exp.length; i++) {
            sk_exp[i] = exp[i];
        }
        bytes memory private_seed = new bytes(par.seed_bytes);
        for (uint i = 0; i < par.seed_bytes; i++) {
            private_seed[i] = sk[i + par.seed_bytes];
        }
        bytes memory sk_exp_oil = new bytes(sk_exp.length - par.p1_bytes);
        for (uint i = 0; i < sk_exp_oil.length; i++) {
            sk_exp_oil[i] = sk_exp[par.p1_bytes + i];
        }
        sk_exp_oil = sample_oil_space(par, private_seed, sk_exp_oil);

        for (uint i = 0; i < sk_exp_oil.length; i++) {
            sk_exp[par.p1_bytes + i] = sk_exp_oil[i];
        }
        bytes memory sk_exp_bilinear = new bytes(
            sk_exp.length - (par.p1_bytes + par.oil_space_bytes)
        );
        for (uint i = 0; i < sk_exp_bilinear.length; i++) {
            sk_exp_bilinear[i] = sk_exp[par.p1_bytes + par.oil_space_bytes + i];
        }
        sk_exp_bilinear = compute_bilinear_part(
            par,
            sk_exp,
            sk_exp_oil,
            sk_exp_bilinear
        );
        for (uint i = 0; i < sk_exp_bilinear.length; i++) {
            sk_exp[par.p1_bytes + par.oil_space_bytes + i] = sk_exp_bilinear[i];
        }
        return sk_exp;
    }

    function sign(
        Params.MayoParams memory par,
        bytes calldata m,
        bytes memory sk,
        bytes calldata random_seed
    ) public view returns (bytes memory) {
        bytes memory sig = new bytes(par.seed_bytes + par.n * par.k);
        bytes memory sk_exp = new bytes(par.sk_exp_bytes);
        sk_exp = expand_sk(par, sk, sk_exp);

        return sign_fast(par, m, sk_exp, sig, random_seed);
    }

    function sign_fast(
        Params.MayoParams memory par,
        bytes calldata m,
        bytes memory sk_exp,
        bytes memory sig,
        bytes calldata random_seed
    ) public view returns (bytes memory) {
        bytes memory sig_salt = new bytes(par.seed_bytes);
        sig_salt = utils.expand(random_seed, par.seed_bytes);
        for (uint i = 0; i < par.seed_bytes; i++) {
            sig[i] = sig_salt[i];
        }
        bytes memory digest = message_digest(par, sig, m);

        bytes memory P1 = new bytes(par.p1_bytes);
        for (uint i = 0; i < par.p1_bytes; i++) {
            P1[i] = sk_exp[i];
        }

        bytes memory oil_space = new bytes(par.oil_space_bytes);
        for (uint i = 0; i < par.oil_space_bytes; i++) {
            oil_space[i] = sk_exp[par.p1_bytes + i];
        }

        bytes memory bilinear = new bytes(
            sk_exp.length - (par.p1_bytes + par.oil_space_bytes)
        );
        for (uint i = 0; i < bilinear.length; i++) {
            bilinear[i] = sk_exp[par.p1_bytes + par.oil_space_bytes + i];
        }

        bytes memory inputs = new bytes(par.n * par.k);
        for (uint i = 0; i < par.n * par.k; i++) {
            inputs[i] = sig[par.seed_bytes + i];
        }
        bytes memory oil_solution = new bytes(par.k * par.o);

        while (true) {
            inputs = sample_vinegar(par, inputs, random_seed);

            bytes memory vinegar_evals_temp = new bytes(par.m);
            bytes memory vinegar_evals = new bytes(par.kc2 * uint(par.m));
            bytes memory linear = new bytes(uint(par.m) * par.k * par.o);
            uint ctr = 0;

            for (uint i = 0; i < par.k; i++) {
                for (uint j = i; j < par.k; j++) {
                    bytes memory vinegar = new bytes(par.n);
                    for (uint k = 0; k < par.n; k++) {
                        vinegar[k] = bytes1(
                            uint8(
                                (uint(uint8(inputs[i * par.n + k])) +
                                    uint(uint8(inputs[j * par.n + k]))) %
                                    par.prime
                            )
                        );
                    }

                    vinegar_evals_temp = evaluateP_vinegar(par, vinegar, P1);
                    for (uint k = 0; k < par.m; k++) {
                        vinegar_evals[ctr * par.m + k] = vinegar_evals_temp[k];
                    }
                    bytes memory multiplier = new bytes(par.m);
                    multiplier[ctr] = abi.encodePacked(uint8(1))[0];

                    for (uint c = 0; c < par.o; c++) {
                        bytes memory vec = new bytes(par.m);
                        bytes memory bilinear_slice = new bytes(
                            bilinear.length - c * (par.n - par.o) * par.m
                        );
                        for (uint k = 0; k < bilinear_slice.length; k++) {
                            bilinear_slice[k] = bilinear[
                                c * (par.n - par.o) * par.m + k
                            ];
                        }
                        vec = utils.linear_combination(
                            bilinear_slice,
                            vinegar,
                            par.n - par.o,
                            par.prime,
                            par.m
                        );
                        bytes memory multiplied = new bytes(par.m);
                        multiplied = multiply_extension_field(
                            par,
                            multiplier,
                            vec,
                            multiplied
                        );

                        bytes memory linear_slice = new bytes(
                            linear.length - (i * par.o + c) * par.m
                        );
                        for (uint k = 0; k < linear_slice.length; k++) {
                            linear_slice[k] = linear[
                                (i * par.o + c) * par.m + k
                            ];
                        }
                        linear_slice = utils.add_vectors(
                            par,
                            multiplied,
                            linear_slice
                        );
                        for (uint k = 0; k < linear_slice.length; k++) {
                            linear[(i * par.o + c) * par.m + k] = linear_slice[
                                k
                            ];
                        }
                        bytes memory linear_slice2 = new bytes(
                            linear.length - (j * par.o + c) * par.m
                        );
                        for (uint k = 0; k < linear_slice2.length; k++) {
                            linear_slice2[k] = linear[
                                (j * par.o + c) * par.m + k
                            ];
                        }
                        linear_slice2 = utils.add_vectors(
                            par,
                            multiplied,
                            linear_slice2
                        );
                        for (uint k = 0; k < linear_slice2.length; k++) {
                            linear[(j * par.o + c) * par.m + k] = linear_slice2[
                                k
                            ];
                        }
                    }
                    ctr++;
                }
            }
            bytes memory RHS = new bytes(par.m);
            RHS = merge_outputs(par, vinegar_evals, RHS);
            RHS = utils.negate(RHS, par.prime);
            RHS = utils.add_vectors(par, RHS, digest);

            try
                this.sample_oil(par, RHS, linear, oil_solution, random_seed)
            returns (bytes memory solution) {
                oil_solution = solution;
                break;
            } catch Error(string memory) {
                continue;
            }
        }
        inputs = add_oil(par, inputs, oil_solution, oil_space);

        for (uint i = 0; i < par.k * par.n; i++) {
            sig[par.seed_bytes + i] = inputs[i];
        }

        return sig;
    }

    function verify(
        Params.MayoParams memory par,
        bytes calldata m,
        bytes calldata pk,
        bytes calldata sig
    ) public view returns (bool) {
        bytes memory pk_exp = expand_pk(par, pk);
        return verify_fast(par, m, pk, pk_exp, sig);
    }

    function verify_fast(
        Params.MayoParams memory par,
        bytes calldata m,
        bytes calldata pk,
        bytes memory pk_exp,
        bytes calldata sig
    ) public view returns (bool) {
        bytes memory digest = message_digest(par, sig, m);

        // evaluate P
        bytes memory outputs = new bytes(uint16(par.m) * par.kc2);
        bytes memory input = new bytes(par.n);
        uint ctr = 0;
        bytes memory pk_p2 = new bytes(pk.length - par.seed_bytes);

        for (uint i = 0; i < pk_p2.length; i++) {
            pk_p2[i] = pk[par.seed_bytes + i];
        }
        bytes memory evaluated = new bytes(par.m);

        for (uint i = 0; i < par.k; i++) {
            for (uint j = i; j < par.k; j++) {
                for (uint k = 0; k < par.n; k++) {
                    input[k] = bytes1(
                        (uint8(sig[par.seed_bytes + i * par.n + k]) +
                            uint8(sig[par.seed_bytes + j * par.n + k])) %
                            uint8(par.prime)
                    );
                }
                evaluated = evaluateP(par, input, pk_exp, pk_p2);
                for (uint k = 0; k < par.m; k++) {
                    outputs[ctr * par.m + k] = evaluated[k];
                }
                ctr++;
            }
        }
        bytes memory output = new bytes(par.m);
        output = merge_outputs(par, outputs, output);

        if (utils.memcmp(digest, output, par.m) != 0) {
            return false;
        }

        return true;
    }
}
