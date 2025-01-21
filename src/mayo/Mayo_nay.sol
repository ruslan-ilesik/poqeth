// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Utils.sol";
import "./Params.sol";
import "./Mayo.sol";

contract Mayo_nay {
    Utils utils;
    Params.MayoParams params;
    Mayo mayo;
    bytes32 public commitment;

    constructor(Params.MayoParams memory _params) {
        params = _params;
        utils = new Utils(params);
        mayo = new Mayo(params);
    }

    function commit(
        bytes calldata message,
        bytes calldata pk,
        bytes calldata sig
    ) public {
        commitment = keccak256(abi.encodePacked(message, pk, sig));
    }

    function verifyNay(
        Params.MayoParams memory par,
        bytes calldata message,
        bytes calldata pk,
        bytes calldata sig,
        uint rowIndex
    ) public view returns (bool) {
        if (commitment != keccak256(abi.encodePacked(message, pk, sig))) {
            return false;
        }
        bytes memory digest = mayo.message_digest(par, sig, message);
        bytes1 targetByte = digest[rowIndex];
        bytes1 result = verify_row(par, pk, sig, rowIndex);

        return result == targetByte;
    }

    function verify_row(
        Params.MayoParams memory par,
        bytes memory pk,
        bytes memory sig,
        uint rowIndex
    ) public view returns (bytes1) {
        bytes memory pk_exp = mayo.expand_pk(par, pk);

        bytes memory outputs = new bytes(uint(par.m) * par.kc2);
        bytes memory input = new bytes(par.n);
        uint ctr = 0;
        bytes memory pk_p2 = new bytes(pk.length - par.seed_bytes);

        for (uint i = 0; i < pk_p2.length; i++) {
            pk_p2[i] = pk[par.seed_bytes + i];
        }
        bytes memory evaluated = new bytes(par.m);

        bytes memory extractedVecs = new bytes(par.p1monomials);
        for (uint i = 0; i < par.p1monomials; ++i) {
            extractedVecs[i] = pk_exp[i * par.m + rowIndex];
        }

        for (uint i = 0; i < par.k; i++) {
            for (uint j = i; j < par.k; j++) {
                for (uint k = 0; k < par.n; k++) {
                    input[k] = bytes1(
                        (uint8(sig[par.seed_bytes + i * par.n + k]) +
                            uint8(sig[par.seed_bytes + j * par.n + k])) %
                            uint8(par.prime)
                    );
                }
                evaluated = evaluateP_row(
                    par,
                    input,
                    extractedVecs,
                    pk_p2,
                    rowIndex
                );
                for (uint k = 0; k < par.m; k++) {
                    outputs[ctr * par.m + k] = evaluated[k];
                }
                ctr++;
            }
        }

        bytes memory output = new bytes(par.m);
        output = merge_outputs_row(par, outputs, output, rowIndex);

        return output[rowIndex];
    }

    function evaluateP_row(
        Params.MayoParams memory par,
        bytes memory input,
        bytes memory extractedVecs,
        bytes memory P2,
        uint rowIndex
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
        bytes memory part1 = utils.linear_combination_row(
            extractedVecs,
            products,
            p1monomials,
            prime,
            m,
            rowIndex
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

    function add_vectors_row(
        Params.MayoParams memory par,
        bytes memory v1,
        bytes memory v2,
        uint rowIndex
    ) public pure returns (bytes memory) {
        uint prime = par.prime;
        uint m = par.m;
        bytes memory out = new bytes(m);
        out[rowIndex] = bytes1(
            uint8(
                (uint(uint8(v1[rowIndex])) + uint(uint8(v2[rowIndex]))) % prime
            )
        );
        return out;
    }

    function merge_outputs_row(
        Params.MayoParams memory par,
        bytes memory outputs,
        bytes memory merged,
        uint rowIndex
    ) public pure returns (bytes memory) {
        if (par.kc2 > par.m) {
            revert("KC2 > M not supported");
        }
        int[] memory Temp = new int[](2 * par.m - 1);
        for (uint k = 0; k < par.kc2; ++k) {
            Temp[rowIndex + k] += int(
                uint(uint8(outputs[k * par.m + rowIndex]))
            );
        }
        return reduce_extension_row(par, Temp, merged, rowIndex);
    }

    function reduce_extension_row(
        Params.MayoParams memory par,
        int[] memory input,
        bytes memory output,
        uint rowIndex
    ) public pure returns (bytes memory) {
        if (par.m == 60 && par.prime == 31) {
            for (uint i = 118; i > 59; --i) {
                input[i - 60] -= input[i] * 27;
                input[i - 59] -= input[i] * 3;
                input[i - 58] -= input[i];
            }
        } else if (par.m == 63 && par.prime == 31) {
            for (uint i = 124; i > 62; --i) {
                input[i - 63] -= input[i] * 2;
                input[i - 61] -= input[i];
            }
        } else {
            revert("Parameters not supported (M, prime)");
        }
        output[rowIndex] = bytes1(
            uint8(
                uint(
                    ((input[rowIndex] % int(par.prime)) +
                        int(par.prime) +
                        int(uint(uint8(output[rowIndex])))) % int(par.prime)
                )
            )
        );
        return output;
    }
}
