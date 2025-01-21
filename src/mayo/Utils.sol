// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Params.sol";

contract Utils {
    Params.MayoParams public params;

    constructor(Params.MayoParams memory _params) {
        params = _params;
    }

    function expand(
        bytes memory data,
        uint outlen
    ) public pure returns (bytes memory) {
        require(outlen > 0, "Length must be greater than 0");
        uint wholeHashes = outlen / 32;
        bytes memory expanded = new bytes(outlen);
        bytes32 keccak = keccak256(abi.encodePacked(data));
        for (uint i = 0; i < wholeHashes; i++) {
            keccak = keccak256(abi.encodePacked(keccak));
            assembly ("memory-safe") {
                mstore(add(expanded, add(32, mul(i, 32))), keccak)
            }
        }
        uint remainder = outlen % 32;
        if (remainder > 0) {
            keccak = keccak256(abi.encodePacked(keccak));
            for (uint i = 0; i < remainder; i++) {
                expanded[wholeHashes * 32 + i] = keccak[i];
            }
        }
        return expanded;
    }

    function reduce(
        bytes calldata input,
        uint prime
    ) public pure returns (bytes memory) {
        bytes memory out = new bytes(input.length);
        assembly ("memory-safe") {
            let inputLength := calldatasize()
            let outPtr := add(out, 0x20)

            for {
                let i := 0
            } lt(i, inputLength) {
                i := add(i, 1)
            } {
                let byteVal := byte(0, calldataload(add(input.offset, i)))
                let reducedVal := mod(byteVal, prime)
                mstore8(add(outPtr, i), reducedVal)
            }
        }
        return out;
    }

    function linear_combination(
        bytes calldata vecs,
        bytes calldata coeffs,
        uint len,
        uint prime,
        uint m
    ) public pure returns (bytes memory) {
        bytes memory out = new bytes(m);

        assembly ("memory-safe") {
            let accumulators := mload(0x40)
            mstore(0x40, add(accumulators, mul(m, 0x20)))

            for {
                let j := 0
            } lt(j, m) {
                j := add(j, 1)
            } {
                mstore(add(accumulators, mul(j, 0x20)), 0)
            }

            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 1)
            } {
                for {
                    let j := 0
                } lt(j, m) {
                    j := add(j, 1)
                } {
                    let vecIndex := add(add(vecs.offset, mul(i, m)), j)
                    let coeffIndex := add(coeffs.offset, i)
                    let vecVal := byte(0, calldataload(vecIndex))
                    let coeffVal := byte(0, calldataload(coeffIndex))
                    let accumIndex := add(accumulators, mul(j, 0x20))
                    let accumVal := mload(accumIndex)
                    let newAccumVal := add(accumVal, mul(vecVal, coeffVal))
                    mstore(accumIndex, newAccumVal)
                }
            }

            let outPtr := add(out, 0x20)
            for {
                let j := 0
            } lt(j, m) {
                j := add(j, 1)
            } {
                let accumVal := mload(add(accumulators, mul(j, 0x20)))
                let modVal := mod(accumVal, prime)
                mstore8(add(outPtr, j), modVal)
            }
        }
        return out;
    }

    function linear_combination_row(
        bytes calldata vecs,
        bytes calldata coeffs,
        uint len,
        uint prime,
        uint m,
        uint index
    ) public pure returns (bytes memory) {
        require(index < m, "Index out of bounds");

        uint accumulator = 0;

        assembly {
            let vecsOffset := add(vecs.offset, index)
            let coeffsOffset := coeffs.offset

            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 1)
            } {
                let vecVal := byte(0, calldataload(add(vecsOffset, mul(i, m))))
                let coeffVal := byte(0, calldataload(add(coeffsOffset, i)))
                accumulator := add(accumulator, mul(vecVal, coeffVal))
            }
        }

        bytes memory out = new bytes(1);
        out[0] = bytes1(uint8(accumulator % prime));
        return out;
    }

    function add_vectors(
        Params.MayoParams memory par,
        bytes calldata v1,
        bytes calldata v2
    ) public pure returns (bytes memory) {
        uint prime = par.prime;
        uint m = par.m;
        bytes memory out = new bytes(m);

        assembly ("memory-safe") {
            let outPtr := add(out, 0x20) // Pointer to the output bytes (skipping the length)
            let v1Offset := v1.offset
            let v2Offset := v2.offset

            // Loop through each byte in v1 and v2
            for {
                let i := 0
            } lt(i, m) {
                i := add(i, 1)
            } {
                // Load the current byte from v1 and v2
                let v1Byte := byte(0, calldataload(add(v1Offset, i)))
                let v2Byte := byte(0, calldataload(add(v2Offset, i)))

                // Add the bytes and perform the modulo operation
                let sum := addmod(v1Byte, v2Byte, prime)

                // Store the result in the output bytes
                mstore8(add(outPtr, i), sum)
            }
        }

        return out;
    }

    function memcmp(
        bytes memory s1,
        bytes memory s2,
        uint n
    ) public pure returns (int) {
        require(
            s1.length >= n && s2.length >= n,
            "Byte arrays are too short for comparison"
        );

        for (uint i = 0; i < n; i++) {
            if (s1[i] < s2[i]) {
                return -1;
            } else if (s1[i] > s2[i]) {
                return 1;
            }
        }
        return 0;
    }

    function negate(
        bytes calldata v,
        uint prime
    ) public pure returns (bytes memory) {
        bytes memory out = new bytes(v.length);
        for (uint i = 0; i < v.length; i++) {
            out[i] = bytes1(
                uint8(
                    uint(
                        (((-int(uint(uint8(v[i])))) % int(prime)) +
                            int(prime)) % int(prime)
                    )
                )
            );
        }
        return out;
    }

    function swap_row(
        uint32[] memory matrix,
        uint a,
        uint b
    ) public pure returns (uint32[] memory) {
        uint32 tmp = 0;
        for (uint i = 0; i < 64; i++) {
            tmp = matrix[64 * a + i];
            matrix[64 * a + i] = matrix[64 * b + i];
            matrix[64 * b + i] = tmp;
        }
        return matrix;
    }

    function random_element(
        Params.MayoParams memory par,
        bytes calldata random_seed
    ) public pure returns (bytes1) {
        bytes1 r = bytes1(uint8(par.prime));
        while (uint8(r) >= par.prime) {
            r = expand(random_seed, 1)[0];
        }
        return r;
    }

    function mod_inverse(
        Params.MayoParams memory par,
        uint a
    ) public pure returns (uint) {
        uint c = 1;
        for (uint i = 0; i < par.prime - 2; ++i) {
            c = (c * a) % par.prime;
        }
        return c;
    }

    function scale(
        Params.MayoParams memory par,
        uint32[] memory matrix,
        uint row,
        uint a
    ) public pure returns (uint32[] memory) {
        for (uint i = 0; i < (par.k * par.o) + 1; ++i) {
            matrix[row * 64 + i] = (((matrix[row * 64 + i] %
                uint32(par.prime)) * uint32(a)) % uint32(par.prime));
        }
        return matrix;
    }

    function row_op(
        Params.MayoParams memory par,
        uint32[] memory matrix,
        uint s,
        uint d,
        uint32 coef
    ) public pure returns (uint32[] memory) {
        for (uint i = s; i < (par.k * par.o) + 1; ++i) {
            matrix[d * 64 + i] += matrix[s * 64 + i] * coef;
        }
        return matrix;
    }

    function gauss_reduction(
        Params.MayoParams memory par,
        uint32[] memory matrix
    ) public pure returns (uint32[] memory) {
        uint row = 0;
        uint col = 0;

        while (true) {
            uint find_row = row;
            while (matrix[find_row * 64 + col] % par.prime == 0) {
                matrix[find_row * 64 + col] = 0;
                find_row++;
                if (find_row == par.m) {
                    col++;
                    find_row = row;
                    if (col == par.k * par.o) {
                        return matrix;
                    }
                }
            }

            if (find_row != row) {
                matrix = swap_row(matrix, row, find_row);
            }

            uint inv = mod_inverse(
                par,
                matrix[row * 64 + col] % uint32(par.prime)
            );
            matrix = scale(par, matrix, row, inv);

            for (uint i = find_row + 1; i < par.m; ++i) {
                uint32 coef = (uint32(par.prime) -
                    (matrix[i * 64 + col] % uint32(par.prime))) %
                    uint32(par.prime);
                matrix = row_op(par, matrix, row, i, coef);
            }

            row++;
            col++;
            if (row == par.m) {
                return matrix;
            }
        }
        return matrix;
    }
}
