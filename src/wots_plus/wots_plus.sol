// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";

contract WOTSPlus {
    bytes32[] pk;
    bytes32[] r;
    uint256 k;

    constructor() {}

    function set_pk(bytes32[] calldata _r, uint256 _k, bytes32[] calldata _pk) public {
        pk = _pk;
        r = _r;
        k = _k;
    }

    function verify(uint256 w, bytes32[] calldata M, bytes32[] calldata sigma) public view returns (bool) {
        uint256 l1 = M.length;
        uint256 l2 = logN(l1*(w-1), w); //log2(l1*(w-1))/log2(w);

        // Compute checksum C
        uint256 checksum = 0;
        for (uint256 i = 0; i < l1; i++) {
            checksum += (w - 1 - uint256(M[i]));
        }

        
        // Compute base w representation of checksum
        bytes32[] memory C = new bytes32[](l2);
        for (uint256 i = 0; i < l2; i++) {
            C[i] = bytes32(checksum % w);
            checksum /= w;
        }

        // Concatenate M and C to form B
        uint256 l = l1 + l2;
        bytes32[] memory B = new bytes32[](l);
        for (uint256 i = 0; i < l1; i++) {
            B[i] = M[i];
        }


        for (uint256 i = 0; i < l2; i++) {
            B[l1 + i] = C[i];
        }

        // Verify signature
        for (uint256 i = 0; i < pk.length; i++) {
            uint256 bi = uint256(B[i]);
            if (pk[i] != c(sigma[i], w - 1 - bi,bi)) {
                return false;
            }
        }
        return true;
    }

    function c(bytes32 x, uint256 i, uint256 start_ind) public view returns (bytes32) {
        bytes32 result = x;
        for (uint256 j = 0; j < i; j++) {
            result = keccak256(abi.encodePacked(result ^ r[start_ind+j], k));
        }
        return result;
    }


    
    function logN(uint x, uint N) public pure returns (uint result) {
        while (x > 1) {
            x /= N;
            result++;
        }
    }

        //CODE FROM: https://ethereum.stackexchange.com/questions/8086/logarithm-math-operation-in-solidity
    function log2(uint x) public pure returns (uint y){
        assembly {
                let arg := x
                x := sub(x,1)
                x := or(x, div(x, 0x02))
                x := or(x, div(x, 0x04))
                x := or(x, div(x, 0x10))
                x := or(x, div(x, 0x100))
                x := or(x, div(x, 0x10000))
                x := or(x, div(x, 0x100000000))
                x := or(x, div(x, 0x10000000000000000))
                x := or(x, div(x, 0x100000000000000000000000000000000))
                x := add(x, 1)
                let m := mload(0x40)
                mstore(m,           0xf8f9cbfae6cc78fbefe7cdc3a1793dfcf4f0e8bbd8cec470b6a28a7a5a3e1efd)
                mstore(add(m,0x20), 0xf5ecf1b3e9debc68e1d9cfabc5997135bfb7a7a3938b7b606b5b4b3f2f1f0ffe)
                mstore(add(m,0x40), 0xf6e4ed9ff2d6b458eadcdf97bd91692de2d4da8fd2d0ac50c6ae9a8272523616)
                mstore(add(m,0x60), 0xc8c0b887b0a8a4489c948c7f847c6125746c645c544c444038302820181008ff)
                mstore(add(m,0x80), 0xf7cae577eec2a03cf3bad76fb589591debb2dd67e0aa9834bea6925f6a4a2e0e)
                mstore(add(m,0xa0), 0xe39ed557db96902cd38ed14fad815115c786af479b7e83247363534337271707)
                mstore(add(m,0xc0), 0xc976c13bb96e881cb166a933a55e490d9d56952b8d4e801485467d2362422606)
                mstore(add(m,0xe0), 0x753a6d1b65325d0c552a4d1345224105391a310b29122104190a110309020100)
                mstore(0x40, add(m, 0x100))
                let magic := 0x818283848586878898a8b8c8d8e8f929395969799a9b9d9e9faaeb6bedeeff
                let shift := 0x100000000000000000000000000000000000000000000000000000000000000
                let a := div(mul(x, magic), shift)
                y := div(mload(add(m,sub(255,a))), shift)
                y := add(y, mul(256, gt(arg, 0x8000000000000000000000000000000000000000000000000000000000000000)))
            }  
    }

}