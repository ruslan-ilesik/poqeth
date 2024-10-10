// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";
import "../merkle_tree.sol";

contract WOTSPlusNaysaer is MerkleTree {


    uint256 k;
    uint16 w;

    bytes32 sign;
    //bytes1[] M;

    function set_pk( uint256 _k) public {
        k = _k;
    }

    function set_param(uint16 _w) public{
        w = _w;
    }

    function set_sign(bytes32 _sign) public{
        sign = _sign;
        //M = _M;
    }


    //returns true if naysayer proof accepted, false otherwise (incorrect data or no actuall mistake)
    function naysaer(bytes32 sign_leaf, bytes32[] memory proof, uint256 index, bytes1[] memory M, bytes32[] memory M_proof, bytes32 pki, bytes32[] memory pki_proof, bytes32[] calldata r, bytes32[] memory r_proof) public returns (bool){
        if (!verify_proof(sign,sign_leaf,proof,index)){
            return false;
        }
        uint256 l1 = M.length;
        uint256 l2 = log2(l1*(w-1))/log2(w);
        uint l = l1+l2;
        if (!verify_proof(sign,keccak256(abi.encodePacked(M)),M_proof,l)){
            return false;
        }
        if (!verify_proof(sign,pki,pki_proof,l+1+index)){
            return false;
        }
        if (!verify_proof(sign,keccak256(abi.encodePacked(r)),r_proof,l*2+1)){
            return false;
        }

        // Directly compute the relevant checksum portion
        uint256 checksum = 0;
        for (uint256 i = 0; i < l1; i++) {
            checksum += (w - 1 - uint8(M[i]));
        }

        uint8 bi;
        if (index < l1) {
            // If the index is in M
            bi = uint8(M[index]);
        } else {
            // If the index is in C
            index -= l1;
            for (uint256 i = 0; i <= index; i++) {
                bi = uint8(checksum % w);
                checksum /= w;
            }
        }
        

        if (pki != c(sign_leaf, w - 1 - bi,bi,r)) {
            return true;
        }
        return false;
    }

    function naysaer(bytes32 sign_leaf, bytes32[] memory proof, uint256 index, bytes2[] memory M, bytes32[] memory M_proof, bytes32 pki, bytes32[] memory pki_proof, bytes32[] calldata r, bytes32[] memory r_proof) public returns (bool){
        if (!verify_proof(sign,sign_leaf,proof,index)){
            return false;
        }

        uint256 l1 = M.length;
        uint256 l2 = log2(l1*(w-1))/log2(w);
        uint l = l1+l2;

        if (!verify_proof(sign,keccak256(abi.encodePacked(M)),M_proof,l)){
            return false;
        }
        if (!verify_proof(sign,pki,pki_proof,l+1+index)){
            return false;
        }
        if (!verify_proof(sign,keccak256(abi.encodePacked(r)),r_proof,l*2+1)){
            return false;
        }
        // Directly compute the relevant checksum portion
        uint256 checksum = 0;
        for (uint256 i = 0; i < l1; i++) {
            checksum += (w - 1 - uint16(M[i]));
        }

        uint16 bi;
        if (index < l1) {
            // If the index is in M
            bi = uint16(M[index]);
        } else {
            // If the index is in C
            index -= l1;
            for (uint256 i = 0; i <= index; i++) {
                bi = uint16(checksum % w);
                checksum /= w;
            }
        }
        

        if (pki != c(sign_leaf, w - 1 - bi,bi,r)) {
            return true;
        }
        return false;
}


  //returns true if naysayer proof accepted, false otherwise (incorrect data or no actuall mistake)
    function naysaer(bytes32 sign_leaf, bytes32[] memory proof, uint256 index, bytes32[] memory M, bytes32[] memory M_proof, bytes32 pki, bytes32[] memory pki_proof, bytes32[] calldata r, bytes32[] memory r_proof) public returns (bool){
        if (!verify_proof(sign,sign_leaf,proof,index)){
            return false;
        }
        uint256 l1 = M.length;
        uint256 l2 = log2(l1*(w-1))/log2(w);
        uint l = l1+l2;
        if (!verify_proof(sign,keccak256(abi.encodePacked(M)),M_proof,l)){
            return false;
        }
        if (!verify_proof(sign,pki,pki_proof,l+1+index)){
            return false;
        }
        if (!verify_proof(sign,keccak256(abi.encodePacked(r)),r_proof,l*2+1)){
            return false;
        }

        // Directly compute the relevant checksum portion
        uint256 checksum = 0;
        for (uint256 i = 0; i < l1; i++) {
            checksum += (w - 1 - uint256(M[i]));
        }

        uint256 bi;
        if (index < l1) {
            // If the index is in M
            bi = uint256(M[index]);
        } else {
            // If the index is in C
            index -= l1;
            for (uint256 i = 0; i <= index; i++) {
                bi = uint256(checksum % w);
                checksum /= w;
            }
        }
        

        if (pki != c(sign_leaf, w - 1 - bi,bi,r)) {
            return true;
        }
        return false;
    }



    function c(bytes32 x, uint256 i, uint256 start_ind, bytes32[] calldata r) public view returns (bytes32) {
        bytes32 result = x;
        for (uint256 j = 0; j < i; j++) {
            result = keccak256(abi.encodePacked(result ^ r[start_ind+j], k));
        }
        return result;
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
                let m2 := mload(0x40)
                mstore(m2,           0xf8f9cbfae6cc78fbefe7cdc3a1793dfcf4f0e8bbd8cec470b6a28a7a5a3e1efd)
                mstore(add(m2,0x20), 0xf5ecf1b3e9debc68e1d9cfabc5997135bfb7a7a3938b7b606b5b4b3f2f1f0ffe)
                mstore(add(m2,0x40), 0xf6e4ed9ff2d6b458eadcdf97bd91692de2d4da8fd2d0ac50c6ae9a8272523616)
                mstore(add(m2,0x60), 0xc8c0b887b0a8a4489c948c7f847c6125746c645c544c444038302820181008ff)
                mstore(add(m2,0x80), 0xf7cae577eec2a03cf3bad76fb589591debb2dd67e0aa9834bea6925f6a4a2e0e)
                mstore(add(m2,0xa0), 0xe39ed557db96902cd38ed14fad815115c786af479b7e83247363534337271707)
                mstore(add(m2,0xc0), 0xc976c13bb96e881cb166a933a55e490d9d56952b8d4e801485467d2362422606)
                mstore(add(m2,0xe0), 0x753a6d1b65325d0c552a4d1345224105391a310b29122104190a110309020100)
                mstore(0x40, add(m2, 0x100))
                let magic := 0x818283848586878898a8b8c8d8e8f929395969799a9b9d9e9faaeb6bedeeff
                let shift := 0x100000000000000000000000000000000000000000000000000000000000000
                let a := div(mul(x, magic), shift)
                y := div(mload(add(m2,sub(255,a))), shift)
                y := add(y, mul(256, gt(arg, 0x8000000000000000000000000000000000000000000000000000000000000000)))
            }  
    }

}