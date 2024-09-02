// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";
import "../merkle_tree.sol";

contract WOTSPlusNaysaer is MerkleTree {
    bytes32[] pk;
    bytes32[] r;
    uint256 k;

    uint16 w = 4;

    bytes32 sign;
    bytes32[] M;

    function set_pk(bytes32[] calldata _r, uint256 _k, bytes32[] calldata _pk) public {
        pk = _pk;
        r = _r;
        k = _k;
    }

    function set_sign(bytes32 _sign, bytes32[] memory _M) public{
        sign = _sign;
        M = _M;
    }


    //returns true if naysayer proof accepted, false otherwise (incorrect data or no actuall mistake)
    function naysaer(bytes32 sign_leaf, bytes32[] memory proof, uint256 index) public returns (bool){
        if (!verify_proof(sign,sign_leaf,proof,index)){
            return false;
        }
        uint256 l1 = M.length;
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
                bi = checksum % w;
                checksum /= w;
            }
        }
        

        if (pk[index] != c(sign_leaf, w - 1 - bi,bi)) {
            return true;
        }
        return false;
    }

    function c(bytes32 x, uint256 i, uint256 start_ind) public view returns (bytes32) {
        bytes32 result = x;
        for (uint256 j = 0; j < i; j++) {
            result = keccak256(abi.encodePacked(result ^ r[start_ind+j], k));
        }
        return result;
    }

}