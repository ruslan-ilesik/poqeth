// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {MerkleTree} from "../merkle_tree.sol";

contract FORS {
    bytes32 pk;
    constructor(){}

    function set_pk(bytes32 _pk) public{
        pk = _pk;
    }



    function verify(string calldata message, bytes32[][] calldata signature, bytes32[] calldata leafs) public returns (bool){
        bytes32 hashed_message = keccak256(abi.encodePacked(message)); 
        bytes32[] memory roots = new bytes32[](signature.length);
        MerkleTree mtree = new MerkleTree();
        for (uint i =0; i < signature.length; i++){
            uint index = uint(uint8(hashed_message[i]));
            roots[i] = mtree.root_from_proof(leafs[i], signature[i],index);
        }
        return pk == keccak256(abi.encodePacked(roots));

    }
}