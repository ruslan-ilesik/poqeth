// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


import {Test, console} from "forge-std/Test.sol";
import {MerkleTree} from "../../src/merkle_tree.sol";
import {FORS} from "../../src/fors/fors.sol";
//import "forge-std/console.sol";

contract FORSTest is Test{
    constructor(){}

    function setUp() public{

    }

    function testFORS() public{
        string memory message = "Hello";
        bytes32 hashed_message = keccak256(abi.encodePacked(message));
        int m = 256; //do not change, constant message size in bits
        uint k = 32;
        uint a = 8;
        // NOTE: k*a = m
        uint t = 2 ** a;
        FORS fors = new FORS();

        // PK and SK generation
        MerkleTree merkle_tree = new MerkleTree();
        bytes32[][] memory sk = new bytes32[][](t);
        bytes32[][][] memory trees = new bytes32[][][](k);
        bytes32[] memory roots = new bytes32[](k);
        for (uint j =0; j < k; j++){
            bytes32[] memory leafs = new bytes32[](t);
            for (uint i = 0; i < t; i++){
                leafs[i] = PRNG();
            }
            trees[j] = merkle_tree.build_tree_from_values(leafs);
            roots[j] = trees[j][trees[j].length-1][0];
            sk[j] = leafs;
        }
        bytes32 pk = keccak256(abi.encodePacked(roots));
        fors.set_pk(pk);
        
        //signing

        // should be changed based on a. This code is for a = 8;
        bytes32[][] memory signature = new bytes32[][](k);
        bytes32[] memory leafs = new bytes32[](k);
        for (uint i=0; i < k; i++){
            uint index_in_tree = uint8(hashed_message[i]);
            signature[i] = merkle_tree.get_proof(trees[i], index_in_tree);
            leafs[i] = trees[i][0][index_in_tree];
        }
        require(fors.verify(message, signature,leafs),"ERROR verifying");

    }

    uint nonce = 0;
    function PRNG() private returns (bytes32) {
        nonce += 1;
        return
            keccak256(
                abi.encodePacked(nonce, msg.sender, blockhash(block.number - 1))
            );
    }

}