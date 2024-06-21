// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


import {Test, console} from "forge-std/Test.sol";
import {MerkleTree} from "../src/merkle_tree.sol";
import "forge-std/console.sol";


contract TestMerkleTree is Test {
    MerkleTree tree;
    bytes32[5] hashes;
    bytes32 root;

    function setUp() public {
        tree = new MerkleTree();
        hashes[0] = keccak256(abi.encodePacked("leaf1"));
        hashes[1] = keccak256(abi.encodePacked("leaf2"));
        hashes[2] = keccak256(abi.encodePacked("leaf3"));
        hashes[3] = keccak256(abi.encodePacked("leaf4"));
        hashes[4] = keccak256(abi.encodePacked("leaf5"));

        bytes32 hash_01 = keccak256(abi.encodePacked(hashes[0], hashes[1]));
        bytes32 hash_23 = keccak256(abi.encodePacked(hashes[2], hashes[3]));

        bytes32 hash_0123 = keccak256(abi.encodePacked(hash_01,hash_23));
        root = keccak256(abi.encodePacked(hash_0123,hashes[4]));
    }

    function test_build_root() public view{
        // Convert fixed-size array to dynamic array
        bytes32[] memory dynamicHashes = new bytes32[](hashes.length);
        for (uint i = 0; i < hashes.length; i++) {
            dynamicHashes[i] = hashes[i];
        }

        assertEq(root, tree.build_root(dynamicHashes));
        assertNotEq(keccak256(abi.encodePacked(root)), tree.build_root(dynamicHashes));
    }

    function test_proof() public {
        bytes32[6] memory leafs = [bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), bytes32(uint256(4)), bytes32(uint256(5)), bytes32(uint256(6))];

        // Convert fixed-size array to dynamic array
        bytes32[] memory dynamicLeafs = new bytes32[](leafs.length);
        for (uint i = 0; i < leafs.length; i++) {
            dynamicLeafs[i] = leafs[i];
        }

        bytes32[][] memory built_tree = tree.build_tree_from_values(dynamicLeafs);
        //printTree(built_tree);
        bytes32[] memory proof = tree.get_proof(built_tree, 3);
        assertTrue(tree.verify_proof(built_tree[built_tree.length-1][0], keccak256(abi.encodePacked(leafs[3])), proof, 3)); 
    }



    function printTree(bytes32[][] memory built_tree) public view {
        // Iterate over the first dimension of the array
        for (uint i = 0; i < built_tree.length; i++) {
            console.log("Row ", i, ":");
            // Iterate over the second dimension of the array
            for (uint j = 0; j < built_tree[i].length; j++) {
                console.logBytes32(built_tree[i][j]);
            }
        }
    }

}