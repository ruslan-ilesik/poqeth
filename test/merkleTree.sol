// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {MerkleTree} from "../src/merkleTree.sol";
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

        bytes32 hash01 = keccak256(abi.encodePacked(hashes[0], hashes[1]));
        bytes32 hash23 = keccak256(abi.encodePacked(hashes[2], hashes[3]));

        bytes32 hash0123 = keccak256(abi.encodePacked(hash01, hash23));
        root = keccak256(abi.encodePacked(hash0123, hashes[4]));
    }

    function testBuildRoot() public view {
        // Convert fixed-size array to dynamic array
        bytes32[] memory dynamicHashes = new bytes32[](hashes.length);
        for (uint i = 0; i < hashes.length; i++) {
            dynamicHashes[i] = hashes[i];
        }
        assertEq(0x3f2aa635540eedc87048b0ede6e41d1d1e97d0c22580b7795d8af7ded6a75bf0, tree.buildRoot(dynamicHashes));
    }

    function testProof() view public {
        bytes32[6] memory leaves = [bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)), bytes32(uint256(4)), bytes32(uint256(5)), bytes32(uint256(6))];

        // Convert fixed-size array to dynamic array
        bytes32[] memory dynamicLeaves = new bytes32[](leaves.length);
        for (uint i = 0; i < leaves.length; i++) {
            dynamicLeaves[i] = leaves[i];
        }

        bytes32[][] memory builtTree = tree.buildTreeFromValues(dynamicLeaves);
        // printTree(builtTree);
        bytes32[] memory proof = tree.getProof(builtTree, 3);
        assertTrue(tree.verifyProof(builtTree[builtTree.length - 1][0], keccak256(abi.encodePacked(leaves[3])), proof, 3));
    }

    function printTree(bytes32[][] memory builtTree) public view {
        // Iterate over the first dimension of the array
        for (uint i = 0; i < builtTree.length; i++) {
            console.log("Row ", i, ":");
            // Iterate over the second dimension of the array
            for (uint j = 0; j < builtTree[i].length; j++) {
                console.logBytes32(builtTree[i][j]);
            }
        }
    }
}
