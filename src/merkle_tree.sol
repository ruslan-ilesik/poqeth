// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";

contract MerkleTree {

    constructor(){}

    //Accepts previously hashed values
    function build_root(bytes32[] memory hashes) public pure returns (bytes32) {
        require(hashes.length > 0, "No hashes provided");

        // While there's more than one hash in the array
        while (hashes.length > 1) {
            uint newLength = (hashes.length + 1) / 2; // Number of pairs
            bytes32[] memory new_level = new bytes32[](newLength);

            for (uint i = 0; i < hashes.length; i += 2) {
                if (i + 1 < hashes.length) {
                    new_level[i / 2] = keccak256(abi.encodePacked(hashes[i], hashes[i + 1]));
                } else {
                    new_level[i / 2] = keccak256(abi.encodePacked(hashes[i],bytes32(0)));
                }
            }
            hashes = new_level;
        }

        return hashes[0];
    }

    function build_root_from_pure_values(bytes32[] memory values) public pure returns (bytes32) {
        for (uint i=0; i < values.length; i++){
            values[i] = keccak256(abi.encodePacked(values[i]));
        }
        return build_root(values);
    }

     // Accepts previously hashed values
    function build_tree(bytes32[] memory hashes) public  returns (bytes32[][] memory) {
        require(hashes.length > 0, "No hashes provided");
        // Calculate the number of levels in the tree
        uint256 levels = 1;
        uint256 tempLength = hashes.length;
        while (tempLength > 1) {
            tempLength = (tempLength + 1) / 2;
            levels++;
        }

        // Create an array to hold each level of the tree
        bytes32[][] memory tree = new bytes32[][](levels);
        tree[0] = hashes;

        // Build the tree
        for (uint256 level = 0; level < levels - 1; level++) {
            uint256 currentLength = tree[level].length;
            uint256 newLength = (currentLength + 1) / 2;
            tree[level + 1] = new bytes32[](newLength);

            for (uint256 i = 0; i < currentLength; i += 2) {
                if (i + 1 < currentLength) {
                    tree[level + 1][i / 2] = keccak256(abi.encodePacked(tree[level][i], tree[level][i + 1]));
                } else {
                    tree[level + 1][i / 2] = keccak256(abi.encodePacked(tree[level][i],bytes32(0)));
                }
            }
        }
        return tree;
    }

    function build_tree_from_values(bytes32[] memory values) public returns (bytes32[][] memory) {
        for (uint256 i = 0; i < values.length; i++) {
            values[i] = keccak256(abi.encodePacked(values[i]));
        }
        return build_tree(values);
    }

    function get_proof(bytes32[][] memory tree, uint256 index) public returns (bytes32[] memory) {
        require(tree.length > 0, "Tree is empty");

        uint256 totalLevels = tree.length;
        bytes32[] memory proof = new bytes32[](totalLevels - 1);

        for (uint256 level = 0; level < totalLevels - 1; level++) {
            uint256 pairIndex = index % 2 == 0 ? index + 1 : index - 1;
            if (pairIndex < tree[level].length) {
                proof[level] = tree[level][pairIndex];
            } else {
                console.logUint(totalLevels);
                console.logUint(level);
                console.logUint(tree[level].length);
                console.logUint(index);
                console.logUint(pairIndex);
                proof[level] = bytes32(0);
            }
            index /= 2;
        }
        return proof;
    }

    function verify_proof(bytes32 root, bytes32 leaf, bytes32[] memory proof, uint256 index) public pure returns (bool) {
        return root_from_proof(leaf, proof, index) == root;
    }

    function root_from_proof( bytes32 leaf, bytes32[] memory proof, uint256 index) public pure returns (bytes32){
        bytes32 hhash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                hhash = keccak256(abi.encodePacked(hhash, proof[i]));
            } else {
                hhash = keccak256(abi.encodePacked(proof[i], hhash));
            }
            index /= 2;
        }
        return hhash;
    }
}

