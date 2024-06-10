// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

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
                    new_level[i / 2] = hashes[i];
                }
            }
            hashes = new_level;
        }

        return hashes[0];
    }
}

