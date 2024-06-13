// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {MerkleTree} from "../merkle_tree.sol";

contract LamportMerkleTree {
    constructor() {}

    bytes32 public_key;

    function set_public_key(bytes32 pb) public {
        public_key = pb;
    }

    function verify(
        string calldata message,
        bytes32[256] calldata signature,
        bytes32[] calldata raw_public_key
    ) public returns (bool) {
        require(raw_public_key.length == 512, "public key should be 512 elements long");
        unchecked { //1294444 to 
            bytes32 msg_bytes = keccak256(abi.encodePacked(message));
            for (uint8 i = 0; i < 32; i++) {
                bytes1 b = msg_bytes[i];
                for (uint8 j = 0; j < 8; j++) {
                    uint16 indx = i * 8 + j;
                    // hash and compare to public key
                    if (keccak256(abi.encodePacked(signature[indx])) != raw_public_key[indx * 2 + (uint8(b >> (7 - j)) & 1)]) {
                        return false;
                    }
                }
            }
            MerkleTree m = new MerkleTree();
            return public_key == m.build_root(raw_public_key);
        }
    }
}
