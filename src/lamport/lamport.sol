// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Lamport {
    bytes32[512] public_key;

    constructor() {}

   function set_public_key(bytes32[512] calldata pb) public {
    public_key = pb;
   }

    function verify(
        string calldata message,
        bytes32[256] calldata signature
    ) public view returns (bool) {
        bytes32 msg_bytes = keccak256(abi.encodePacked(message));
        for (uint8 i = 0; i < 32; i++) {
            bytes1 b = msg_bytes[i];
            for (uint8 j = 0; j < 8; j++) {
                uint16 indx = i * 8 + j;
                // hash and compare to publick key
                if (keccak256(abi.encodePacked(signature[indx])) != public_key[indx * 2 + (uint8(b >> (7 - j)) & 1)]){
                    return false;
                }
            }
        }
        return true;
    }


}

