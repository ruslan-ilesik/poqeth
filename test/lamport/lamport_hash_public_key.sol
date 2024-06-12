// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {LamportHashPublicKey} from "../../src/lamport/lamport_hash_public_key.sol";




contract TestLamportHashPublicKey is Test {
    LamportHashPublicKey public lamp;
    uint256 nonce = 0;
    bytes32[512] private_key;
    bytes32[512] raw_private_key;
    string message;
    bytes32[256] signature;

    function setUp() public {
        message ="ilesik";
        lamp = new LamportHashPublicKey();
        bytes32 generated_public_key;
        generated_public_key = key_gen();
        test_set_key(generated_public_key);
        msg_encode();
    }

    function test_set_key(bytes32 generated_public_key) public{
        lamp.set_public_key(generated_public_key);
    }
    
    function test_verify() public view {
        assertTrue(lamp.verify(message, signature,raw_private_key));
    }

    function PRNG() private returns (bytes32) {
        nonce += 1;
        return
            keccak256(
                abi.encodePacked(nonce, msg.sender, blockhash(block.number - 1))
            );
    }

     function key_gen()
        public
        returns ( bytes32)
    {
        for (uint256 i = 0; i < 512; i++) {
            private_key[i] = PRNG();
            raw_private_key[i] = keccak256(abi.encodePacked(private_key[i]));
        }
        return keccak256(abi.encodePacked(raw_private_key));
    }

     function msg_encode()
        public 
    {
        bytes32 msg_bytes = keccak256(abi.encodePacked(message));

        for (uint256 i = 0; i < 32; i++) {
            bytes1 b = msg_bytes[i];
            for (uint256 j = 0; j < 8; j++) {
                uint256 indx = i * 8 + j;
                //private key bit by bit trasform to signature
                signature[indx] = private_key[
                    indx * 2 + (uint8(b >> (7 - j)) & 1)
                ];
            }
        }
    }
}