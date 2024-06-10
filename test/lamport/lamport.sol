// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Lamport} from "../../src/lamport/lamport.sol";

contract TestLamport is Test {
    Lamport public lamp;
    uint256 nonce = 0;
    bytes32[512] private_key;
    bytes32[512] generated_public_key;
    string message;
    bytes32[256] signature;

    function setUp() public {
        message ="ilesik";
        lamp = new Lamport();
        generated_public_key = key_gen();
        test_set_key();
        msg_encode();
    }

    function test_set_key() public{
        lamp.set_public_key(generated_public_key);
    }
    
    function test_verify() public view {
        assertTrue(lamp.verify(message, signature));
    }

    function test_wrong_verify() public view {
        assertFalse(lamp.verify(string.concat(message, " bye"), signature));
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
        returns ( bytes32[512] memory)
    {
        bytes32[512] memory public_key;
        for (uint256 i = 0; i < 512; i++) {
            private_key[i] = PRNG();
            public_key[i] = keccak256(abi.encodePacked(private_key[i]));
        }
        return (public_key);
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
