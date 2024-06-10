// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {LamportMerkleTree} from "../../src/lamport/lamport_merkle_tree.sol";
import {MerkleTree} from "../../src/merkle_tree.sol";


contract TestLamportMerkleTree is Test {
    LamportMerkleTree lamp;
    MerkleTree tree;
    uint256 nonce = 0;
    bytes32[512] private_key;
    bytes32[] public_key;
    string message;
    bytes32[256] signature;
    bytes32 key;

    function setUp() public{
        message ="ilesik";
        public_key = new bytes32[](512);
        lamp = new LamportMerkleTree();
        tree = new MerkleTree();
        key_gen();
        key = tree.build_root(public_key);
        msg_encode();
        test_set_key();
    }

    function test_set_key() public{
        lamp.set_public_key(key);
    }

     function test_verify() public {
        assertTrue(lamp.verify(message, signature,public_key));
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
    {
        for (uint256 i = 0; i < 512; i++) {
            private_key[i] = PRNG();
            public_key[i] = keccak256(abi.encodePacked(private_key[i]));
        }
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