// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// m = 256 (8 bytes), w = 16, l = (formula in pdf)


import {Test, console} from "forge-std/Test.sol";
import {WOTSPlus} from "../../src/wots_plus/wots_plus.sol";
import "forge-std/console.sol";

contract TestWotsPlusCollect is Test {
    WOTSPlus wots;
    bytes32[] M;
    bytes32[] sigma;
    bytes32[] sk;
    bytes32[] pk;
    bytes32[] r;
    uint256 k;
    uint256 m = 32; //bytes, can not be changed!
    uint16 w = 16; 
    // bits, lets assume it will divisible by 8
    uint256 l1 ;
    uint256 l2;


    function setUp() public{
        string memory message = "Hello";
       
        l1 = (m*8) / log2(w) + ((m*8) % log2(w) == 0 ? 0 : 1);
        l2 = log2(l1*(w-1))/log2(w);
        uint256 l = l1+l2;
        uint256 n = 512;

        wots = new WOTSPlus();
        (sk,pk,r,k) = key_gen(n,l,w);
        

        bytes32 hashed_message = hex"fff0000000000000000000000000000000000000000000000000000000000000";
        //keccak256(abi.encodePacked(message));
        uint256 nhm = uint256(hashed_message);
        M = new bytes32[](l1);
        for (uint256 i = 0; i < l1; i++) {
            M[i] = bytes32(nhm % w);
            nhm /= w;
        }
        sigma = sign(w,k,l1,l2,M,sk,r);
    }

    function test_set_key() public{
         wots.set_pk(keccak256(abi.encodePacked(r,k,pk)));
         wots.set_w(w);
    }

    function testWots() public {
        wots.set_w(w);
        wots.set_pk(keccak256(abi.encodePacked(r,k,pk)));
        assertTrue(wots.verify(M, sigma,pk,r,k));
    }

    function c(bytes32 x, bytes32[] memory r, uint256 k, uint256 i) public pure returns (bytes32) {
        bytes32 result = x;

        for (uint256 j = 0; j < i; j++) {
            result = keccak256(abi.encodePacked(result ^ r[j], k));
        }

        return result;
    }

    //lets assume n is in bytes, not bits for simpler operations;
    function key_gen(uint256 n,uint256 l,uint256 w) public returns (bytes32[] memory sk,bytes32[] memory pk,bytes32[] memory r,uint256 k){
        require(w>1,"w should be >1");
        sk = new bytes32[](l);
        for (uint256 i =0; i < l; i++){
            sk[i] = bytes32(random(n));
        }
        r  = new bytes32[](w-1);
        for (uint256 i =0; i < w-1; i++){
            r[i] = bytes32(random(n));
        }
        pk = new bytes32[](l);
        k = random();
        for (uint256 i =0; i < l; i++){
            pk[i] = c(sk[i],r,k,w-1);
        }
        return (sk,pk,r,k);
    }

    function sign(uint256 w, uint256 k, uint256 l1, uint256 l2, bytes32[] memory M, bytes32[] memory sk, bytes32[] memory r) public view returns (bytes32[] memory sigma) {
        uint256 checksum = 0;
        for (uint256 i = 0; i < l1; i++) {
            checksum += (w - 1 - uint256(M[i]));
        }
        
        bytes32[] memory C = new bytes32[](l2);
        for (uint256 i = 0; i < l2; i++) {
            C[i] = bytes32(checksum % w);
            checksum /= w;
        }
        
        uint256 l = l1 + l2;
        bytes32[] memory B = new bytes32[](l);
        for (uint256 i = 0; i < l1; i++) {
            B[i] = M[i];
        }
        for (uint256 i = 0; i < l2; i++) {
            B[l1 + i] = C[i];
        }
        
        sigma = new bytes32[](l);
        for (uint256 i = 0; i < l; i++) {
            uint256 bi = uint256((B[i]));
            sigma[i] = c(sk[i], r, k, bi);
        }
        
        return sigma;
    }

   function splitBytes32(bytes32 input, uint8 w) public pure returns (bytes32[] memory chunks) {
        require(w % 8 == 0, "w must be divisible by 8");
        require(w > 0 && w <= 256, "Invalid chunk size");

        uint256 chunkCount = 256 / w;
        chunks = new bytes32[](chunkCount);

        uint256 byteSize = w / 8; // Number of bytes in each chunk
        for (uint256 i = 0; i < chunkCount; i++) {
            bytes32 chunk;
            for (uint256 j = 0; j < byteSize; j++) {
                chunk |= (bytes32(uint256(uint8(input[i * byteSize + j])) & 0xFF) >> (j * 8));
            }
            chunks[i] = chunk;
        }

        return chunks;
    }


    //CODE FROM: https://stackoverflow.com/questions/71131781/is-there-an-efficient-way-to-join-an-array-of-strings-into-a-single-string-in-so
    function concat(string[] memory words) public pure returns (string memory) {
        bytes memory output;

        for (uint256 i = 0; i < words.length; i++) {
            output = abi.encodePacked(output, words[i]);
        }

        return string(output);
    }


    //CODE FROM: https://stackoverflow.com/questions/73555009/how-to-generate-random-words-in-solidity-based-on-a-string-of-letters
    // I needed to add this to the random function to generate a different random number
    uint counter =1;

    // size is length of word
    function randomString(uint size) public  payable returns(string memory){
        bytes memory randomWord=new bytes(size);
        for (uint i=0;i<size;i++){
            randomWord[i]= bytes1(uint8(random(255)));
        }
        return string(randomWord);
    }

    function random(uint number) public payable returns(uint){
        counter++;
        return uint(keccak256(abi.encodePacked(block.timestamp,block.prevrandao,  
        msg.sender,counter))) % number;
    }

    function random() public payable returns(uint){
        counter++;
        return uint(keccak256(abi.encodePacked(block.timestamp,block.prevrandao,  
        msg.sender,counter)));
    }

    //CODE FROM: https://ethereum.stackexchange.com/questions/8086/logarithm-math-operation-in-solidity
    function log2(uint x) public pure returns (uint y){
        assembly {
                let arg := x
                x := sub(x,1)
                x := or(x, div(x, 0x02))
                x := or(x, div(x, 0x04))
                x := or(x, div(x, 0x10))
                x := or(x, div(x, 0x100))
                x := or(x, div(x, 0x10000))
                x := or(x, div(x, 0x100000000))
                x := or(x, div(x, 0x10000000000000000))
                x := or(x, div(x, 0x100000000000000000000000000000000))
                x := add(x, 1)
                let m2 := mload(0x40)
                mstore(m2,           0xf8f9cbfae6cc78fbefe7cdc3a1793dfcf4f0e8bbd8cec470b6a28a7a5a3e1efd)
                mstore(add(m2,0x20), 0xf5ecf1b3e9debc68e1d9cfabc5997135bfb7a7a3938b7b606b5b4b3f2f1f0ffe)
                mstore(add(m2,0x40), 0xf6e4ed9ff2d6b458eadcdf97bd91692de2d4da8fd2d0ac50c6ae9a8272523616)
                mstore(add(m2,0x60), 0xc8c0b887b0a8a4489c948c7f847c6125746c645c544c444038302820181008ff)
                mstore(add(m2,0x80), 0xf7cae577eec2a03cf3bad76fb589591debb2dd67e0aa9834bea6925f6a4a2e0e)
                mstore(add(m2,0xa0), 0xe39ed557db96902cd38ed14fad815115c786af479b7e83247363534337271707)
                mstore(add(m2,0xc0), 0xc976c13bb96e881cb166a933a55e490d9d56952b8d4e801485467d2362422606)
                mstore(add(m2,0xe0), 0x753a6d1b65325d0c552a4d1345224105391a310b29122104190a110309020100)
                mstore(0x40, add(m2, 0x100))
                let magic := 0x818283848586878898a8b8c8d8e8f929395969799a9b9d9e9faaeb6bedeeff
                let shift := 0x100000000000000000000000000000000000000000000000000000000000000
                let a := div(mul(x, magic), shift)
                y := div(mload(add(m2,sub(255,a))), shift)
                y := add(y, mul(256, gt(arg, 0x8000000000000000000000000000000000000000000000000000000000000000)))
            }  
    }
}