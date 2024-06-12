// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


import {Test, console} from "forge-std/Test.sol";

contract TestWotsPlus is Test {
    function setUp() public{
        key_gen(4,16,5);
    }




    //lets assume n is in bytes not bits for simpler operations;
    function key_gen(uint256 n,uint256 l,uint256 w) public returns (string[] memory sk,bytes32[] memory pk,uint256[] memory r){
        require(w>1,"w should be >1");
        sk = new string[](l);
        for (uint256 i =0; i < l; i++){
            sk[i] = randomString(n);
        }
        r  = new uint256[](w-1);
        for (uint256 i =0; i < w-1; i++){
            r[i] = random();
        }
        pk = new bytes32[](l+1);
        pk[0] = keccak256(abi.encodePacked(r,random()));
        for (uint256 i=1; i < l+1; i++){
            bytes32 hashed = keccak256(abi.encodePacked(sk[i-1],r));
            for (uint j =0; j < w-2;j++){
                hashed = keccak256(abi.encodePacked(hashed));
            }
            pk[i] = hashed;
        }
        return (sk,pk,r);
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
}