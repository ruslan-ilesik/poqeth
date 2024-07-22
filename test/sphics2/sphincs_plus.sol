pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";
import {Sphincs_plus} from "../../src/sphincs2/sphincs_plus.sol";


contract TestSphincsPlus is Test {
    uint n = 32;
    uint w = 16;
    uint h = 60;
    uint d = 10;
    uint k = 248;
    uint a = 8;
    uint t = 2 ** a;

    Sphincs_plus sph;
    function setUp()public{
        sph = new Sphincs_plus();
        spx_keygen();
    }

    function spx_keygen()public returns (Sphincs_plus.SPHINCS_SK memory, Sphincs_plus.SPHINCS_PK memory){
        bytes memory SKseed = new bytes(n);
        bytes memory SKprf = new bytes(n);
        bytes memory PKseed = new bytes(n);
        
        // Pseudo-random generation using keccak256 and block timestamp
        SKseed = abi.encodePacked(keccak256(abi.encodePacked(block.timestamp, "SKseed")));
        SKprf = abi.encodePacked(keccak256(abi.encodePacked(block.timestamp, "SKprf")));
        PKseed = abi.encodePacked(keccak256(abi.encodePacked(block.timestamp, "PKseed")));
    }


}