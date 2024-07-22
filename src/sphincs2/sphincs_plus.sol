// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Sphincs_plus{
    uint n = 32;
    uint w = 16;
    uint h = 60;
    uint d = 10;
    uint k = 248;
    uint a = 8;
    uint t = 2 ** a;

    // Struct to represent the public key
    struct SPHINCS_PK {
        bytes PKseed;
        bytes PKroot;
    }

    // Struct to represent the secret key
    struct SPHINCS_SK {
        bytes SKseed;
        bytes SKprf;
        bytes PKseed;
        bytes PKroot;
    }


}