pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";
import {Sphincs_plus, ADRS} from "../../src/sphincs2/sphincs_plus.sol";


contract TestSphincsPlus is Test {
    
    // Struct to represent the secret key
    struct SPHINCS_SK {
        bytes32 SKseed;
        bytes32 SKprf;
        bytes32 PKseed;
        bytes32 PKroot;
    }

    uint32 WOTS_HASH = 0;
    uint32 WOTS_PK = 1;
    uint32 TREE = 2;
    uint32 FORS_TREE = 3;
    uint32 FORS_ROOTS = 4;
    uint32 WOTS_PRF = 5;
    uint32 FORS_PRF = 6;


    uint n = 32;
    uint w = 16;
    uint h = 10;
    uint d = 10;
    uint k = 248;
    bytes32 M = 0;
    uint a = 8;
    uint t = 2 ** a;

    uint len1;
    uint len2;
    uint len;

    SPHINCS_SK sphincs_sk;
    Sphincs_plus.SPHINCS_PK sphincs_pk;
    Sphincs_plus.SPHINCS_SIG sphincs_sig;

    Sphincs_plus sph;
    function setUp()public{
        sph = new Sphincs_plus();
        len1 = (n) / log2(w) + ((n) % log2(w) == 0 ? 0 : 1);
        len2 = (log2(len1 * (w - 1)) / log2(w)) + 1;
        len = len1 + len2;
        spx_keygen();
        spx_sign();
    }

    function test_sphincs()public{
        sph.set_pk(sphincs_pk);
    }

    function spx_sign()public {
        ADRS adrs = new ADRS();
        bytes32 opt = keccak256(abi.encodePacked(block.timestamp, "opt"));
        sphincs_sig.r = keccak256(abi.encodePacked(sphincs_sk.SKprf,opt,M));
    }

    function spx_keygen()public{
        sphincs_sk.SKseed = keccak256(abi.encodePacked(block.timestamp, "SKseed"));
        sphincs_sk.SKprf = keccak256(abi.encodePacked(block.timestamp, "SKprf"));

        sphincs_pk.seed =  keccak256(abi.encodePacked(block.timestamp, "PKseed"));
        sphincs_pk.root = ht_PKgen();

        sphincs_sk.PKseed = sphincs_pk.seed;
        sphincs_sk.PKroot =  sphincs_pk.root;
    }

    function ht_PKgen() public returns (bytes32) {
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(bytes4(uint32(d-1)));
        adrs.setTreeAddress(0);
        return  xmss_PKgen(adrs);
    }

    function xmss_PKgen(ADRS adrs) public returns(bytes32){
        return treehash(0,h/d,adrs);
    }

    function treehash(uint s, uint z, ADRS adrs) public returns(bytes32){
        adrs.setType(WOTS_HASH);   // Type = OTS hash address
        adrs.setKeyPairAddress(bytes4(uint32(s)));
        bytes32 node = wots_PKgen(adrs); 
        adrs.setType(TREE);
        adrs.setTreeHeight(bytes4(uint32(1)));
        adrs.setTreeIndex(bytes4(uint32(s)));
        bytes32[] memory auth = new bytes32[](h);

        //fake auth path
        for (uint i =0; i < (h); i++){
            if (uint32(adrs.getTreeIndex()) > 0){
                adrs.setTreeIndex(bytes4((uint32(adrs.getTreeIndex()) - 1) / 2));
            }
            
            auth[i] = keccak256(abi.encodePacked(block.timestamp,h));
            node = keccak256(abi.encodePacked(sphincs_pk.seed ,adrs.toBytes(),node,auth[i]));
            adrs.setTreeHeight(bytes4(uint32(adrs.getTreeHeight())+1));
        }
        return node;
    }


    function wots_PKgen(ADRS adrs)public returns (bytes32){
        ADRS wotspkADRS = new ADRS();
        wotspkADRS.fillFrom(adrs);
        ADRS skADRS = new ADRS();
        skADRS.fillFrom(adrs);
        skADRS.setType(WOTS_PRF);
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32[] memory sk = new bytes32[](len);
        bytes32[] memory tmp = new bytes32[](len);
        for (uint32 i = 0; i < len; i++ ) {
            skADRS.setChainAddress(bytes4(i));
            skADRS.setHashAddress(0);
            sk[i] = PRF(sphincs_sk.SKseed, skADRS);
            adrs.setChainAddress(bytes4(i));
            adrs.setHashAddress(0);
            tmp[i] = chain(sk[i], 0, w - 1,  sphincs_pk.seed, adrs);
        }
        wotspkADRS.setType(WOTS_PK);
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());

        return keccak256(abi.encodePacked(sphincs_pk.seed,wotspkADRS.toBytes(), tmp));
    }


    function chain(bytes32 X, uint i, uint s,bytes32 SEED, ADRS adrs) public returns (bytes32) {
        if ( s == 0 ) {
            return X;
        }
        if ( (i + s) > (w - 1) ) {
            return 0;
        }
        bytes32 tmp = chain(X, i, s - 1, SEED, adrs);
        adrs.setHashAddress(bytes4(uint32(i + s - 1)));
        tmp = keccak256(abi.encodePacked(SEED, adrs.toBytes(), tmp));
        return tmp;
    }

    function PRF(bytes32 SEED, ADRS adrs) public returns(bytes32){
        return keccak256(abi.encodePacked(SEED,adrs.toBytes()));
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
                let aaaaa := div(mul(x, magic), shift)
                y := div(mload(add(m2,sub(255,aaaaa))), shift)
                y := add(y, mul(256, gt(arg, 0x8000000000000000000000000000000000000000000000000000000000000000)))
            }  
    }

}