// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


import {Test, console} from "forge-std/Test.sol";
import {Xmss,ADRS} from "../../src/xmss/xmss.sol";
import "forge-std/console.sol";


contract TestXmss is Test {
    Xmss xmss;
    uint h = 2;
    uint w = 4;
    bytes32 Mp = 0xfffffffffffffffffffffffff800000000000000000000000000000000000000;
    uint m = 32; // constant
    uint n = 32; // constant as we just random 256 bit hashes
    //uint a = 8;
    uint t = 2**8;//2 ** 8;
    bytes32 skPrf;
    bytes32 seed;
    uint256 l1 ;
    uint256 l2;
    uint256 l;
    bytes32[] wotsSk;
    bytes32[] wotsPk;
    bytes32[] r;
    bytes32 k;
    bytes32 root ;
    uint idx = 0;
 
    Xmss.PK xmssPk;
    Xmss.SIG xmssSig;



    function setUp() public{
        xmss = new Xmss();
        l1 = (m*8) / log2(w) + ((m*8) % log2(w) == 0 ? 0 : 1);
        l2 = log2(l1*(w-1))/log2(w);
        l = l1+l2;
        xmssKeyGen();
        xmssSig.idxSig =uint32(idx);
        xmssSig.r = keccak256(abi.encodePacked(skPrf,idx));
        ADRS adrs = new ADRS();
        adrs.setType(0);   // Type = OTS hash address
        adrs.setOTSAddress(uint32(idx));

        xmssSig.sigOts = wotsSign(adrs);


    }

    function xmssKeyGen()public {
        wotsSk = wotsKeySk();
        skPrf= random();
        seed = random();
        ADRS adrs = new ADRS();
        //also defines auth path as we anyway fake all nodes
        root = treehash(0,adrs);
        xmssPk = Xmss.PK(root,seed);
    }

    function wotsSign(ADRS adrs)  public returns (bytes32[] memory sig){
        uint256 csum = 0;
        bytes32[] memory msg = baseW(Mp, l1);
        for (uint i = 0; i < l1; i++ ) {
            csum = csum + w - 1 - uint256(msg[i]);
        }
        csum = csum << ( 8 - ( ( l2 * log2(w) ) % 8 ));
        uint len2Bytes = ceil( ( l2 * log2(w) ), 8 );
        bytes32[] memory msg2 = baseW(toByte(csum, len2Bytes), l2);
        sig = new bytes32[](l);
        for (uint i = 0; i < l; i++ ) {
          adrs.setChainAddress(uint32(i));
          if (i < l1){
            sig[i] = chain(wotsSk[i], 0, uint(msg[i]), adrs);
          }
          else{
            sig[i] = chain(wotsSk[i], 0, uint(msg2[i-l1]), adrs);
          }
          
        }
        return sig;
    }

    function toByte(uint256 x, uint y) public pure returns (bytes memory) {
        bytes memory b = new bytes(y);
        for (uint i = 0; i < y; i++) {
            b[i] = bytes1(uint8(x >> (8 * (y - 1 - i))));
        }
        return b;
    }

    function baseW(bytes memory X,uint outLen) public returns (bytes32[] memory){
        uint iin = 0;
        uint out = 0;
        uint8 total = 0;
        uint bits = 0;
        uint consumed;
        bytes32[] memory basew = new bytes32[](outLen);
        for (consumed = 0; consumed < outLen; consumed++ ) {
           if ( bits == 0 ) {
               total = uint8(X[iin]);
               iin++;
               bits += 8;
           }
           bits -= log2(w);
           basew[out] = bytes32((total >> bits) & (w - 1));
           out++;
       }
       return basew;
    }

    function baseW(bytes32 X,uint outLen) public returns (bytes32[] memory){
        uint iin = 0;
        uint out = 0;
        uint8 total = 0;
        uint bits = 0;
        uint consumed;
        bytes32[] memory basew = new bytes32[](outLen);
        for (consumed = 0; consumed < outLen; consumed++ ) {
           if ( bits == 0 ) {
               total = uint8(X[iin]);
               iin++;
               bits += 8;
           }
           bits -= log2(w);
           basew[out] = bytes32((total >> bits) & (w - 1));
           out++;
       }
       return basew;

    }

    function treehash(uint s, ADRS adrs) public returns (bytes32) {
        //require(s % (uint256(1) << h) == 0,"treeHash cond fail");
        adrs.setType(0);   // Type = OTS hash address
        adrs.setOTSAddress(uint32(s));
        bytes32[] memory pk = wotsKeyPk(adrs);
        adrs.setType(1);   // Type = L-tree address
        adrs.setLTreeAddress(uint32(s));
        bytes32 node = ltree(pk,adrs);
        //console.logBytes32(node);
        adrs.setType(2);   // Type = hash tree address
        adrs.setTreeHeight(0);
        adrs.setTreeIndex(uint32(s));
        //fake other trees with random values, we need only one message tree for verefication testing
        xmssSig.auth = new bytes32[](h);
        for (uint i =0; i < (h); i++){
            xmssSig.auth[i] = random();
            node = randHash(node,xmssSig.auth[i], adrs);
            adrs.setTreeHeight(uint32(adrs.getTreeHeight())+1);
        }
        //console.logBytes32(node);
        return node;
    }
    function ceil(uint a, uint b) internal pure returns (uint) {
        return (a + b - 1) / b;
    }

    function randHash(bytes32 l, bytes32 r,ADRS adrs)public returns (bytes32){
        adrs.setKeyAndMask(0);
        bytes32 KEY = PRF(adrs);
        adrs.setKeyAndMask(1);
        bytes32 BM0 = PRF(adrs);
        adrs.setKeyAndMask(2);
        bytes32 BM1 = PRF(adrs);
        return keccak256(abi.encodePacked(KEY, (l ^ BM0), (r ^ BM1)));
    }  

    function ltree(bytes32[] memory pk, ADRS addrs)public  returns (bytes32){
        uint len = l;
        addrs.setTreeHeight(0);
        while ( len > 1 ) {
            for ( uint i = 0; i < (len / 2); i++ ) {
                addrs.setTreeIndex(uint32(i));
                pk[i] = randHash(pk[2*i], pk[2*i + 1], addrs);
            }
            if ( len % 2 == 1 ) {
                pk[(len / 2)] = pk[len - 1];
            }
            len = ceil(len, 2);
            addrs.setTreeHeight(uint32(addrs.getTreeHeight()) + 1);
        }
        return pk[0];

    } 

    function chain(bytes32 X, uint i, uint s, ADRS adrs) public returns (bytes32) {
        if ((i + s) > (w - 1)) {
            return 0;
        }

        bytes32 tmp = X;

        for (uint k = 0; k < s; k++) {
            adrs.setHashAddress(uint32(i + k));
            adrs.setKeyAndMask(0);
            bytes32 KEY = PRF(adrs);
            adrs.setKeyAndMask(1);
            bytes32 BM = PRF(adrs);
            tmp = keccak256(abi.encodePacked(KEY, tmp ^ BM));
        }

        return tmp;
    }


    function wotsKeyPk(ADRS adrs)public returns(bytes32[] memory){
        bytes32[] memory pk = new bytes32[](l);
        for ( uint i = 0; i < l; i++ ) {
            adrs.setChainAddress(uint32(i));
            pk[i] = chain(wotsSk[i], 0, w - 1, adrs);
        }
        return pk;
    }

    function wotsKeySk() public returns (bytes32[] memory sk){
        require(w>1,"w should be >1");
        sk = new bytes32[](l);
        for (uint256 i =0; i < l; i++){
            sk[i] = bytes32(random());
        }
        return sk;
    }

    function testXmss() public{
        xmss.setPk(xmssPk);
        require(xmss.verify(xmssSig, Mp, w,h),"verefication failed");
        // PLACE HOLDER START
        // PLACE HOLDER END
    }

    uint counter = 0;
    function random() public payable returns(bytes32){
        counter++;
        return keccak256(abi.encodePacked(block.timestamp,block.prevrandao,  
        msg.sender,counter));
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

    function c(bytes32 x, bytes32[] memory r,bytes32 k, uint256 i)public pure returns (bytes32){
        if (i==0){
            return x;
        }
        return keccak256(abi.encodePacked(c(x, r, k, i - 1) ^ r[i - 1],k));
    } 

    function PRF(ADRS adrs) public returns(bytes32){
        return keccak256(abi.encodePacked(seed,adrs.toBytes()));
    }
}