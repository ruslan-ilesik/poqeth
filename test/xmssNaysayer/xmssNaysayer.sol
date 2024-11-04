// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


import {Test, console} from "forge-std/Test.sol";
import {XmssNaysayer,ADRS} from "../../src/xmssNaysayer/xmssNaysayer.sol";
import {MerkleTree} from "../../src/merkle_tree.sol";
import "forge-std/console.sol";

//4397356 h=1
//4413730 h=2
//4430119 h=3


//4709188 h=20
//4725636 h=21
contract TestXmssNaysayer is Test {
    XmssNaysayer xmss;
    MerkleTree mt;
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

    bytes32[] htAdditionalNodes;
    bytes32[] wotsPkHash;

    bytes32 ltreeRes;

    uint idx = 0;
 
    XmssNaysayer.PK xmssPk;
    XmssNaysayer.SIG xmssSig;

    uint256 len1;
    uint256 len2;
    uint256 lengthAll;


    function setUp() public{
        wotsPkHash = new bytes32[](1);
        xmss = new XmssNaysayer();
        mt = new MerkleTree();
        l1 = (m*8) / log2(w) + ((m*8) % log2(w) == 0 ? 0 : 1);
        l2 = log2(l1*(w-1))/log2(w);
        l = l1+l2;

        len1 = l1;
        len2 = l2;
        lengthAll = l;

        xmssKeyGen();
        xmssSig.idxSig =uint32(idx);
        xmssSig.r = keccak256(abi.encodePacked(skPrf,idx));
        ADRS adrs = new ADRS();
        adrs.setType(0);   // Type = OTS hash address
        adrs.setOTSAddress(uint32(idx));

        xmssSig.sigOts = wotsSign(adrs);
        xmss.setArgs(uint8(w),uint8(h));

    }


    function testXmssWots() public{
        xmss.setPk(xmssPk);
        bytes32[] memory sig = concatenateBytes32Arrays([wotsPkHash,xmssSig.auth,xmssSig.sigOts,wotsPk,htAdditionalNodes]);
        bytes32 root = mt.buildRoot(sig);
        bytes32[][] memory tree = mt.buildTree(sig);
        xmss.setSig(root,xmssSig.idxSig,xmssSig.r, uint8(h), Mp,xmssSig.auth.length, xmssSig.sigOts.length,wotsPk.length);
        
        bytes32[] memory p1 = mt.getProof(tree, xmssSig.auth.length);
        bytes32[] memory p2 = mt.getProof(tree, xmssSig.auth.length + xmssSig.sigOts.length);
        /*require(xmss.naysayerWots(0, xmssSig.sigOts[0], p1, wotsPk[0], p2), "failed good path");
        p2[0] = p2[0] ^ bytes1(uint8(1));
        require(xmss.naysayerWots(0, xmssSig.sigOts[0], p1, wotsPk[0], p2) == false, "passed bad path");*/

        //require(xmss.naysayerWots(0,xmssSig.auth.length, sig[xmssSig.auth.length], mt.getProof(tree,xmssSig.auth.length)) == false,"good sign failed for xmss");

        require(xmss.naysayerWots(0, xmssSig.sigOts[0], p1, wotsPk[0], p2) == false, "failed no error");

        xmssSig.sigOts[0] = xmssSig.sigOts[0] ^ bytes1(uint8(1));
        sig = concatenateBytes32Arrays([wotsPkHash,xmssSig.auth,xmssSig.sigOts,wotsPk,htAdditionalNodes]);
        root = mt.buildRoot(sig);
        tree = mt.buildTree(sig);
        p1 = mt.getProof(tree, 1+xmssSig.auth.length);
        p2 = mt.getProof(tree, 1+xmssSig.auth.length + xmssSig.sigOts.length);
        xmss.setSig(root,xmssSig.idxSig,xmssSig.r, uint8(h), Mp,xmssSig.auth.length, xmssSig.sigOts.length,wotsPk.length);
        require(xmss.naysayerWots(0, xmssSig.sigOts[0], p1, wotsPk[0], p2) , "failed to detect error");
        xmssSig.sigOts[0] = xmssSig.sigOts[0] ^ bytes1(uint8(1));
    }


    function testXmssHt()public{
        {
        xmss.setPk(xmssPk);
        bytes32[] memory sig = concatenateBytes32Arrays([wotsPkHash,xmssSig.auth,xmssSig.sigOts,wotsPk,htAdditionalNodes]);
        bytes32 root = mt.buildRoot(sig);
        bytes32[][] memory tree = mt.buildTree(sig);
        xmss.setSig(root,xmssSig.idxSig,xmssSig.r, uint8(h), Mp,xmssSig.auth.length, xmssSig.sigOts.length,wotsPk.length);
        bytes32[] memory p1 = mt.getProof(tree, 1+xmssSig.auth.length+xmssSig.sigOts.length+wotsPk.length+2);
        bytes32[] memory p2 = mt.getProof(tree, 1+xmssSig.auth.length+xmssSig.sigOts.length+wotsPk.length+1);
        bytes32[] memory p3 = mt.getProof(tree, 1);


        //check that elems in signature
        //require(xmss.naysayerHT(2, htAdditionalNodes[2], p1, htAdditionalNodes[1], p2, xmssSig.auth[1], p3),"failed good elements");
        //require(xmss.naysayerHT(2, htAdditionalNodes[1], p1, htAdditionalNodes[1], p2, xmssSig.auth[1], p3) == false,"passed bad elements");

        require(xmss.naysayerHT(2, htAdditionalNodes[2], p1, htAdditionalNodes[1], p2, xmssSig.auth[1], p3)== false,"passed with no mistake");
        }
        {
            xmss.setPk(xmssPk);
            htAdditionalNodes[2] = htAdditionalNodes[2] ^ bytes32(uint(1));
            bytes32[] memory sig = concatenateBytes32Arrays([wotsPkHash,xmssSig.auth,xmssSig.sigOts,wotsPk,htAdditionalNodes]);
            bytes32 root = mt.buildRoot(sig);
            bytes32[][] memory tree = mt.buildTree(sig);
            xmss.setSig(root,xmssSig.idxSig,xmssSig.r, uint8(h), Mp,xmssSig.auth.length, xmssSig.sigOts.length,wotsPk.length);
            bytes32[] memory p1 = mt.getProof(tree, 1+xmssSig.auth.length+xmssSig.sigOts.length+wotsPk.length+2);
            bytes32[] memory p2 = mt.getProof(tree, 1+xmssSig.auth.length+xmssSig.sigOts.length+wotsPk.length+1);
            bytes32[] memory p3 = mt.getProof(tree, 1+1);


            //check that elems in signature
            //require(xmss.naysayerHT(2, htAdditionalNodes[2], p1, htAdditionalNodes[1], p2, xmssSig.auth[1], p3),"failed good elements");
            //require(xmss.naysayerHT(2, htAdditionalNodes[1], p1, htAdditionalNodes[1], p2, xmssSig.auth[1], p3) == false,"passed bad elements");

            require(xmss.naysayerHT(2, htAdditionalNodes[2], p1, htAdditionalNodes[1], p2, xmssSig.auth[1], p3),"good proof failed");
            htAdditionalNodes[2] = htAdditionalNodes[2] ^ bytes32(uint(1));
        }
    }

    function testXmssLTree() public{
        {
            xmss.setPk(xmssPk);
            bytes32[] memory sig = concatenateBytes32Arrays([wotsPkHash,xmssSig.auth,xmssSig.sigOts,wotsPk,htAdditionalNodes]);
            bytes32 root = mt.buildRoot(sig);
            bytes32[][] memory tree = mt.buildTree(sig);
            xmss.setSig(root,xmssSig.idxSig,xmssSig.r, uint8(h), Mp,xmssSig.auth.length, xmssSig.sigOts.length,wotsPk.length);
            bytes32[] memory p1 = mt.getProof(tree,0);
            bytes32[] memory p2 = mt.getProof(tree,1+xmssSig.auth.length+xmssSig.sigOts.length+wotsPk.length);
            //check signature path
            //require(xmss.naysayerLtree(xmssSig.sigOts, p1, ltreeRes, p2),"failed good elements");
            //xmssSig.sigOts[0] = xmssSig.sigOts[0] ^ bytes1(uint8(1));
            //require(xmss.naysayerLtree(xmssSig.sigOts, p1, ltreeRes, p2) == false,"pased bad elements");
            //xmssSig.sigOts[0] = xmssSig.sigOts[0] ^ bytes1(uint8(1));
            
            //console.logBytes();
            
            require(xmss.naysayerLTree(wotsPk, p1, ltreeRes, p2)==false,"passed when no error");
        }

        {
            ltreeRes = ltreeRes ^ bytes32(uint(1));
            htAdditionalNodes[0] = htAdditionalNodes[0] ^  bytes32(uint(1));
            xmss.setPk(xmssPk);
            bytes32[] memory sig = concatenateBytes32Arrays([wotsPkHash,xmssSig.auth,xmssSig.sigOts,wotsPk,htAdditionalNodes]);
            bytes32 root = mt.buildRoot(sig);
            bytes32[][] memory tree = mt.buildTree(sig);
            //xmss.setSig(root,xmssSig.idxSig,xmssSig.r, uint8(h), Mp,xmssSig.auth.length, xmssSig.sigOts.length,wotsPk.length);
            xmss.setSigFromVar(wotsPkHash, xmssSig.auth, xmssSig.sigOts, wotsPk, htAdditionalNodes, xmssSig.idxSig, xmssSig.r, uint8(h), Mp);
            bytes32[] memory p1 = mt.getProof(tree,0);
            bytes32[] memory p2 = mt.getProof(tree,1+xmssSig.auth.length+xmssSig.sigOts.length+wotsPk.length);
            require(xmss.naysayerLTree(wotsPk, p1, ltreeRes, p2),"failed when valid error");
            ltreeRes = ltreeRes ^ bytes32(uint(1));
            htAdditionalNodes[0] = htAdditionalNodes[0] ^  bytes32(uint(1));
        }
    }

    
    function wotsPkFromSig(bytes32[] memory sig,bytes32 M, ADRS adrs)public returns(bytes32[] memory){
        uint csum = 0;
        bytes32[] memory msg = baseW(M,len1);
        for (uint i = 0; i < len1; i++ ) {
           csum = csum + w - 1 - uint(msg[i]);
        }
        csum = csum << ( 8 - ( ( len2 * log2(w) ) % 8 ));
        uint len2Bytes = ceil( ( len2 * log2(w) ), 8 );
        bytes32[] memory msg2 = baseW(toByte(csum, len2Bytes),len2);
        bytes32[] memory tmpPk = new bytes32[](lengthAll);
        for (uint i = 0; i < lengthAll; i++ ) {
          adrs.setChainAddress(uint32(i));
          if (i < len1){
            tmpPk[i] = chain(sig[i], uint(msg[i]), w - 1 - uint(msg[i]), adrs);
          }
          else{
            tmpPk[i] = chain(sig[i], uint(msg2[i-len1]), w - 1 - uint(msg2[i-len1]), adrs);
          }
        }
        return tmpPk;
    }

    function xmssKeyGen()public {
        wotsSk = wotsKeySk();
        skPrf= random();
        seed = random();
        ADRS adrs = new ADRS();
        //also defines auth path as we anyway fake all nodes
        root = treehash(0,adrs);
        xmssPk = XmssNaysayer.PK(root,seed);
    }

    function wotsSign(ADRS adrs)  public returns (bytes32[] memory sig){
        uint256 csum = 0;
        ADRS adrsCopy = new ADRS();
        adrsCopy.fillFrom(adrs);
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

    function baseW(bytes memory X,uint outLen) public view returns (bytes32[] memory){
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

    function baseW(bytes32 X,uint outLen) public view returns (bytes32[] memory){
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
        wotsPk = pk;
        wotsPkHash[0] = keccak256(abi.encodePacked(pk));
        bytes32 node = ltree(pk,adrs);
        ltreeRes = node;
        adrs.setType(2);   // Type = hash tree address
        adrs.setTreeHeight(0);
        adrs.setTreeIndex(uint32(s));
        //fake other trees with random values, we need only one message tree for verefication testing
        xmssSig.auth = new bytes32[](h);
        htAdditionalNodes = new bytes32[](h+1);
        for (uint i =0; i < (h); i++){
            htAdditionalNodes[i] = node;
            xmssSig.auth[i] = random();
            node = randHash(node,xmssSig.auth[i], adrs);
            adrs.setTreeHeight(uint32(adrs.getTreeHeight())+1);
        }
        htAdditionalNodes[h] = node;
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

function concatenateBytes32Arrays(bytes32[][5] memory arrays) public pure returns (bytes32[] memory) {
        // Calculate the total length of the resulting bytes32 array
        uint256 totalLength = 0;
        for (uint256 i = 0; i < arrays.length; i++) {
            totalLength += arrays[i].length;
        }

        // Create a new bytes32 array to hold the concatenated result
        bytes32[] memory result = new bytes32[](totalLength);

        // Copy elements from input arrays to the result array
        uint256 currentIndex = 0;
        for (uint256 i = 0; i < arrays.length; i++) {
            bytes32[] memory currentArray = arrays[i];
            for (uint256 j = 0; j < currentArray.length; j++) {
                result[currentIndex] = currentArray[j];
                currentIndex++;
            }
        }

        return result;
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

    function PRF(ADRS adrs) public view returns(bytes32){
        return keccak256(abi.encodePacked(seed,adrs.toBytes()));
    }
}


