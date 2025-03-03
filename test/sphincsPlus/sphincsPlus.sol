pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";
import {SphincsPlus, ADRS} from "../../src/sphincsPlus/sphincsPlus.sol";


contract TestSphincsPlus is Test {
    
    // Struct to represent the secret key
    struct SphincsSk {
        bytes32 SKseed;
        bytes32 SKprf;
        bytes32 PKseed;
        bytes32 PKroot;
    }

    uint32 WOTSHASH = 0;
    uint32 WOTSPK = 1;
    uint32 TREE = 2;
    uint32 FORSTREE = 3;
    uint32 FORSROOT = 4;
    uint32 WOTSPRF = 5;
    uint32 FORSPRF = 6;


    uint n = 32; // constant
    uint m = 32; // constant
    uint w = 4;
    uint h = 3;
    uint d = 2;
    uint a = 4;
    uint k = 60;
    bytes32 M = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;
    uint t = 2 ** a;

    uint len1;
    uint len2;
    uint len;

    SphincsSk sphincsSk;
    SphincsPlus.SphincsPk sphincsPk;
    SphincsPlus.SphincsSig sphincsSig;

    SphincsPlus sph;
    function setUp()public{
        sph = new SphincsPlus();
        len1 = (n) / log2(w) + ((n) % log2(w) == 0 ? 0 : 1);
        len2 = (log2(len1 * (w - 1)) / log2(w)) + 1;
        len = len1 + len2;

        uint tmpMdSize = (k*a+7) /8;
        uint tmpIdxTreeSize = ((h+7-h/d)/8);
        uint tmpIdxLeafSize = (h/d+7)/8;

        //console.logUint(tmpMdSize);
        //console.logUint(tmpIdxTreeSize);
        //console.logUint(tmpIdxLeafSize);

        require((k*a+7)/8 + (h-h/d+7)/8 + (h/d+7)/8 == m, "message size does not match one which can be signed");
        spxKeygen();
        spxSign();
    }

    function testSphincs()public{
        sph.setParams(n, w, h, d, k, a, t);
        sph.setPk(sphincsPk);
        require(sph.verify(M, sphincsSig),"verefication failed");
    }

    function spxSign()public {
        ADRS adrs = new ADRS();
        bytes32 opt = keccak256(abi.encodePacked(block.timestamp, "opt"));
        sphincsSig.r = keccak256(abi.encodePacked(sphincsSk.SKprf,opt,M));

        //We assume M is already diggest for testing hamming weight propouses
        bytes32 digest = M;
        uint tmpMdSize = (k*a+7) /8;
        uint tmpIdxTreeSize = ((h-h/d+7)/8);
        uint tmpIdxLeafSize = (h/d+7)/8;

        bytes1[] memory tmpMd = new bytes1[](tmpMdSize);
        for (uint i=0; i < tmpMdSize; i++ ){
            tmpMd[i] = digest[i];
        }
        
        bytes1[] memory tmpIdxTree = new bytes1[](tmpIdxTreeSize);
        for (uint i=0; i < tmpIdxTreeSize; i++ ){
            tmpIdxTree[i] = digest[tmpMdSize+i];
        }

        bytes1[] memory tmpIdxLeaf = new bytes1[](tmpIdxLeafSize);
        for (uint i=0; i < tmpIdxLeafSize; i++ ){
            tmpIdxLeaf[i] = digest[tmpMdSize+tmpIdxTreeSize+i];
        }
          
 
        bytes memory  md = extractBits(abi.encodePacked(tmpMd), 0, k*a);

        // idxTree: first h - h/d bits after md
        uint256 idxTreeBits = h - h / d;
        bytes memory  idxTree = extractBits(abi.encodePacked(tmpIdxTree), 0, idxTreeBits);

        // idxLeaf: first h/d bits after idxTree
        uint256 idxLeafBits = h / d;
        bytes memory idxLeaf = extractBits(abi.encodePacked(tmpIdxLeaf), 0, idxLeafBits);
        

        adrs.setType(FORSTREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(bytesToBytes8(idxTree));
        adrs.setKeyPairAddress(bytesToBytes4(idxLeaf));
        sphincsSig.forsSig = forsSign(md, sphincsSk.SKseed, sphincsSk.PKseed, adrs);
        bytes32 pkFors = forsPkFromSig(sphincsSig.forsSig,md,sphincsSk.PKseed,adrs);

        //console.logBytes32(pkFors);
        adrs.setType(TREE);
        SphincsPlus.HtSig memory sigHt = htSign(pkFors,sphincsSk.SKseed,sphincsSk.PKseed,  uint64(bytesToBytes8(idxTree)),uint32(bytesToBytes4(idxLeaf)));
        sphincsSig.htSig = sigHt;
    }

    function htSign(bytes32 M, bytes32 SKseed, bytes32 PKseed, uint64 idxTree, uint32 idxLeaf)public returns(SphincsPlus.HtSig memory){
        SphincsPlus.HtSig memory sigHt = SphincsPlus.HtSig(new SphincsPlus.XmssSig[](d));
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(bytes8(idxTree));
        uint256 idxTreeBits = h - h / d;
        uint256 idxLeafBits = h / d;
        SphincsPlus.XmssSig memory SigTmp = xmssSign(M,SKseed,idxLeaf,PKseed,adrs);
        sigHt.sig[0] = SigTmp;
        bytes32 root = xmssPkFromSig(idxLeaf, SigTmp, M, PKseed, adrs);
        //console.logBytes32(root);
        bytes memory idxLeaf2 = abi.encodePacked(idxLeaf);
        bytes memory idxTree2 = abi.encodePacked(idxTree);
        for (uint j = 1; j < d; j++) {
            if (j == d-1){
                idxTreeBits = 0;
                idxLeaf2 = new bytes(4);
                idxTree2 = new bytes(4);
            }
            else{
                // Extract idxLeaf as the least significant (h / d) bits of idxTree
                idxLeaf2 = extractBits(idxTree2, idxTreeBits - (h / d), h / d);

                // Update idxTree to the most significant (h - (j + 1) * (h / d)) bits
                idxTreeBits -= h / d;
                
                idxTree2 = extractBits(idxTree2, 0, idxTreeBits);
            }
            adrs.setLayerAddress(bytes4(uint32(j)));
            adrs.setTreeAddress(bytesToBytes4(idxTree2));
            SigTmp = xmssSign(root, SKseed, uint32(bytesToBytes4(idxTree2)), PKseed, adrs);
            sigHt.sig[j] = SigTmp;
            root = xmssPkFromSig(uint32(bytesToBytes4(idxLeaf2)), SigTmp, root, PKseed, adrs);
            //console.logBytes32(root);

            //as key gen doies not work properly
            sphincsPk.root = root;
        }
        return sigHt;
    }

    function xmssPkFromSig(uint32 idx, SphincsPlus.XmssSig memory sigXmss, bytes32 M, bytes32 PKseed, ADRS adrs) public returns (bytes32){
    adrs.setType(WOTSHASH);
    adrs.setKeyPairAddress(bytes4(idx));
    bytes32[] memory sig = sigXmss.sig;
    bytes32[] memory AUTH = sigXmss.auth;
    bytes32[2] memory node;
    node[0] = wotsPkFromSig(sig, M, PKseed, adrs);
    adrs.setType(TREE);
    adrs.setTreeIndex(bytes4(idx));
    for (uint k = 0; k < h / d; k++ ) {
        adrs.setTreeHeight(bytes4(uint32(k+1)));
        if ((idx / (2**k)) % 2 == 0 ) {
            adrs.setTreeIndex(bytes4(uint32(adrs.getTreeIndex()) / 2));
            node[1] = keccak256(abi.encodePacked(PKseed, adrs.toBytes(), node[0] , AUTH[k]));
        } 
        else {
            adrs.setTreeIndex(bytes4((uint32(adrs.getTreeIndex()) - 1) / 2));
            node[1] = keccak256(abi.encodePacked(PKseed, adrs.toBytes(), AUTH[k], node[0]));
        }
        node[0] = node[1];
        }
    return node[0];
    }

    function wotsPkFromSig(bytes32[] memory sig, bytes32 M, bytes32 PKseed, ADRS adrs) public returns(bytes32){
        uint csum = 0;
        ADRS wotspkADRS = new ADRS();
        wotspkADRS.fillFrom(adrs);
        bytes32[] memory msg = baseW(M,len1);
        for (uint i = 0; i < len1; i++ ) {
           csum = csum + w - 1 - uint(msg[i]);
        }
        csum = csum << ( 8 - ( ( len2 * log2(w) ) % 8 ));
        uint len2Bytes = ceil( ( len2 * log2(w) ), 8 );
        bytes32[] memory msg2 = baseW(toByte(csum, len2Bytes),len2);
        bytes32[] memory tmp = new bytes32[](len);
        for (uint i = 0; i < len; i++ ) {
          adrs.setChainAddress(bytes4(uint32(i)));
          if (i < len1){
            tmp[i] = chain(sig[i], uint(msg[i]), w - 1 - uint(msg[i]),PKseed, adrs);
          }
          else{
            tmp[i] = chain(sig[i], uint(msg2[i-len1]), w - 1 - uint(msg2[i-len1]),PKseed, adrs);
          }
        }
        wotspkADRS.setType(WOTSPK);
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32 pk = keccak256(abi.encodePacked(PKseed,wotspkADRS.toBytes(),tmp));
        return pk;
    }

    function xmssSign(bytes32 M, bytes32 SKseed, uint32 idx, bytes32 PKseed, ADRS adrs)public returns(SphincsPlus.XmssSig memory){
        bytes32[] memory AUTH = new bytes32[](h/d);
        for (uint j = 0; j < h/d; j++ ) {
            uint k = 60;
            AUTH[j] = treehash(k*(2**j),j, adrs);
        }
        adrs.setType(WOTSHASH);
        adrs.setKeyPairAddress(bytes4(idx));
        bytes32[] memory sig = wotsSign(M,SKseed,PKseed,adrs);
        SphincsPlus.XmssSig memory xmssSig = SphincsPlus.XmssSig(sig,AUTH);
        return xmssSig;
    } 

    function wotsSign(bytes32 M, bytes32 SKseed, bytes32 PKseed, ADRS adrs)public returns(bytes32[] memory){
        uint csum = 0;
        bytes32[] memory msg = baseW(M, len1);
        for (uint i = 0; i < len1; i++ ) {
            csum = csum + w - 1 - uint256(msg[i]);
        }
        
        if( (log2(w) % 8) != 0) {
            csum = csum << ( 8 - ( ( len2 * log2(w) ) % 8 ));
        }
        uint len2Bytes = ceil( ( len2 * log2(w) ), 8 );
        bytes32[] memory msg2 = baseW(toByte(csum, len2Bytes), len2);
        ADRS skADRS = new ADRS();
        skADRS.fillFrom(adrs);
        skADRS.setType(WOTSPRF);
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress());

        bytes32[] memory sig = new bytes32[](len);
        for (uint i = 0; i < len; i++ ) {
            skADRS.setChainAddress(bytes4(uint32(i)));
            skADRS.setHashAddress(0);
            bytes32 sk = PRF(SKseed, skADRS);
            adrs.setChainAddress(bytes4(uint32(i)));
            adrs.setHashAddress(0);
            if (i < len1){
                sig[i] = chain(sk, 0, uint(msg[i]),PKseed, adrs);
            }
            else{
                sig[i] = chain(sk, 0, uint(msg2[i-len1]),PKseed, adrs);
            }
        }
        return sig;
    }

    function forsPkFromSig(SphincsPlus.ForsSig memory sigFors, bytes memory M, bytes32 PKseed, ADRS adrs)public  returns (bytes32) {
        bytes32[2] memory  node;
        bytes32[] memory root = new bytes32[](k);
        for(uint i = 0; i < k; i++){
            bytes memory idx = extractBits(M, i*a , (i+1)*a - i*a - 1);
            bytes32 sk = sigFors.sig[i].sk;
            adrs.setTreeHeight(0);
            adrs.setTreeIndex(bytes4(uint32(i*t + uint32(bytesToBytes4(idx)))));
            node[0] = keccak256(abi.encodePacked(PKseed, adrs.toBytes(), sk));
            bytes32[] memory auth = sigFors.sig[i].auth;

            adrs.setTreeIndex(bytes4(uint32(i*t + uint32(bytesToBytes4(idx))))); 
            for (uint j = 0; j < a; j++ ) {
                adrs.setTreeHeight(bytes4(uint32(j+1)));
                if ( ((uint32(bytesToBytes4(idx)) / (2**j)) % 2) == 0 ) {
                    adrs.setTreeIndex(bytes4(uint32(adrs.getTreeIndex()) / 2));
                    node[1] = keccak256(abi.encodePacked(PKseed, adrs.toBytes(), node[0] , auth[j]));
                } 
                else {
                    adrs.setTreeIndex(bytes4((uint32(adrs.getTreeIndex()) - 1) / 2));
                    node[1] = keccak256(abi.encodePacked(PKseed, adrs.toBytes(), auth[j], node[0]));
                }
                node[0] = node[1];
                }
            root[i] = node[0];
        }

        ADRS forspkADRS = new ADRS();
        forspkADRS.fillFrom(adrs);
        forspkADRS.setType(FORSROOT);
        forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32 pk = keccak256(abi.encodePacked(PKseed,forspkADRS.toBytes(),root));
        return pk;
    }

    function forsSign( bytes memory M, bytes32 SKseed, bytes32 PKseed, ADRS adrs) public returns (SphincsPlus.ForsSig memory){
        SphincsPlus.ForsSig memory sig = SphincsPlus.ForsSig(new SphincsPlus.ForsSigInner[](k));
        for(uint i = 0; i < k; i++){
            uint idx = bytesToUint256(extractBits(M, i*a, (i+1)*a - i*a));
            bytes32 sk = forsSkgen(SKseed, adrs, i*t + idx) ;

            bytes32[] memory auth = new bytes32[](a);
            for ( uint j = 0; j < a; j++ ) {
                uint s = (idx/ (2**j)) ^ 1;
                auth[j] = forsTreehash(SKseed, i * t + s * 2**j, j, PKseed, adrs);
            }
            sig.sig[i] = SphincsPlus.ForsSigInner(sk,auth);
        }
        return sig;
    }

    function forsTreehash(bytes32 SKseed, uint s, uint z, bytes32 PKseed, ADRS adrs)public returns (bytes32){
        require( s % (1 << z) == 0, "forsTreehash condition failed");

        //2^z not needed as we fake path
        bytes32 sk = forsSkgen(SKseed,adrs,s);
        bytes32 node = keccak256(abi.encodePacked(PKseed, adrs.toBytes(),sk));
        // fake path
        for ( uint i = 0; i < z; i++ ) {
            adrs.setTreeHeight(bytes4(uint32(i)));
            adrs.setTreeIndex(bytes4(uint32(0)));
            node = keccak256(abi.encodePacked(PKseed, adrs.toBytes(), node, bytes32(0) ));
            adrs.setTreeHeight(bytes4(uint32(adrs.getTreeHeight()) + 1));
        }
        return node;
    }

    function forsSkgen(bytes32 SKseed, ADRS adrs, uint idx)public returns (bytes32){
        ADRS skADRS = new ADRS();
        skADRS.fillFrom(adrs);
        skADRS.setType(FORSPRF);
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        skADRS.setTreeHeight(0);
        skADRS.setTreeIndex(bytes4(uint32(idx)));

        return PRF(SKseed,skADRS);
    }

    function spxKeygen()public{
        sphincsSk.SKseed = keccak256(abi.encodePacked(block.timestamp, "SKseed"));
        sphincsSk.SKprf = keccak256(abi.encodePacked(block.timestamp, "SKprf"));

        sphincsPk.seed =  keccak256(abi.encodePacked(block.timestamp, "PKseed"));

        // key gen does not work properly because of faking
        sphincsPk.root = htPkGen();

        sphincsSk.PKseed = sphincsPk.seed;
        sphincsSk.PKroot =  sphincsPk.root;
    }

    function htPkGen() public returns (bytes32) {
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(bytes4(uint32(d-1)));
        adrs.setTreeAddress(0);
        return  xmssPkgen(adrs);
    }

    function xmssPkgen(ADRS adrs) public returns(bytes32){
        return treehash(0,h/d,adrs);
    }

    function treehash(uint s, uint z, ADRS adrs) public returns(bytes32){
        adrs.setType(WOTSHASH);   // Type = OTS hash address
        adrs.setKeyPairAddress(bytes4(uint32(s)));
        bytes32 node = wotsPkgen(adrs); 
        adrs.setType(TREE);
        adrs.setTreeHeight(bytes4(uint32(1)));
        adrs.setTreeIndex(bytes4(uint32(s)));
        bytes32[] memory auth = new bytes32[](h);

        //fake auth path
        for (uint i =0; i < (h); i++){
            if (uint32(adrs.getTreeIndex()) > 0){
                adrs.setTreeIndex(bytes4((uint32(adrs.getTreeIndex()) - 1) / 2));
            }
            
            //auth[i] = keccak256(abi.encodePacked(block.timestamp,h));
            node = keccak256(abi.encodePacked(sphincsPk.seed ,adrs.toBytes(),node,bytes32(0)));
            adrs.setTreeHeight(bytes4(uint32(adrs.getTreeHeight())+1));
        }
        return node;
    }


    function wotsPkgen(ADRS adrs)public returns (bytes32){
        ADRS wotspkADRS = new ADRS();
        wotspkADRS.fillFrom(adrs);
        ADRS skADRS = new ADRS();
        skADRS.fillFrom(adrs);
        skADRS.setType(WOTSPRF);
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32[] memory sk = new bytes32[](len);
        bytes32[] memory tmp = new bytes32[](len);
        for (uint32 i = 0; i < len; i++ ) {
            skADRS.setChainAddress(bytes4(i));
            skADRS.setHashAddress(0);
            sk[i] = PRF(sphincsSk.SKseed, skADRS);
            adrs.setChainAddress(bytes4(i));
            adrs.setHashAddress(0);
            tmp[i] = chain(sk[i], 0, w - 1,  sphincsPk.seed, adrs);
        }
        wotspkADRS.setType(WOTSPK);
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());

        return keccak256(abi.encodePacked(sphincsPk.seed,wotspkADRS.toBytes(), tmp));
    }


    function chain(bytes32 X, uint i, uint s,bytes32 seed, ADRS adrs) public returns (bytes32) {
        if ( s == 0 ) {
            return X;
        }
        if ( (i + s) > (w - 1) ) {
            return 0;
        }
        bytes32 tmp = chain(X, i, s - 1, seed, adrs);
        adrs.setHashAddress(bytes4(uint32(i + s - 1)));
        tmp = keccak256(abi.encodePacked(seed, adrs.toBytes(), tmp));
        return tmp;
    }

    function PRF(bytes32 seed, ADRS adrs) public returns(bytes32){
        return keccak256(abi.encodePacked(seed,adrs.toBytes()));
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

    function extractBits(bytes memory data, uint startBit, uint numBits) internal pure returns (bytes memory) {
        uint startByte = startBit / 8;
        uint endBit = startBit + numBits - 1;
        uint endByte = endBit / 8;
        uint byteLength = endByte - startByte + 1;

        bytes memory result = new bytes(byteLength);
        uint resultBitIndex = 0;

        for (uint i = 0; i < byteLength; i++) {
            uint8 currentByte = uint8(data[startByte + i]);

            for (uint bit = 0; bit < 8; bit++) {
                if (resultBitIndex >= numBits) break;

                uint bitPosition = startBit + resultBitIndex;
                bool bitValue = (currentByte & (0x80 >> bit)) != 0;

                uint resultByteIndex = resultBitIndex / 8;
                uint resultBitInByte = resultBitIndex % 8;

                if (bitValue) {
                    result[resultByteIndex] = bytes1(uint8(result[resultByteIndex]) | uint8(0x80 >> resultBitInByte));
                }

                resultBitIndex++;
            }
        }

        return result;
    }

    function bytesToBytes4(bytes memory b) public pure returns (bytes4) {
       // require(b.length <= 4, "Bytes array too long to convert to bytes4");
        bytes4 out;
        if (b.length == 0) {
            return out; // return 0x00000000 if the array is empty
        }
        assembly {
            out := mload(add(b, 32))
        }
        // If the input is shorter than 4 bytes, shift it to the right
        if (b.length < 4){
            return bytes4(uint32(out) << (8 * (4 - b.length)));
        }
        return out;
  
    }


    function bytesToBytes8(bytes memory b) public pure returns (bytes8) {
        require(b.length <= 8, "Bytes array too long to convert to bytes8");
        bytes8 out;
        if (b.length == 0) {
            return out; // return 0x0000000000000000 if the array is empty
        }
        assembly {
            out := mload(add(b, 32))
        }
        // If the input is shorter than 8 bytes, shift it to the right
        return bytes8(uint64(out) << (8 * (8 - b.length)));
    }

    function bytesToUint256(bytes memory b) public pure returns (uint256) {
        require(b.length <= 32, "Bytes array too long to convert to uint256");
        uint256 out;
        if (b.length == 0) {
            return out; // return 0 if the array is empty
        }
        assembly {
            out := mload(add(b, 32))
        }
        // If the input is shorter than 32 bytes, shift it to the right
        return out >> (8 * (32 - b.length));
    }

    function toByte(uint256 x, uint y) public pure returns (bytes memory) {
        bytes memory b = new bytes(y);
        for (uint i = 0; i < y; i++) {
            b[i] = bytes1(uint8(x >> (8 * (y - 1 - i))));
        }
        return b;
    }

    
    function ceil(uint a, uint b) internal pure returns (uint) {
        return (a + b - 1) / b;
    }


}