// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";

contract ADRS {
    bytes4 public layerAddress;
    bytes8 public treeAddress;
    bytes4 public adrsType;

    bytes4 public firstWord;
    bytes4 public secondWord;
    bytes4 public thirdWord;

    constructor() {
        layerAddress = bytes4(0);
        treeAddress = bytes8(0);
        adrsType = bytes4(0);

        firstWord = bytes4(0);
        secondWord = bytes4(0);
        thirdWord = bytes4(0);
    }

    function toBytes()public returns (bytes memory){
        return abi.encodePacked(layerAddress,treeAddress,adrsType,firstWord,secondWord,thirdWord);
    }

    function fillFrom(ADRS adrs)public{
        layerAddress = adrs.getLayerAddress();
        treeAddress = adrs.getTreeAddress();
        adrsType = adrs.getType();

        firstWord = adrs.getKeyPairAddress(); //first word
        secondWord = adrs.getChainAddress(); //second word
        thirdWord = adrs.getTreeIndex(); //third word
    }

    function setType(uint32 typeValue) public {
        adrsType = bytes4(typeValue);
        firstWord = bytes4(0);
        secondWord = bytes4(0);
        thirdWord = bytes4(0);
    }

    function getType()public returns(bytes4){
        return adrsType;
    }

    function setLayerAddress(bytes4 a) public{
        layerAddress = a;
    }
    function getLayerAddress() public view returns(bytes4){
        return layerAddress;
    }

    function setTreeAddress(bytes8 a) public{
        treeAddress = a;
    }
    function getTreeAddress() public view returns(bytes8){
        return treeAddress;
    }

    function setKeyPairAddress(bytes4 a) public{
        firstWord = a;
    }
    function getKeyPairAddress() public view returns(bytes4){
        return firstWord;
    }

    function setChainAddress(bytes4 a) public{
        secondWord = a;
    }
    function getChainAddress() public view returns(bytes4){
        return secondWord;
    }

    function setHashAddress(bytes4 a) public{
        thirdWord = a;
    }
    function getHashAddress() public view returns(bytes4){
        return thirdWord;
    }

    function setTreeHeight(bytes4 a) public{
        secondWord = a;
    }
    function getTreeHeight() public view returns(bytes4){
        return secondWord;
    }

    function setTreeIndex(bytes4 a) public{
        thirdWord = a;
    }
    function getTreeIndex() public view returns(bytes4){
        return thirdWord;
    }
}


contract SphincsPlus{
    uint n;
    uint w;
    uint h;
    uint d;
    uint k;
    uint a;
    uint t;
    uint len1;
    uint len2;
    uint len;


    uint32 WOTSHASH = 0;
    uint32 WOTSPK = 1;
    uint32 TREE = 2;
    uint32 FORSTREE = 3;
    uint32 FORSROOT = 4;
    uint32 WOTSPRF = 5;
    uint32 FORSPRF = 6;

    // Struct to represent the public key
    struct SphincsPk {
        bytes32 seed;
        bytes32 root;
    }

    struct XmssSig{
        bytes32[] sig;
        bytes32[] auth;
    }

    struct HtSig{
        XmssSig[] sig;
    }

    struct ForsSigInner{
        bytes32 sk;
        bytes32[] auth;
    }

    struct ForsSig{
        ForsSigInner[] sig;
    }

    struct SphincsSig{
        bytes32 r;
        ForsSig forsSig;
        HtSig htSig;
    }

    SphincsPk pk;
    function setPk(SphincsPk memory p) public {
        pk = p;
    }

     function setParams(
        uint _n,
        uint _w,
        uint _h,
        uint _d,
        uint _k,
        uint _a,
        uint _t
    ) public {
        n = _n;
        w = _w;
        h = _h;
        d = _d;
        k = _k;
        a = _a;
        t = _t;

        len1 = (n) / log2(w) + ((n) % log2(w) == 0 ? 0 : 1);
        len2 = (log2(len1 * (w - 1)) / log2(w)) + 1;
        len = len1 + len2;

    }

    function chain(bytes32 X, uint i, uint s, bytes32 seed, ADRS adrs) public returns (bytes32) {
        // Return X if s is 0, as no transformation is needed
        if (s == 0) {
            return X;
        }

        // If the operation would exceed the limit, return 0
        if ((i + s) > (w - 1)) {
            return 0;
        }

        bytes32 tmp = X;

        // Iterate s times to perform the chaining
        for (uint j = 0; j < s; j++) {
            adrs.setHashAddress(bytes4(uint32(i + j)));
            tmp = keccak256(abi.encodePacked(seed, adrs.toBytes(), tmp));
        }

        return tmp;
    }


    function verify(bytes32 M, SphincsSig memory SIG)public returns (bool){
        ADRS adrs = new ADRS();
        bytes32 R = SIG.r;
        ForsSig memory sigFors = SIG.forsSig;
        HtSig memory sigHt = SIG.htSig;


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
        adrs.setTreeAddress(bytesToBytes4(idxTree));
        adrs.setKeyPairAddress(bytesToBytes4(idxLeaf));


        //this is checked, returns same
        bytes32 pkFors = forsPkFromSig(sigFors,md,pk.seed,adrs);
        //console.logBytes32(pkFors);

        adrs.setType(TREE);
        return htVerify(pkFors, sigHt, pk.seed, bytesToBytes8(idxTree), bytesToBytes4(idxLeaf), pk.root);
    }

    function htVerify(bytes32 M, HtSig memory sigHt, bytes32 PKseed,bytes8 idxTree, bytes4 idxLeaf,bytes32 pkHt )public returns(bool){
        ADRS adrs = new ADRS();
        XmssSig memory SigTmp = sigHt.sig[0];
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idxTree);
        bytes32 node = xmssPkFromSig(uint32(idxLeaf), SigTmp, M, PKseed, adrs);
        //console.logBytes32(node);
        uint256 idxTreeBits = h - h / d;
        uint256 idxLeafBits = h / d;
        bytes memory idxLeaf2 = abi.encodePacked(idxLeaf);
        bytes memory idxTree2 = abi.encodePacked(idxTree);
        //console.log("AAAAAAAAAAAAAAA");
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
            SigTmp = sigHt.sig[j];
            node = xmssPkFromSig(uint32(bytesToBytes4(idxLeaf2)), SigTmp, node, PKseed, adrs);
            //console.logBytes32(node);
        }
       // console.log();

        //console.logBytes32(pkHt);
        return pkHt == node;
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

    function forsPkFromSig(ForsSig memory sigFors, bytes memory M, bytes32 PKseed, ADRS adrs)public  returns (bytes32) {
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

        
    function ceil(uint a, uint b) internal pure returns (uint) {
        return (a + b - 1) / b;
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
