// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";
import "../merkleTree.sol";

contract ADRS {
    bytes4 public layerAddress;
    bytes8 public treeAddress;
    bytes4 public adrsType;

    bytes4 public firstWord;
    bytes4 public secondWord;
    bytes4 public thirdWord;

    bytes4 public keyAndMask;

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

    function getType()public view returns(bytes4){
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


contract SphincsPlusNaysayer is MerkleTree{
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
    uint32 FORSROOTS = 4;
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


    bytes32 sig;
    bytes32 M;

    function setSign(bytes32 _sig, bytes32 _M) public {
        sig = _sig;
        M = _M;
    }

    //default offset = 1 as we store r in signature
    //forsSigs amount = k;
    //fors sig len = 3;

    //xmss sig len = len
    //xmss auth len = h/d
    //wots pk len = len 
    //xmss additional nodes = h/d+1;
    //xmss additional words = 1;
    //xmss total length = d+h/d+len+h/d+1+1 = d+len+2*h/d+2;
    function WotsHashNaysayer(
        uint treeIndex,
        bytes32[] memory wotsPk,
        bytes32[][] memory wotsPkProof,
        bytes32 hashed,
        bytes32[] memory hashedProof,
        bytes32 M2,
        bytes32[] memory mProof
    ) public returns (bool){
        uint xmssFInd = 1 + 3 * k + 1;
        uint xmssLen = 1 + h / d + len + len + h / d + 1;
        for (uint i =0; i < wotsPk.length;i++){
            if (!verifyProof(sig, wotsPk[i], wotsPkProof[i], xmssFInd+xmssLen*treeIndex+1+h/d+len+i)){
                return false;
            }
        }

        if (!verifyProof(sig, hashed, hashedProof, xmssFInd+xmssLen*treeIndex)){
            return false;
        }

        if (treeIndex == 0) {
            if (!verifyProof(sig, M2, mProof,xmssFInd+xmssLen*d )){
                return false;
            }
        } else if (!verifyProof(sig, M2, mProof, xmssFInd + xmssLen * treeIndex - 1)) {
            return false;
        }


        uint tmpMdSize = (k * a + 7) / 8;
        uint tmpIdxTreeSize = ((h - h / d + 7) / 8);
        uint tmpIdxLeafSize = (h / d + 7) / 8;

        // Processing digest
        bytes1[] memory tmpMd = new bytes1[](tmpMdSize);
        for (uint i = 0; i < tmpMdSize; i++) {
            tmpMd[i] = M2[i];
        }

        bytes1[] memory tmpIdxTree = new bytes1[](tmpIdxTreeSize);
        for (uint i = 0; i < tmpIdxTreeSize; i++) {
            tmpIdxTree[i] = M2[tmpMdSize + i];
        }

        bytes1[] memory tmpIdxLeaf = new bytes1[](tmpIdxLeafSize);
        for (uint i = 0; i < tmpIdxLeafSize; i++) {
            tmpIdxLeaf[i] = M2[tmpMdSize + tmpIdxTreeSize + i];
        }

  
        bytes memory md;
        bytes memory idxLeaf2;
        bytes memory idxTree2;
        ADRS adrs = new ADRS();

        {
            bytes memory idxLeaf;
            bytes memory idxTree;
            md = extractBits(abi.encodePacked(tmpMd), 0, k * a);
            uint256 idxTreeBits = h - h / d;
            idxTree = extractBits(abi.encodePacked(tmpIdxTree), 0, idxTreeBits);
            uint256 idxLeafBits = h / d;
            idxLeaf = extractBits(abi.encodePacked(tmpIdxLeaf), 0, idxLeafBits);


            bytes memory idxLeaf2 = abi.encodePacked(idxLeaf);
            bytes memory idxTree2 = abi.encodePacked(idxTree);

            for (uint j = 1; j < treeIndex; j++) {
                if (j == d - 1) {
                    idxTreeBits = 0;
                    idxLeaf2 = new bytes(4);
                    idxTree2 = new bytes(4);
                } else {
                    idxLeaf2 = extractBits(idxTree2, idxTreeBits - (h / d), h / d);
                    idxTreeBits -= h / d;
                    idxTree2 = extractBits(idxTree2, 0, idxTreeBits);
                }
            }
        }

        uint32 idx = uint32(bytesToBytes4(idxLeaf2));
        adrs.setType(WOTSHASH);
        adrs.setKeyPairAddress(bytes4(idx));
        adrs.setLayerAddress(bytes4(uint32(treeIndex)));
        adrs.setChainAddress(bytes4(uint32(len-1)));

        ADRS wotspkADRS = new ADRS();
        wotspkADRS.fillFrom(adrs);

        wotspkADRS.setType(WOTSPK);
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32 pk = keccak256(abi.encodePacked(pk.seed,wotspkADRS.toBytes(),wotsPk));
        return pk !=hashed;
    }

   
    function wotsNaysayer(
        uint treeIndex,
        uint wotsSigInd,
        bytes32 M2,
        bytes32[] memory mProof,
        bytes32 wotsPkElem,
        bytes32[] memory wotsPkProof,
        bytes32 wotsSigElem,
        bytes32[] memory wotsSigProof
    ) public returns (bool) {

        // Memory variables to avoid stack depth issues
        {
            uint xmssFInd = 1 + 3 * k + 1;
            uint xmssLen = 1 + h / d + len + len + h / d + 1;

            if (treeIndex == 0) {
                if (!verifyProof(sig, M2, mProof,xmssFInd+xmssLen*d )){
                    return false;
                }
            } else if (!verifyProof(sig, M2, mProof, xmssFInd + xmssLen * treeIndex - 1)) {
                return false;
            }

            uint wotsPkElemInd = xmssFInd + xmssLen * treeIndex + 1 + h / d + len + wotsSigInd;
            if (!verifyProof(sig, wotsPkElem, wotsPkProof, wotsPkElemInd)) {
                return false;
            }

            uint wotsSigElemInd = xmssFInd + xmssLen * treeIndex + 1 + h / d + wotsSigInd;
            if (!verifyProof(sig, wotsSigElem, wotsSigProof, wotsSigElemInd)) {
                return false;
            }
        }

        uint tmpMdSize = (k * a + 7) / 8;
        uint tmpIdxTreeSize = ((h - h / d + 7) / 8);
        uint tmpIdxLeafSize = (h / d + 7) / 8;

        // Processing digest
        bytes1[] memory tmpMd = new bytes1[](tmpMdSize);
        for (uint i = 0; i < tmpMdSize; i++) {
            tmpMd[i] = M2[i];
        }

        bytes1[] memory tmpIdxTree = new bytes1[](tmpIdxTreeSize);
        for (uint i = 0; i < tmpIdxTreeSize; i++) {
            tmpIdxTree[i] = M2[tmpMdSize + i];
        }

        bytes1[] memory tmpIdxLeaf = new bytes1[](tmpIdxLeafSize);
        for (uint i = 0; i < tmpIdxLeafSize; i++) {
            tmpIdxLeaf[i] = M2[tmpMdSize + tmpIdxTreeSize + i];
        }

  
        bytes memory md;
        bytes memory idxLeaf2;
        bytes memory idxTree2;
        ADRS adrs = new ADRS();

        {
            bytes memory idxLeaf;
            bytes memory idxTree;
            md = extractBits(abi.encodePacked(tmpMd), 0, k * a);
            uint256 idxTreeBits = h - h / d;
            idxTree = extractBits(abi.encodePacked(tmpIdxTree), 0, idxTreeBits);
            uint256 idxLeafBits = h / d;
            idxLeaf = extractBits(abi.encodePacked(tmpIdxLeaf), 0, idxLeafBits);


            bytes memory idxLeaf2 = abi.encodePacked(idxLeaf);
            bytes memory idxTree2 = abi.encodePacked(idxTree);

            for (uint j = 1; j < treeIndex; j++) {
                if (j == d - 1) {
                    idxTreeBits = 0;
                    idxLeaf2 = new bytes(4);
                    idxTree2 = new bytes(4);
                } else {
                    idxLeaf2 = extractBits(idxTree2, idxTreeBits - (h / d), h / d);
                    idxTreeBits -= h / d;
                    idxTree2 = extractBits(idxTree2, 0, idxTreeBits);
                }
            }
        }

        uint32 idx = uint32(bytesToBytes4(idxLeaf2));
        adrs.setType(WOTSHASH);
        adrs.setKeyPairAddress(bytes4(idx));
        adrs.setLayerAddress(bytes4(uint32(treeIndex)));
        bytes32 node;
        {
            uint csum = 0;
            ADRS wotspkADRS = new ADRS();
            wotspkADRS.fillFrom(adrs);

            bytes32[] memory msg = baseW(M2, len1);
            for (uint i = 0; i < len1; i++) {
                csum += w - 1 - uint(msg[i]);
            }

            csum <<= (8 - ((len2 * log2(w)) % 8));
            uint len2Bytes = ceil((len2 * log2(w)), 8);
            bytes32[] memory msg2 = baseW(toByte(csum, len2Bytes), len2);

            adrs.setChainAddress(bytes4(uint32(wotsSigInd)));

           
            if (wotsSigInd < len1) {
                uint tempp = uint(msg[wotsSigInd]);
                uint tmp2 = w - 1 - tempp;
                node = chain(wotsSigElem, tempp, tmp2, pk.seed, adrs);
            } else {
                uint tempp = uint(msg2[wotsSigInd - len1]);
                uint tmp2 = w - 1 - tempp;
                node = chain(wotsSigElem, tempp, tmp2, pk.seed, adrs);
            }
        }

        //return false; // Or return the actual result based on your logic
        return node != wotsPkElem;
    }




    function xmssNaysayer(
        uint treeInd, 
        uint topNodeInd, 
        bytes32 topNode, 
        bytes32[] memory topNodeProof,  
        bytes32 bottomNode, 
        bytes32[] memory bottomNodeProof,
        bytes32 authNode, 
        bytes32[] memory authNodeProof 
    ) public returns (bool) {
        //required because compiler crashes trying to inline it
        uint xmssFInd = 1 + 3 * k+1;
        uint xmssLen =  1+h/d + len+len+h/d+1;
        uint baseIndex = xmssFInd + xmssLen * treeInd +  1+h/d + len+len;

        // Split the complex expressions into intermediate variables
        uint topNodeIndex = baseIndex + topNodeInd;
        uint bottomNodeIndex = baseIndex + topNodeInd - 1;
        uint authNodeIndex = xmssFInd + xmssLen * treeInd + 1 + topNodeInd - 1;

        // Verify each proof separately and return false early if any fails
        if (!verifyProof(sig, topNode, topNodeProof, topNodeIndex)) {
            return false;
        }

        if (!verifyProof(sig, bottomNode, bottomNodeProof, bottomNodeIndex)) {
            return false;
        }

        if (!verifyProof(sig, authNode, authNodeProof, authNodeIndex)) {
            return false;
        }


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

        bytes memory idxLeaf2 = abi.encodePacked(idxLeaf);
        bytes memory idxTree2 = abi.encodePacked(idxTree);
        ADRS adrs = new ADRS();
        for (uint j = 1; j < treeInd; j++) {
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
        }
        uint32 idx = uint32(bytesToBytes4(idxLeaf2));
        adrs.setType(TREE);
        adrs.setTreeIndex(bytes4(idx));
        adrs.setLayerAddress(bytes4(uint32(treeInd)));
        //console.logBytes(adrs.toBytes());
         for (uint k = 0; k < topNodeInd; k++ ) {
           
            if ((idx / (2**k)) % 2 == 0 ) {
                adrs.setTreeIndex(bytes4(uint32(adrs.getTreeIndex()) / 2));
            }
            else {  
                adrs.setTreeIndex(bytes4((uint32(adrs.getTreeIndex()) - 1) / 2));
            }
            //console.logBytes(adrs.toBytes());
        }
        bytes32 node;
        adrs.setTreeHeight(bytes4(uint32(topNodeInd)));
        if ((idx / (2**topNodeInd)) % 2 == 0 ) {
            adrs.setTreeIndex(bytes4(uint32(adrs.getTreeIndex()) / 2));
            node = keccak256(abi.encodePacked(pk.seed, adrs.toBytes(), bottomNode , authNode));
        } 
        else {
            adrs.setTreeIndex(bytes4((uint32(adrs.getTreeIndex()) - 1) / 2));
            node = keccak256(abi.encodePacked(pk.seed, adrs.toBytes(), authNode, bottomNode));
        }
       // console.logBytes(adrs.toBytes());

        return node !=topNode;
    }




    function naysayerFors( uint forsInd, bytes32 forsSk,bytes32[] memory forsSkProof, bytes32[] memory forsProof, bytes32[] memory forsProofProof, bytes32 forsRoot, bytes32[] memory forsRootProof) public returns(bool){
        if (!verifyProof(sig, forsSk, forsSkProof, 1+forsInd*3) || !verifyProof(sig, keccak256(abi.encodePacked(forsProof)), forsProofProof, 1+forsInd*3+1) || !verifyProof(sig,forsRoot,forsRootProof,1+forsInd*3+2)){
            return false;
        }
        ADRS adrs = new ADRS();

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

        //FORS 
        bytes32[2] memory node;


        uint i = forsInd;
        bytes32 sk = forsSk;

        bytes memory idx = extractBits(abi.encodePacked(md), i*a , (i+1)*a - i*a - 1);
        adrs.setTreeHeight(0);
        //console.logBytes(idx);
        adrs.setTreeIndex(bytes4(uint32(i*t + uint32(bytesToBytes4(idx)))));


        node[0] = keccak256(abi.encodePacked(pk.seed, adrs.toBytes(), sk));
        //console.logBytes32(node[0]);

        bytes32[] memory auth = forsProof;
        adrs.setTreeIndex(bytes4(uint32(i*t + uint32(bytesToBytes4(idx))))); 
        for (uint j = 0; j < a; j++ ) {
            adrs.setTreeHeight(bytes4(uint32(j+1)));
            if ( ((uint32(bytesToBytes4(idx)) / (2**j)) % 2) == 0 ) {
                adrs.setTreeIndex(bytes4(uint32(adrs.getTreeIndex()) / 2));
                node[1] = keccak256(abi.encodePacked(pk.seed, adrs.toBytes(), node[0] , auth[j]));
            } 
            else {
                adrs.setTreeIndex(bytes4((uint32(adrs.getTreeIndex()) - 1) / 2));
                node[1] = keccak256(abi.encodePacked(pk.seed, adrs.toBytes(), auth[j], node[0]));
            }
            node[0] = node[1];
        }
        //console.logBytes32(node[0]);
        //console.logBytes32(forsRoot);
        return node[0] != forsRoot;
    }

    //offset fors =  1+3*k+1



    function naysayerForsHash(bytes32[] memory roots, bytes32[][] memory proofs, bytes32 hashed, bytes32[] memory hashedProof) public returns (bool){
        for (uint i =0; i < k; i++){
            if (!verifyProof(sig, roots[i], proofs[i], 1+3*i+2)){
                return false;
            }
        }
        if (!verifyProof(sig, hashed, hashedProof, 1+3*k)){
            return false;
        }

        ADRS adrs = new ADRS();
    



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

        ADRS forspkADRS = new ADRS();
        forspkADRS.setType(FORSROOTS);
        forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        //console.logBytes32(hashed);
        bytes32 pk = keccak256(abi.encodePacked(pk.seed,forspkADRS.toBytes(),roots));
        return pk !=hashed;
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

        
    function toByte(uint256 x, uint y) public pure returns (bytes memory) {
        bytes memory b = new bytes(y);
        for (uint i = 0; i < y; i++) {
            b[i] = bytes1(uint8(x >> (8 * (y - 1 - i))));
        }
        return b;
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


    function ceil(uint a, uint b) internal pure returns (uint) {
        return (a + b - 1) / b;
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