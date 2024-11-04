pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";
import {SphincsPlusNaysayer, ADRS,MerkleTree} from "../../src/sphincs_naysayer/sphincs_naysayer.sol";


contract TestSphincsPlusNaysayer is Test {

    struct NaysayerXmssSig{
        bytes32 wotsPkHash;
        bytes32[] xmssAuth;
        bytes32[] sig;
        bytes32[] wotsPk;
        bytes32[] htAdditionalNodes;
    }

    struct NaysayerForsSigInner{
        bytes32 sk;
        bytes32 authHash;
        bytes32 root;
    }

    struct NaysayerForsSig{
        NaysayerForsSigInner[] sig;
        bytes32 hashedRoot;
    }

    struct NaysayerSphincsSig{
        bytes32 r;
        NaysayerForsSig forsSig;
        NaysayerXmssSig[] sig;
        bytes32 forsPk;
    }

    bytes32[][] naysayerforsProofs;

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
    uint32 FORSROOTS = 4;
    uint32 WOTSPRF = 5;
    uint32 FORSPRF = 6;

    uint n = 32; // constant
    uint m = 32; // constant
    uint w = 16;
    uint h = 3;
    uint d = 2;
    uint a = 5;
    uint k = 47;
    bytes32 M = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;
    uint t = 2 ** a;

    uint len1;
    uint len2;
    uint len;

    SphincsSk sphincsSk;
    SphincsPlusNaysayer.SphincsPk sphincsPk;
    SphincsPlusNaysayer.SphincsSig sphincsSig;
    MerkleTree mt;


    NaysayerSphincsSig naysayerSig;

    SphincsPlusNaysayer sph;
    function setUp()public{
        mt = new MerkleTree();
        sph = new SphincsPlusNaysayer();
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
        verifyPartsAssign(M,sphincsSig);
    }


    function testSphincsWotshash() public {
        sph.setParams(n, w, h, d, k, a, t);
        sph.setPk(sphincsPk);
        bytes32[] memory sigma = flattenSPHINCS(naysayerSig);
        uint xmssFInd = 1 + 3 * k+1;
        uint xmssLen = 1+h/d + len+len+h/d+1;
        {
            sph.setSign(mt.buildRoot(sigma),M);
            uint treeInd = 1;
            bytes32[][] memory tree = mt.buildTree(sigma);
            bytes32[][] memory proofs = new bytes32[][](len);
            for (uint i =0 ; i < len; i++){
                proofs[i] = mt.getProof(tree,xmssFInd+treeInd* xmssLen + 1+h/d+len+i);
            }


            bytes32[] memory proof2 = mt.getProof(tree,xmssFInd+treeInd* xmssLen);
            uint mInd = xmssFInd+xmssLen*treeInd-1;
            bytes32 m = naysayerSig.sig[treeInd-1].htAdditionalNodes[h/d];
            bytes32[] memory mProof =  mt.getProof(tree,mInd);

            //check proofs
            //require(sph.WotsHashNaysayer(treeInd,naysayerSig.sig[treeInd].wotsPk,proofs,naysayerSig.sig[treeInd].wotsPkHash,proof2,m,mProof),"failed good proof");
            //require(sph.WotsHashNaysayer(treeInd,naysayerSig.sig[treeInd-1].wotsPk,proofs,naysayerSig.sig[treeInd].wotsPkHash,proof2,m,mProof) == false,"passed bad proof");
        
            require(sph.WotsHashNaysayer(treeInd,naysayerSig.sig[treeInd].wotsPk,proofs,naysayerSig.sig[treeInd].wotsPkHash,proof2,m,mProof)==false,"passed proof without mistake");
        }
        {
         
            uint treeInd = 1;
            naysayerSig.sig[treeInd].wotsPk[0] = naysayerSig.sig[treeInd].wotsPk[0] ^ bytes32(uint(1));

            sigma = flattenSPHINCS(naysayerSig);
            bytes32[][] memory tree = mt.buildTree(sigma);

            sph.setSign(mt.buildRoot(sigma),M);

            bytes32[][] memory proofs = new bytes32[][](len);
            for (uint i =0 ; i < len; i++){
                proofs[i] = mt.getProof(tree,xmssFInd+treeInd* xmssLen + 1+h/d+len+i);
            }

            bytes32[] memory proof2 = mt.getProof(tree,xmssFInd+treeInd* xmssLen);

            uint mInd = xmssFInd+xmssLen*treeInd-1;
            bytes32 m = naysayerSig.sig[treeInd-1].htAdditionalNodes[h/d];
            bytes32[] memory mProof =  mt.getProof(tree,mInd);

            //check proofs
            //require(sph.WotsHashNaysayer(treeInd,naysayerSig.sig[treeInd].wotsPk,proofs,naysayerSig.sig[treeInd].wotsPkHash,proof2,m,mProof),"failed good proof");
            //require(sph.WotsHashNaysayer(treeInd,naysayerSig.sig[treeInd-1].wotsPk,proofs,naysayerSig.sig[treeInd].wotsPkHash,proof2,m,mProof) == false,"passed bad proof");
        
            require(sph.WotsHashNaysayer(treeInd,naysayerSig.sig[treeInd].wotsPk,proofs,naysayerSig.sig[treeInd].wotsPkHash,proof2,m,mProof)==true,"failed proof with mistake");
            naysayerSig.sig[treeInd].wotsPk[0] = naysayerSig.sig[treeInd].wotsPk[0] ^ bytes32(uint(1));
        }

    }


    function testSphincsWots() public{
        sph.setParams(n, w, h, d, k, a, t);
        sph.setPk(sphincsPk);
        bytes32[] memory sigma = flattenSPHINCS(naysayerSig);
        uint xmssFInd = 1 + 3 * k+1;
        uint xmssLen = 1+h/d + len+len+h/d+1;
        {
            sph.setSign(mt.buildRoot(sigma),M);

            uint treeIndex = 1;
            uint wotsSigInd = 2;
            bytes32[][] memory tree = mt.buildTree(sigma);
            uint wotsPkElemInd = xmssFInd+xmssLen*treeIndex+1+h/d+len+wotsSigInd;
            uint wotsSigElemInd = xmssFInd+xmssLen*treeIndex+1+h/d + wotsSigInd;
            uint mInd = xmssFInd+xmssLen*treeIndex-1;
            bytes32 m = naysayerSig.sig[treeIndex-1].htAdditionalNodes[h/d];
            bytes32 wotsPkElem = naysayerSig.sig[treeIndex].wotsPk[wotsSigInd];
            bytes32 wotsSigElem = naysayerSig.sig[treeIndex].sig[wotsSigInd];

            bytes32[] memory mProof =  mt.getProof(tree,mInd);
            bytes32[] memory wotsPkProof =  mt.getProof(tree,wotsPkElemInd);
            bytes32[] memory wotsSigElemProof =  mt.getProof(tree,wotsSigElemInd);

            //check auth path works
            //require (sph.wotsNaysayer(treeIndex, wotsSigInd, m, mProof, wotsPkElem, wotsPkProof,wotsSigElem,wotsSigElemProof),"failed good auth path");
            //require (sph.wotsNaysayer(treeIndex+1, wotsSigInd, m, mProof, wotsPkElem, wotsPkProof,wotsSigElem,wotsSigElemProof) == false,"passed bad auth path");

            require (sph.wotsNaysayer(treeIndex, wotsSigInd, m, mProof, wotsPkElem, wotsPkProof,wotsSigElem,wotsSigElemProof) == false,"passed with no actual error");
        }
        {
            uint treeIndex = 1;
            uint wotsSigInd = 2;
            naysayerSig.sig[treeIndex].wotsPk[wotsSigInd] = naysayerSig.sig[treeIndex].wotsPk[wotsSigInd] ^ bytes32(uint(1));
            sigma = flattenSPHINCS(naysayerSig);
            sph.setSign(mt.buildRoot(sigma),M);
            bytes32[][] memory tree = mt.buildTree(sigma);
            uint wotsPkElemInd = xmssFInd+xmssLen*treeIndex+1+h/d+len+wotsSigInd;
            uint wotsSigElemInd = xmssFInd+xmssLen*treeIndex+1+h/d + wotsSigInd;
            uint mInd = xmssFInd+xmssLen*treeIndex-1;
            bytes32 m = naysayerSig.sig[treeIndex-1].htAdditionalNodes[h/d];
            bytes32 wotsPkElem = naysayerSig.sig[treeIndex].wotsPk[wotsSigInd];
            bytes32 wotsSigElem = naysayerSig.sig[treeIndex].sig[wotsSigInd];

            bytes32[] memory mProof =  mt.getProof(tree,mInd);
            bytes32[] memory wotsPkProof =  mt.getProof(tree,wotsPkElemInd);
            bytes32[] memory wotsSigElemProof =  mt.getProof(tree,wotsSigElemInd);

            //check auth path works
            //require (sph.wotsNaysayer(treeIndex, wotsSigInd, m, mProof, wotsPkElem, wotsPkProof,wotsSigElem,wotsSigElemProof),"failed good auth path");
            //require (sph.wotsNaysayer(treeIndex+1, wotsSigInd, m, mProof, wotsPkElem, wotsPkProof,wotsSigElem,wotsSigElemProof) == false,"passed bad auth path");

            require (sph.wotsNaysayer(treeIndex, wotsSigInd, m, mProof, wotsPkElem, wotsPkProof,wotsSigElem,wotsSigElemProof) == true,"failed with actual proof");
            naysayerSig.sig[treeIndex].wotsPk[wotsSigInd] = naysayerSig.sig[treeIndex].wotsPk[wotsSigInd] ^ bytes32(uint(1));
        }
    }

    function testSphincsXmss()public{
        sph.setParams(n, w, h, d, k, a, t);
        sph.setPk(sphincsPk);
        bytes32[] memory sigma = flattenSPHINCS(naysayerSig);
        uint xmssFInd = 1 + 3 * k+1;
        uint xmssLen = 1+h/d + len+len+h/d+1;
        uint treeInd = 0;
        uint topInd = 1;
        {
            sph.setSign(mt.buildRoot(sigma),M);
            bytes32[][] memory tree = mt.buildTree(sigma);
            uint baseIndex = xmssFInd + xmssLen * treeInd +  1+h/d + len+len;


            bytes32[] memory proof = mt.getProof(tree,baseIndex+topInd);
            bytes32[] memory proof2 = mt.getProof(tree,baseIndex+topInd-1);
            bytes32[] memory proof3 = mt.getProof(tree,xmssFInd + xmssLen * treeInd + 1 + topInd - 1);

            bytes32 topNode = naysayerSig.sig[treeInd].htAdditionalNodes[topInd];
            bytes32 bottomNode = naysayerSig.sig[treeInd].htAdditionalNodes[topInd-1];
            bytes32 authNode = naysayerSig.sig[treeInd].xmssAuth[topInd-1];
            //test auth path
            //require(sph.xmssNaysayer(treeInd, topInd, topNode, proof, bottomNode, proof2, authNode, proof3),"failed good auth");
            //proof3 = mt.getProof(tree,xmssFInd + xmssLen * treeInd + 1 + topInd);
            //require(sph.xmssNaysayer(treeInd, topInd, topNode, proof, bottomNode, proof2, authNode, proof3)==false,"passed bad auth");
            //proof3 = mt.getProof(tree,xmssFInd + xmssLen * treeInd + 1 + topInd - 1);

            require(sph.xmssNaysayer(treeInd, topInd, topNode, proof, bottomNode, proof2, authNode, proof3) == false,"passed proof with no mistake");
        }
        {
            uint baseIndex = xmssFInd + xmssLen * treeInd +  1+h/d + len+len;
            sigma[baseIndex+topInd] = sigma[baseIndex+topInd] ^ bytes32(uint(1));
            sph.setSign(mt.buildRoot(sigma),M);

            bytes32[][] memory tree = mt.buildTree(sigma);


            bytes32[] memory proof = mt.getProof(tree,baseIndex+topInd);
            bytes32[] memory proof2 = mt.getProof(tree,baseIndex+topInd-1);
            bytes32[] memory proof3 = mt.getProof(tree,xmssFInd + xmssLen * treeInd + 1 + topInd - 1);

            bytes32 topNode = sigma[baseIndex+topInd];
            bytes32 bottomNode = naysayerSig.sig[treeInd].htAdditionalNodes[topInd-1];
            bytes32 authNode = naysayerSig.sig[treeInd].xmssAuth[topInd-1];
            //test auth path
            //require(sph.xmssNaysayer(treeInd, topInd, topNode, proof, bottomNode, proof2, authNode, proof3),"failed good auth");
            //proof3 = mt.getProof(tree,xmssFInd + xmssLen * treeInd + 1 + topInd);
            //require(sph.xmssNaysayer(treeInd, topInd, topNode, proof, bottomNode, proof2, authNode, proof3)==false,"passed bad auth");
            //proof3 = mt.getProof(tree,xmssFInd + xmssLen * treeInd + 1 + topInd - 1);

            require(sph.xmssNaysayer(treeInd, topInd, topNode, proof, bottomNode, proof2, authNode, proof3) == true,"failed proof with nactual mistake");
            sigma[baseIndex+topInd] = sigma[baseIndex+topInd] ^ bytes32(uint(1));
        }
    }

    function testSphincsFors()public{
        sph.setParams(n, w, h, d, k, a, t);
        sph.setPk(sphincsPk);
        bytes32[] memory sigma = flattenSPHINCS(naysayerSig);

        {
            sph.setSign(mt.buildRoot(sigma),M);
            bytes32[][] memory tree = mt.buildTree(sigma);
            bytes32[] memory proof = mt.getProof(tree,1+1*3);
            bytes32[] memory proof2 = mt.getProof(tree,1+1*3+1);
            bytes32[] memory proof3 = mt.getProof(tree,1+1*3+2);

            //test only verefication path
            //require(sph.naysayerFors(1,naysayerSig.forsSig.sig[1].sk,proof,naysayerforsProofs[1],proof2,naysayerSig.forsSig.sig[1].root,proof3),"failed good argument for verefication path");
            //require(sph.naysayerFors(1,naysayerSig.forsSig.sig[1].sk,proof,naysayerforsProofs[2],proof2,naysayerSig.forsSig.sig[1].root,proof3) == false,"passed bad argument for verefication path");

            
            require(sph.naysayerFors(1,naysayerSig.forsSig.sig[1].sk,proof,naysayerforsProofs[1],proof2,naysayerSig.forsSig.sig[1].root,proof3) == false,"passed bad proof where there is no mistakes");
            
        }
        {
            sigma[1+1*3+2] = sigma[1+1*3+2]^bytes32(uint(1));

            sph.setSign(mt.buildRoot(sigma),M);
            bytes32[][] memory tree = mt.buildTree(sigma);
            bytes32[] memory proof = mt.getProof(tree,1+1*3);
            bytes32[] memory proof2 = mt.getProof(tree,1+1*3+1);
            bytes32[] memory proof3 = mt.getProof(tree,1+1*3+2);

            require(sph.naysayerFors(1,naysayerSig.forsSig.sig[1].sk,proof,naysayerforsProofs[1],proof2,sigma[1+1*3+2],proof3),"failed good proof");
            sigma[1+1*3+2] = sigma[1+1*3+2]^bytes32(uint(1));
        }
    }

    function testSphincsForsHash() public{
        sph.setParams(n, w, h, d, k, a, t);
        sph.setPk(sphincsPk);
        bytes32[] memory sigma = flattenSPHINCS(naysayerSig);
        {
            sph.setSign(mt.buildRoot(sigma),M);
            bytes32[][] memory tree = mt.buildTree(sigma);
            bytes32[] memory roots = new bytes32[](k);
            bytes32[][] memory proofs = new bytes32[][](k);
            for (uint i =0 ; i < k; i++){
                roots[i] = sigma[1+3*i+2];
                proofs[i] = mt.getProof(tree,1+3*i+2);
            }


            bytes32[] memory proofR = mt.getProof(tree,1+3*k);
            bytes32 hashed = sigma[1+3*k];

            //check auth paths.
            //require(sph.naysayerForsHash(roots, proofs,hashed,proofR),"failed good elements");
            //proofs[0][0] = proofs[0][0]^bytes32(uint(1));
            //require(sph.naysayerForsHash(roots, proofs,hashed,proofR)== false,"passed bad elements");
            require(sph.naysayerForsHash(roots, proofs,hashed,proofR)== false,"passed proof with no actual mistake");
        }
        {
            sigma[1+1*3+2] =  sigma[1+1*3+2] ^bytes32(uint(1));
            sph.setSign(mt.buildRoot(sigma),M);
            bytes32[][] memory tree = mt.buildTree(sigma);
            bytes32[] memory roots = new bytes32[](k);
            bytes32[][] memory proofs = new bytes32[][](k);
            for (uint i =0 ; i < k; i++){
                roots[i] = sigma[1+3*i+2];
                proofs[i] = mt.getProof(tree,1+3*i+2);
            }


            bytes32[] memory proofR = mt.getProof(tree,1+3*k);
            bytes32 hashed = sigma[1+3*k];

            require(sph.naysayerForsHash(roots, proofs,hashed,proofR)==true,"failed proof with actual mistake");

            sigma[1+1*3+2] =  sigma[1+1*3+2] ^bytes32(uint(1));
        }
    }


 function verifyPartsAssign(bytes32 M, SphincsPlusNaysayer.SphincsSig memory SIG)public returns (bool){
        ADRS adrs = new ADRS();
        bytes32 R = SIG.r;
        SphincsPlusNaysayer.ForsSig memory sigFors = SIG.forsSig;



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
        forsPkFromSigPartsAssign(sigFors,md,sphincsPk.seed,adrs);
    }

    function forsPkFromSigPartsAssign(SphincsPlusNaysayer.ForsSig memory sigFors, bytes memory M, bytes32 PKseed, ADRS adrs)public  returns (bytes32) {
        bytes32[2] memory  node;
        bytes32[] memory root = new bytes32[](k);
        for(uint i = 0; i < k; i++){
            bytes memory idx = extractBits(M, i*a , (i+1)*a - i*a - 1);
            bytes32 sk = sigFors.sig[i].sk;
            adrs.setTreeHeight(0);
            //if(i == 1){
            //console.logBytes(idx);
            //}
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
            if(i == 1){
                //console.logBytes32(node[0]);
            }
            root[i] = node[0];
            naysayerSig.forsSig.sig[i].root = node[0];
        }

        ADRS forspkADRS = new ADRS();
        forspkADRS.fillFrom(adrs);
        forspkADRS.setType(FORSROOTS);
        forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32 pk = keccak256(abi.encodePacked(PKseed,forspkADRS.toBytes(),root));
        naysayerSig.forsPk = pk;
        return pk;
    }




        // Function to concatenate bytes32 arrays
    function concatenateBytes32Arrays(bytes32[] memory arr1, bytes32[] memory arr2) private pure returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](arr1.length + arr2.length);
        uint256 i = 0;
        for (; i < arr1.length; i++) {
            result[i] = arr1[i];
        }
        for (uint256 j = 0; j < arr2.length; j++) {
            result[i + j] = arr2[j];
        }
        return result;
    }


    function flattenXMSS(NaysayerXmssSig memory xmssSig) private pure returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](1);
        result[0] = xmssSig.wotsPkHash;


        // Concatenate other parts (auth, sig, wotsPk, htAdditionalNodes)
        result = concatenateBytes32Arrays(result, xmssSig.xmssAuth);
        result = concatenateBytes32Arrays(result, xmssSig.sig);
        result = concatenateBytes32Arrays(result, xmssSig.wotsPk);
        result = concatenateBytes32Arrays(result, xmssSig.htAdditionalNodes);

        return result;
    }

    bytes32 hashedForForsSig;

    function flattenFORS(NaysayerForsSig memory forsSig) private returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](forsSig.sig.length * 3+1); // Each FORS signature has 2 elements (sk, authHash)
        for (uint256 i = 0; i < forsSig.sig.length; i++) {
            result[i * 3] = forsSig.sig[i].sk;
            result[i * 3 + 1] = forsSig.sig[i].authHash;
            result[i * 3 + 2] = forsSig.sig[i].root;
        }
        result[forsSig.sig.length * 3] = hashedForForsSig;
        return result;
    }


    function flattenSPHINCS(NaysayerSphincsSig memory sphincsSig) public returns (bytes32[] memory) {
        // Start with `r`
        bytes32[] memory result = new bytes32[](1);
        result[0] = sphincsSig.r;

        // Flatten FORS sig
        bytes32[] memory forsFlattened = flattenFORS(sphincsSig.forsSig);
        result = concatenateBytes32Arrays(result, forsFlattened);

        // Flatten each XMSS sig and concatenate
        for (uint256 i = 0; i < sphincsSig.sig.length; i++) {
            bytes32[] memory xmssFlattened = flattenXMSS(sphincsSig.sig[i]);
            result = concatenateBytes32Arrays(result, xmssFlattened);
        }

        return result;
    }


    function spxSign()public {
        ADRS adrs = new ADRS();
        bytes32 opt = keccak256(abi.encodePacked(block.timestamp, "opt"));
        sphincsSig.r = keccak256(abi.encodePacked(sphincsSk.SKprf,opt,M));
        naysayerSig.r = keccak256(abi.encodePacked(sphincsSk.SKprf,opt,M));

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
        hashedForForsSig = pkFors;
        //console.logBytes32(pkFors);

        //console.logBytes32(pkFors);
        adrs.setType(TREE);
        SphincsPlusNaysayer.HtSig memory sigHt = htSign(pkFors,sphincsSk.SKseed,sphincsSk.PKseed,  uint64(bytesToBytes8(idxTree)),uint32(bytesToBytes4(idxLeaf)));
        sphincsSig.htSig = sigHt;
    }

    NaysayerXmssSig[] xmssnsig;
    uint xmssSigInd = 0;

    function htSign(bytes32 M, bytes32 SKseed, bytes32 PKseed, uint64 idxTree, uint32 idxLeaf)public returns(SphincsPlusNaysayer.HtSig memory){
        SphincsPlusNaysayer.HtSig memory sigHt = SphincsPlusNaysayer.HtSig(new SphincsPlusNaysayer.XmssSig[](d));
        xmssnsig = new NaysayerXmssSig[](d);
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(bytes8(idxTree));
        uint256 idxTreeBits = h - h / d;
        uint256 idxLeafBits = h / d;
        SphincsPlusNaysayer.XmssSig memory SigTmp = xmssSign(M,SKseed,idxLeaf,PKseed,adrs);
        sigHt.sig[0] = SigTmp;
        bytes32 root = xmssPkFromSig(idxLeaf, SigTmp, M, PKseed, adrs);
        //console.logBytes32(root);   
        xmssnsig[0].xmssAuth = SigTmp.auth;
        xmssnsig[0].sig = SigTmp.sig;
        sigHt.sig[0] = SigTmp;
        bytes memory idxLeaf2 = abi.encodePacked(idxLeaf);
        bytes memory idxTree2 = abi.encodePacked(idxTree);
        for (uint j = 1; j < d; j++) {
            xmssSigInd = j;
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
            xmssnsig[j].xmssAuth = SigTmp.auth;
            xmssnsig[j].sig = SigTmp.sig;
            sigHt.sig[j] = SigTmp;
            root = xmssPkFromSig(uint32(bytesToBytes4(idxLeaf2)), SigTmp, root, PKseed, adrs);
            //console.logBytes32(root);
            //as key gen doies not work properly
            sphincsPk.root = root;

        }
        naysayerSig.sig = xmssnsig;
        return sigHt;
    }

    function xmssPkFromSig(uint32 idx, SphincsPlusNaysayer.XmssSig memory sigXmss, bytes32 M, bytes32 PKseed, ADRS adrs) public returns (bytes32){
    adrs.setType(WOTSHASH);
    //console.logUint(idx);
    adrs.setKeyPairAddress(bytes4(idx));
    bytes32[] memory sig = sigXmss.sig;
    bytes32[] memory AUTH = sigXmss.auth;
    bytes32[2] memory node;
    node[0] = wotsPkFromSig(sig, M, PKseed, adrs);
    adrs.setType(TREE);
    adrs.setTreeIndex(bytes4(idx));
    //console.logBytes(adrs.toBytes());
    xmssnsig[xmssSigInd].htAdditionalNodes = new bytes32[](h/d+1);
    xmssnsig[xmssSigInd].htAdditionalNodes[0] =  node[0];
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
        xmssnsig[xmssSigInd].htAdditionalNodes[k+1] = node[0];

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
        xmssnsig[xmssSigInd].wotsPkHash=pk;
        xmssnsig[xmssSigInd].wotsPk = tmp;
        return pk;
    }

    function xmssSign(bytes32 M, bytes32 SKseed, uint32 idx, bytes32 PKseed, ADRS adrs)public returns(SphincsPlusNaysayer.XmssSig memory){
        bytes32[] memory AUTH = new bytes32[](h/d);
        for (uint j = 0; j < h/d; j++ ) {
            AUTH[j] = treehash(k*(2**j),j, adrs);
        }
        adrs.setType(WOTSHASH);
        adrs.setKeyPairAddress(bytes4(idx));
        bytes32[] memory sig = wotsSign(M,SKseed,PKseed,adrs);
        SphincsPlusNaysayer.XmssSig memory xmssSig = SphincsPlusNaysayer.XmssSig(sig,AUTH);
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

    function forsPkFromSig(SphincsPlusNaysayer.ForsSig memory sigFors, bytes memory M, bytes32 PKseed, ADRS adrs)public  returns (bytes32) {
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
        forspkADRS.setType(FORSROOTS);
        forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32 pk = keccak256(abi.encodePacked(PKseed,forspkADRS.toBytes(),root));
        return pk;
    }

    function forsSign( bytes memory M, bytes32 SKseed, bytes32 PKseed, ADRS adrs) public returns (SphincsPlusNaysayer.ForsSig memory){
        SphincsPlusNaysayer.ForsSig memory sig = SphincsPlusNaysayer.ForsSig(new SphincsPlusNaysayer.ForsSigInner[](k));
        NaysayerForsSig memory nsig = NaysayerForsSig(new NaysayerForsSigInner[](k),0);
        naysayerforsProofs = new bytes32[][](k);
        for(uint i = 0; i < k; i++){
            uint idx = bytesToUint256(extractBits(M, i*a, (i+1)*a - i*a));
            bytes32 sk = forsSkgen(SKseed, adrs, i*t + idx) ;

            bytes32[] memory auth = new bytes32[](a);
            for ( uint j = 0; j < a; j++ ) {
                uint s = (idx/ (2**j)) ^ 1;
                auth[j] = forsTreehash(SKseed, i * t + s * 2**j, j, PKseed, adrs);
            }
            sig.sig[i] = SphincsPlusNaysayer.ForsSigInner(sk,auth);
            nsig.sig[i] = NaysayerForsSigInner(sk,keccak256(abi.encodePacked(auth)),0); //3rd value should be defined later
            naysayerforsProofs[i] = auth;
        }

        naysayerSig.forsSig = nsig;
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