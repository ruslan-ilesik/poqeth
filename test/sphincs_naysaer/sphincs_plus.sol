pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";
import {Sphincs_plus_naysaer, ADRS,MerkleTree} from "../../src/sphincs_naysaer/sphincs_naysaer.sol";


contract TestSphincsPlusNaysayer is Test {

    struct NAYSAYER_XMSS_SIG{
        bytes32 wots_pk_hash;
       // bytes32 xmss_root;
        bytes32[] xmss_auth;
        bytes32[] sig;
        bytes32[] wots_pk;
        bytes32[] ht_additional_nodes;
    }

    struct NAYSAYER_FORS_SIG_INNER{
        bytes32 sk;
        bytes32 auth_hash;
        bytes32 root;
    }

    struct NAYSAYER_FORS_SIG{
        NAYSAYER_FORS_SIG_INNER[] sig;
        bytes32 hashed_root;
    }

    struct NAYSAYER_SPHINCS_SIG{
        bytes32 r;
        NAYSAYER_FORS_SIG fors_sig;
        NAYSAYER_XMSS_SIG[] sig;
        bytes32 fors_pk;
    }

    bytes32[][] naysayer_fors_proofs;

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

    uint n = 32; // constant
    uint m = 32; // constant
    uint w = 4;
    uint h = 16;
    uint d = 6;
    uint a = 25;
    uint k = 9;
    bytes32 M = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;
    uint t = 2 ** a;

    uint len1;
    uint len2;
    uint len;

    SPHINCS_SK sphincs_sk;
    Sphincs_plus_naysaer.SPHINCS_PK sphincs_pk;
    Sphincs_plus_naysaer.SPHINCS_SIG sphincs_sig;
    MerkleTree mt;


    NAYSAYER_SPHINCS_SIG naysayer_sig;

    Sphincs_plus_naysaer sph;
    function setUp()public{
        mt = new MerkleTree();
        sph = new Sphincs_plus_naysaer();
        len1 = (n) / log2(w) + ((n) % log2(w) == 0 ? 0 : 1);
        len2 = (log2(len1 * (w - 1)) / log2(w)) + 1;
        len = len1 + len2;

        uint tmp_md_size = (k*a+7) /8;
        uint tmp_idx_tree_size = ((h+7-h/d)/8);
        uint tmp_idx_leaf_size = (h/d+7)/8;

        //console.logUint(tmp_md_size);
        //console.logUint(tmp_idx_tree_size);
        //console.logUint(tmp_idx_leaf_size);

        require((k*a+7)/8 + (h-h/d+7)/8 + (h/d+7)/8 == m, "message size does not match one which can be signed");
        spx_keygen();
        spx_sign();
        verify_parts_assign(M,sphincs_sig);
    }


    function test_sphincs_wots_hash() public {
        sph.set_params(n, w, h, d, k, a, t);
        sph.set_pk(sphincs_pk);
        bytes32[] memory sigma = flattenSPHINCS(naysayer_sig);
        uint xmss_f_ind = 1 + 3 * k+1;
        uint xmss_len = 1+h/d + len+len+h/d+1;
        {
            sph.set_sign(mt.build_root(sigma),M);
            uint tree_ind = 1;
            bytes32[][] memory tree = mt.build_tree(sigma);

            bytes32[][] memory proofs = new bytes32[][](len);
            for (uint i =0 ; i < len; i++){
                proofs[i] = mt.get_proof(tree,xmss_f_ind+tree_ind* xmss_len + 1+h/d+len+i);
            }

            bytes32[] memory proof2 = mt.get_proof(tree,xmss_f_ind+tree_ind* xmss_len);

            uint m_ind = xmss_f_ind+xmss_len*tree_ind-1;
            bytes32 m = naysayer_sig.sig[tree_ind-1].ht_additional_nodes[h/d];
            bytes32[] memory m_proof =  mt.get_proof(tree,m_ind);

            //check proofs
            //require(sph.wots_hash_naysayer(tree_ind,naysayer_sig.sig[tree_ind].wots_pk,proofs,naysayer_sig.sig[tree_ind].wots_pk_hash,proof2,m,m_proof),"failed good proof");
            //require(sph.wots_hash_naysayer(tree_ind,naysayer_sig.sig[tree_ind-1].wots_pk,proofs,naysayer_sig.sig[tree_ind].wots_pk_hash,proof2,m,m_proof) == false,"passed bad proof");
        
            require(sph.wots_hash_naysayer(tree_ind,naysayer_sig.sig[tree_ind].wots_pk,proofs,naysayer_sig.sig[tree_ind].wots_pk_hash,proof2,m,m_proof)==false,"passed proof without mistake");
        }
        {
         
            uint tree_ind = 1;
            naysayer_sig.sig[tree_ind].wots_pk[0] = naysayer_sig.sig[tree_ind].wots_pk[0] ^ bytes32(uint(1));

            sigma = flattenSPHINCS(naysayer_sig);
            bytes32[][] memory tree = mt.build_tree(sigma);

            sph.set_sign(mt.build_root(sigma),M);

            bytes32[][] memory proofs = new bytes32[][](len);
            for (uint i =0 ; i < len; i++){
                proofs[i] = mt.get_proof(tree,xmss_f_ind+tree_ind* xmss_len + 1+h/d+len+i);
            }

            bytes32[] memory proof2 = mt.get_proof(tree,xmss_f_ind+tree_ind* xmss_len);

            uint m_ind = xmss_f_ind+xmss_len*tree_ind-1;
            bytes32 m = naysayer_sig.sig[tree_ind-1].ht_additional_nodes[h/d];
            bytes32[] memory m_proof =  mt.get_proof(tree,m_ind);

            //check proofs
            //require(sph.wots_hash_naysayer(tree_ind,naysayer_sig.sig[tree_ind].wots_pk,proofs,naysayer_sig.sig[tree_ind].wots_pk_hash,proof2,m,m_proof),"failed good proof");
            //require(sph.wots_hash_naysayer(tree_ind,naysayer_sig.sig[tree_ind-1].wots_pk,proofs,naysayer_sig.sig[tree_ind].wots_pk_hash,proof2,m,m_proof) == false,"passed bad proof");
        
            require(sph.wots_hash_naysayer(tree_ind,naysayer_sig.sig[tree_ind].wots_pk,proofs,naysayer_sig.sig[tree_ind].wots_pk_hash,proof2,m,m_proof)==true,"failed proof with mistake");
            naysayer_sig.sig[tree_ind].wots_pk[0] = naysayer_sig.sig[tree_ind].wots_pk[0] ^ bytes32(uint(1));
        }

    }


    function test_sphincs_wots() public{
        sph.set_params(n, w, h, d, k, a, t);
        sph.set_pk(sphincs_pk);
        bytes32[] memory sigma = flattenSPHINCS(naysayer_sig);
        uint xmss_f_ind = 1 + 3 * k+1;
        uint xmss_len = 1+h/d + len+len+h/d+1;
        {
            sph.set_sign(mt.build_root(sigma),M);

            uint tree_index = 1;
            uint wots_sig_ind = 2;
            bytes32[][] memory tree = mt.build_tree(sigma);
            uint wots_pk_elem_ind = xmss_f_ind+xmss_len*tree_index+1+h/d+len+wots_sig_ind;
            uint wots_sig_elem_ind = xmss_f_ind+xmss_len*tree_index+1+h/d + wots_sig_ind;
            uint m_ind = xmss_f_ind+xmss_len*tree_index-1;
            bytes32 m = naysayer_sig.sig[tree_index-1].ht_additional_nodes[h/d];
            bytes32 wots_pk_elem = naysayer_sig.sig[tree_index].wots_pk[wots_sig_ind];
            bytes32 wots_sig_elem = naysayer_sig.sig[tree_index].sig[wots_sig_ind];

            bytes32[] memory m_proof =  mt.get_proof(tree,m_ind);
            bytes32[] memory wots_pk_proof =  mt.get_proof(tree,wots_pk_elem_ind);
            bytes32[] memory wots_sig_elem_proof =  mt.get_proof(tree,wots_sig_elem_ind);

            //check auth path works
            //require (sph.wots_naysayer(tree_index, wots_sig_ind, m, m_proof, wots_pk_elem, wots_pk_proof,wots_sig_elem,wots_sig_elem_proof),"failed good auth path");
            //require (sph.wots_naysayer(tree_index+1, wots_sig_ind, m, m_proof, wots_pk_elem, wots_pk_proof,wots_sig_elem,wots_sig_elem_proof) == false,"passed bad auth path");

            require (sph.wots_naysayer(tree_index, wots_sig_ind, m, m_proof, wots_pk_elem, wots_pk_proof,wots_sig_elem,wots_sig_elem_proof) == false,"passed with no actual error");
        }
        {
            uint tree_index = 1;
            uint wots_sig_ind = 2;
            naysayer_sig.sig[tree_index].wots_pk[wots_sig_ind] = naysayer_sig.sig[tree_index].wots_pk[wots_sig_ind] ^ bytes32(uint(1));
            sigma = flattenSPHINCS(naysayer_sig);
            sph.set_sign(mt.build_root(sigma),M);
            bytes32[][] memory tree = mt.build_tree(sigma);
            uint wots_pk_elem_ind = xmss_f_ind+xmss_len*tree_index+1+h/d+len+wots_sig_ind;
            uint wots_sig_elem_ind = xmss_f_ind+xmss_len*tree_index+1+h/d + wots_sig_ind;
            uint m_ind = xmss_f_ind+xmss_len*tree_index-1;
            bytes32 m = naysayer_sig.sig[tree_index-1].ht_additional_nodes[h/d];
            bytes32 wots_pk_elem = naysayer_sig.sig[tree_index].wots_pk[wots_sig_ind];
            bytes32 wots_sig_elem = naysayer_sig.sig[tree_index].sig[wots_sig_ind];

            bytes32[] memory m_proof =  mt.get_proof(tree,m_ind);
            bytes32[] memory wots_pk_proof =  mt.get_proof(tree,wots_pk_elem_ind);
            bytes32[] memory wots_sig_elem_proof =  mt.get_proof(tree,wots_sig_elem_ind);

            //check auth path works
            //require (sph.wots_naysayer(tree_index, wots_sig_ind, m, m_proof, wots_pk_elem, wots_pk_proof,wots_sig_elem,wots_sig_elem_proof),"failed good auth path");
            //require (sph.wots_naysayer(tree_index+1, wots_sig_ind, m, m_proof, wots_pk_elem, wots_pk_proof,wots_sig_elem,wots_sig_elem_proof) == false,"passed bad auth path");

            require (sph.wots_naysayer(tree_index, wots_sig_ind, m, m_proof, wots_pk_elem, wots_pk_proof,wots_sig_elem,wots_sig_elem_proof) == true,"failed with actual proof");
            naysayer_sig.sig[tree_index].wots_pk[wots_sig_ind] = naysayer_sig.sig[tree_index].wots_pk[wots_sig_ind] ^ bytes32(uint(1));
        }
    }

    function test_sphincs_xmss()public{
        sph.set_params(n, w, h, d, k, a, t);
        sph.set_pk(sphincs_pk);
        bytes32[] memory sigma = flattenSPHINCS(naysayer_sig);
        uint xmss_f_ind = 1 + 3 * k+1;
        uint xmss_len = 1+h/d + len+len+h/d+1;
        {
            sph.set_sign(mt.build_root(sigma),M);
            uint tree_ind = 2;
            uint top_ind = 1;
            bytes32[][] memory tree = mt.build_tree(sigma);
            uint baseIndex = xmss_f_ind + xmss_len * tree_ind +  1+h/d + len+len;


            bytes32[] memory proof = mt.get_proof(tree,baseIndex+top_ind);
            bytes32[] memory proof2 = mt.get_proof(tree,baseIndex+top_ind-1);
            bytes32[] memory proof3 = mt.get_proof(tree,xmss_f_ind + xmss_len * tree_ind + 1 + top_ind - 1);

            bytes32 top_node = naysayer_sig.sig[tree_ind].ht_additional_nodes[top_ind];
            bytes32 bottom_node = naysayer_sig.sig[tree_ind].ht_additional_nodes[top_ind-1];
            bytes32 auth_node = naysayer_sig.sig[tree_ind].xmss_auth[top_ind-1];
            //test auth path
            //require(sph.xmss_naysayer(tree_ind, top_ind, top_node, proof, bottom_node, proof2, auth_node, proof3),"failed good auth");
            //proof3 = mt.get_proof(tree,xmss_f_ind + xmss_len * tree_ind + 1 + top_ind);
            //require(sph.xmss_naysayer(tree_ind, top_ind, top_node, proof, bottom_node, proof2, auth_node, proof3)==false,"passed bad auth");
            //proof3 = mt.get_proof(tree,xmss_f_ind + xmss_len * tree_ind + 1 + top_ind - 1);

            require(sph.xmss_naysayer(tree_ind, top_ind, top_node, proof, bottom_node, proof2, auth_node, proof3) == false,"passed proof with no mistake");
        }
        {
            uint tree_ind = 2;
            uint top_ind = 1;
            uint baseIndex = xmss_f_ind + xmss_len * tree_ind +  1+h/d + len+len;
            sigma[baseIndex+top_ind] = sigma[baseIndex+top_ind] ^ bytes32(uint(1));
            sph.set_sign(mt.build_root(sigma),M);

            bytes32[][] memory tree = mt.build_tree(sigma);


            bytes32[] memory proof = mt.get_proof(tree,baseIndex+top_ind);
            bytes32[] memory proof2 = mt.get_proof(tree,baseIndex+top_ind-1);
            bytes32[] memory proof3 = mt.get_proof(tree,xmss_f_ind + xmss_len * tree_ind + 1 + top_ind - 1);

            bytes32 top_node = sigma[baseIndex+top_ind];
            bytes32 bottom_node = naysayer_sig.sig[tree_ind].ht_additional_nodes[top_ind-1];
            bytes32 auth_node = naysayer_sig.sig[tree_ind].xmss_auth[top_ind-1];
            //test auth path
            //require(sph.xmss_naysayer(tree_ind, top_ind, top_node, proof, bottom_node, proof2, auth_node, proof3),"failed good auth");
            //proof3 = mt.get_proof(tree,xmss_f_ind + xmss_len * tree_ind + 1 + top_ind);
            //require(sph.xmss_naysayer(tree_ind, top_ind, top_node, proof, bottom_node, proof2, auth_node, proof3)==false,"passed bad auth");
            //proof3 = mt.get_proof(tree,xmss_f_ind + xmss_len * tree_ind + 1 + top_ind - 1);

            require(sph.xmss_naysayer(tree_ind, top_ind, top_node, proof, bottom_node, proof2, auth_node, proof3) == true,"failed proof with nactual mistake");
            sigma[baseIndex+top_ind] = sigma[baseIndex+top_ind] ^ bytes32(uint(1));
        }
    }

    function test_sphincs_fors()public{
        sph.set_params(n, w, h, d, k, a, t);
        sph.set_pk(sphincs_pk);
        bytes32[] memory sigma = flattenSPHINCS(naysayer_sig);

        {
            sph.set_sign(mt.build_root(sigma),M);
            bytes32[][] memory tree = mt.build_tree(sigma);
            bytes32[] memory proof = mt.get_proof(tree,1+1*3);
            bytes32[] memory proof2 = mt.get_proof(tree,1+1*3+1);
            bytes32[] memory proof3 = mt.get_proof(tree,1+1*3+2);

            //test only verefication path
            //require(sph.naysaer_fors(1,naysayer_sig.fors_sig.sig[1].sk,proof,naysayer_fors_proofs[1],proof2,naysayer_sig.fors_sig.sig[1].root,proof3),"failed good argument for verefication path");
            //require(sph.naysaer_fors(1,naysayer_sig.fors_sig.sig[1].sk,proof,naysayer_fors_proofs[2],proof2,naysayer_sig.fors_sig.sig[1].root,proof3) == false,"passed bad argument for verefication path");

            
            require(sph.naysaer_fors(1,naysayer_sig.fors_sig.sig[1].sk,proof,naysayer_fors_proofs[1],proof2,naysayer_sig.fors_sig.sig[1].root,proof3) == false,"passed bad proof where there is no mistakes");
            
        }
        {
            sigma[1+1*3+2] = sigma[1+1*3+2]^bytes32(uint(1));

            sph.set_sign(mt.build_root(sigma),M);
            bytes32[][] memory tree = mt.build_tree(sigma);
            bytes32[] memory proof = mt.get_proof(tree,1+1*3);
            bytes32[] memory proof2 = mt.get_proof(tree,1+1*3+1);
            bytes32[] memory proof3 = mt.get_proof(tree,1+1*3+2);

            require(sph.naysaer_fors(1,naysayer_sig.fors_sig.sig[1].sk,proof,naysayer_fors_proofs[1],proof2,sigma[1+1*3+2],proof3),"failed good proof");
            sigma[1+1*3+2] = sigma[1+1*3+2]^bytes32(uint(1));
        }
    }

    function test_sphincs_fors_hash() public{
        sph.set_params(n, w, h, d, k, a, t);
        sph.set_pk(sphincs_pk);
        bytes32[] memory sigma = flattenSPHINCS(naysayer_sig);
        {
            sph.set_sign(mt.build_root(sigma),M);
            bytes32[][] memory tree = mt.build_tree(sigma);
            bytes32[] memory roots = new bytes32[](k);
            bytes32[][] memory proofs = new bytes32[][](k);
            for (uint i =0 ; i < k; i++){
                roots[i] = sigma[1+3*i+2];
                proofs[i] = mt.get_proof(tree,1+3*i+2);
            }


            bytes32[] memory proof_r = mt.get_proof(tree,1+3*k);
            bytes32 hashed = sigma[1+3*k];

            //check auth paths.
            //require(sph.naysayer_fors_hash(roots, proofs,hashed,proof_r),"failed good elements");
            //proofs[0][0] = proofs[0][0]^bytes32(uint(1));
            //require(sph.naysayer_fors_hash(roots, proofs,hashed,proof_r)== false,"passed bad elements");
            require(sph.naysayer_fors_hash(roots, proofs,hashed,proof_r)== false,"passed proof with no actual mistake");
        }
        {
            sigma[1+1*3+2] =  sigma[1+1*3+2] ^bytes32(uint(1));
            sph.set_sign(mt.build_root(sigma),M);
            bytes32[][] memory tree = mt.build_tree(sigma);
            bytes32[] memory roots = new bytes32[](k);
            bytes32[][] memory proofs = new bytes32[][](k);
            for (uint i =0 ; i < k; i++){
                roots[i] = sigma[1+3*i+2];
                proofs[i] = mt.get_proof(tree,1+3*i+2);
            }


            bytes32[] memory proof_r = mt.get_proof(tree,1+3*k);
            bytes32 hashed = sigma[1+3*k];

            require(sph.naysayer_fors_hash(roots, proofs,hashed,proof_r)==true,"failed proof with actual mistake");

            sigma[1+1*3+2] =  sigma[1+1*3+2] ^bytes32(uint(1));
        }
    }


 function verify_parts_assign(bytes32 M, Sphincs_plus_naysaer.SPHINCS_SIG memory SIG)public returns (bool){
        ADRS adrs = new ADRS();
        bytes32 R = SIG.r;
        Sphincs_plus_naysaer.FORS_SIG memory SIG_FORS = SIG.fors_sig;
        //HT_SIG memory SIG_HT = SIG.ht_sig;


        //We assume M is already diggest for testing hamming weight propouses
        bytes32 digest = M;


        uint tmp_md_size = (k*a+7) /8;
        uint tmp_idx_tree_size = ((h-h/d+7)/8);
        uint tmp_idx_leaf_size = (h/d+7)/8;

        bytes1[] memory tmp_md = new bytes1[](tmp_md_size);
        for (uint i=0; i < tmp_md_size; i++ ){
            tmp_md[i] = digest[i];
        }

        bytes1[] memory tmp_idx_tree = new bytes1[](tmp_idx_tree_size);
        for (uint i=0; i < tmp_idx_tree_size; i++ ){
            tmp_idx_tree[i] = digest[tmp_md_size+i];
        }

        bytes1[] memory tmp_idx_leaf = new bytes1[](tmp_idx_leaf_size);
        for (uint i=0; i < tmp_idx_leaf_size; i++ ){
            tmp_idx_leaf[i] = digest[tmp_md_size+tmp_idx_tree_size+i];
        }

        bytes memory  md = extractBits(abi.encodePacked(tmp_md), 0, k*a);

        // idx_tree: first h - h/d bits after md
        uint256 idx_tree_bits = h - h / d;
        bytes memory  idx_tree = extractBits(abi.encodePacked(tmp_idx_tree), 0, idx_tree_bits);

        // idx_leaf: first h/d bits after idx_tree
        uint256 idx_leaf_bits = h / d;
        bytes memory idx_leaf = extractBits(abi.encodePacked(tmp_idx_leaf), 0, idx_leaf_bits);

        adrs.setType(FORS_TREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(bytesToBytes4(idx_tree));
        adrs.setKeyPairAddress(bytesToBytes4(idx_leaf));
        fors_pkFromSig_parts_assign(SIG_FORS,md,sphincs_pk.seed,adrs);
    }

    function fors_pkFromSig_parts_assign(Sphincs_plus_naysaer.FORS_SIG memory SIG_FORS, bytes memory M, bytes32 PKseed, ADRS adrs)public  returns (bytes32) {
        bytes32[2] memory  node;
        bytes32[] memory root = new bytes32[](k);
        for(uint i = 0; i < k; i++){
            bytes memory idx = extractBits(M, i*a , (i+1)*a - i*a - 1);
            bytes32 sk = SIG_FORS.sig[i].sk;
            adrs.setTreeHeight(0);
            //if(i == 1){
            //console.logBytes(idx);
            //}
            adrs.setTreeIndex(bytes4(uint32(i*t + uint32(bytesToBytes4(idx)))));

            node[0] = keccak256(abi.encodePacked(PKseed, adrs.toBytes(), sk));

            bytes32[] memory auth = SIG_FORS.sig[i].auth;

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
            naysayer_sig.fors_sig.sig[i].root = node[0];
        }

        ADRS forspkADRS = new ADRS();
        forspkADRS.fillFrom(adrs);
        forspkADRS.setType(FORS_ROOTS);
        forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32 pk = keccak256(abi.encodePacked(PKseed,forspkADRS.toBytes(),root));
        naysayer_sig.fors_pk = pk;
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

    // Function to flatten NAYSAYER_XMSS_SIG into bytes32[]
    function flattenXMSS(NAYSAYER_XMSS_SIG memory xmssSig) private pure returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](1);
        result[0] = xmssSig.wots_pk_hash;
        //result[1] = xmssSig.xmss_root;

        // Concatenate other parts (auth, sig, wots_pk, ht_additional_nodes)
        result = concatenateBytes32Arrays(result, xmssSig.xmss_auth);
        result = concatenateBytes32Arrays(result, xmssSig.sig);
        result = concatenateBytes32Arrays(result, xmssSig.wots_pk);
        result = concatenateBytes32Arrays(result, xmssSig.ht_additional_nodes);

        return result;
    }

    bytes32 hashed_for_fors_sig;
    // Function to flatten NAYSAYER_FORS_SIG into bytes32[]
    function flattenFORS(NAYSAYER_FORS_SIG memory forsSig) private returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](forsSig.sig.length * 3+1); // Each FORS signature has 2 elements (sk, auth_hash)
        for (uint256 i = 0; i < forsSig.sig.length; i++) {
            result[i * 3] = forsSig.sig[i].sk;
            result[i * 3 + 1] = forsSig.sig[i].auth_hash;
            result[i * 3 + 2] = forsSig.sig[i].root;
        }
        result[forsSig.sig.length * 3] = hashed_for_fors_sig;
        return result;
    }

    // Function to flatten NAYSAYER_SPHINCS_SIG into bytes32[]
    function flattenSPHINCS(NAYSAYER_SPHINCS_SIG memory sphincsSig) public returns (bytes32[] memory) {
        // Start with `r`
        bytes32[] memory result = new bytes32[](1);
        result[0] = sphincsSig.r;

        // Flatten FORS sig
        bytes32[] memory fors_flattened = flattenFORS(sphincsSig.fors_sig);
        result = concatenateBytes32Arrays(result, fors_flattened);

        // Flatten each XMSS sig and concatenate
        for (uint256 i = 0; i < sphincsSig.sig.length; i++) {
            bytes32[] memory xmss_flattened = flattenXMSS(sphincsSig.sig[i]);
            result = concatenateBytes32Arrays(result, xmss_flattened);
        }

        return result;
    }


    function spx_sign()public {
        ADRS adrs = new ADRS();
        bytes32 opt = keccak256(abi.encodePacked(block.timestamp, "opt"));
        sphincs_sig.r = keccak256(abi.encodePacked(sphincs_sk.SKprf,opt,M));
        naysayer_sig.r = keccak256(abi.encodePacked(sphincs_sk.SKprf,opt,M));

        //We assume M is already diggest for testing hamming weight propouses
        bytes32 digest = M;
        uint tmp_md_size = (k*a+7) /8;
        uint tmp_idx_tree_size = ((h-h/d+7)/8);
        uint tmp_idx_leaf_size = (h/d+7)/8;

        bytes1[] memory tmp_md = new bytes1[](tmp_md_size);
        for (uint i=0; i < tmp_md_size; i++ ){
            tmp_md[i] = digest[i];
        }
        
        bytes1[] memory tmp_idx_tree = new bytes1[](tmp_idx_tree_size);
        for (uint i=0; i < tmp_idx_tree_size; i++ ){
            tmp_idx_tree[i] = digest[tmp_md_size+i];
        }

        bytes1[] memory tmp_idx_leaf = new bytes1[](tmp_idx_leaf_size);
        for (uint i=0; i < tmp_idx_leaf_size; i++ ){
            tmp_idx_leaf[i] = digest[tmp_md_size+tmp_idx_tree_size+i];
        }
          
 
        bytes memory  md = extractBits(abi.encodePacked(tmp_md), 0, k*a);

        // idx_tree: first h - h/d bits after md
        uint256 idx_tree_bits = h - h / d;
        bytes memory  idx_tree = extractBits(abi.encodePacked(tmp_idx_tree), 0, idx_tree_bits);

        // idx_leaf: first h/d bits after idx_tree
        uint256 idx_leaf_bits = h / d;
        bytes memory idx_leaf = extractBits(abi.encodePacked(tmp_idx_leaf), 0, idx_leaf_bits);
        

        adrs.setType(FORS_TREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(bytesToBytes8(idx_tree));
        adrs.setKeyPairAddress(bytesToBytes4(idx_leaf));
        sphincs_sig.fors_sig = fors_sign(md, sphincs_sk.SKseed, sphincs_sk.PKseed, adrs);
        bytes32 PK_FORS = fors_pkFromSig(sphincs_sig.fors_sig,md,sphincs_sk.PKseed,adrs);
        hashed_for_fors_sig = PK_FORS;
        //console.logBytes32(PK_FORS);

        //console.logBytes32(PK_FORS);
        adrs.setType(TREE);
        Sphincs_plus_naysaer.HT_SIG memory SIG_HT = ht_sign(PK_FORS,sphincs_sk.SKseed,sphincs_sk.PKseed,  uint64(bytesToBytes8(idx_tree)),uint32(bytesToBytes4(idx_leaf)));
        sphincs_sig.ht_sig = SIG_HT;
    }

    NAYSAYER_XMSS_SIG[] xmssnsig;
    uint xmssn_sig_ind = 0;

    function ht_sign(bytes32 M, bytes32 SKseed, bytes32 PKseed, uint64 idx_tree, uint32 idx_leaf)public returns(Sphincs_plus_naysaer.HT_SIG memory){
        Sphincs_plus_naysaer.HT_SIG memory SIG_HT = Sphincs_plus_naysaer.HT_SIG(new Sphincs_plus_naysaer.XMSS_SIG[](d));
        xmssnsig = new NAYSAYER_XMSS_SIG[](d);
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(bytes8(idx_tree));
        uint256 idx_tree_bits = h - h / d;
        uint256 idx_leaf_bits = h / d;
        Sphincs_plus_naysaer.XMSS_SIG memory SIG_tmp = xmss_sign(M,SKseed,idx_leaf,PKseed,adrs);
        SIG_HT.sig[0] = SIG_tmp;
        bytes32 root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PKseed, adrs);
        //xmssnsig[0].xmss_root = root;
        //console.logBytes32(root);   
        xmssnsig[0].xmss_auth = SIG_tmp.auth;
        xmssnsig[0].sig = SIG_tmp.sig;
        SIG_HT.sig[0] = SIG_tmp;
        bytes memory idx_leaf2 = abi.encodePacked(idx_leaf);
        bytes memory idx_tree2 = abi.encodePacked(idx_tree);
        for (uint j = 1; j < d; j++) {
            xmssn_sig_ind = j;
            if (j == d-1){
                idx_tree_bits = 0;
                idx_leaf2 = new bytes(4);
                idx_tree2 = new bytes(4);
            }
            else{
                // Extract idx_leaf as the least significant (h / d) bits of idx_tree
                idx_leaf2 = extractBits(idx_tree2, idx_tree_bits - (h / d), h / d);

                // Update idx_tree to the most significant (h - (j + 1) * (h / d)) bits
                idx_tree_bits -= h / d;
                
                idx_tree2 = extractBits(idx_tree2, 0, idx_tree_bits);
            }
            adrs.setLayerAddress(bytes4(uint32(j)));
            adrs.setTreeAddress(bytesToBytes4(idx_tree2));
            SIG_tmp = xmss_sign(root, SKseed, uint32(bytesToBytes4(idx_tree2)), PKseed, adrs);
            xmssnsig[j].xmss_auth = SIG_tmp.auth;
            xmssnsig[j].sig = SIG_tmp.sig;
            SIG_HT.sig[j] = SIG_tmp;
            root = xmss_pkFromSig(uint32(bytesToBytes4(idx_leaf2)), SIG_tmp, root, PKseed, adrs);
            //console.logBytes32(root);
            //as key gen doies not work properly
            sphincs_pk.root = root;
           // xmssnsig[j].xmss_root = root;
        }
        naysayer_sig.sig = xmssnsig;
        return SIG_HT;
    }

    function xmss_pkFromSig(uint32 idx, Sphincs_plus_naysaer.XMSS_SIG memory SIG_XMSS, bytes32 M, bytes32 PKseed, ADRS adrs) public returns (bytes32){
    adrs.setType(WOTS_HASH);
    //console.logUint(idx);
    adrs.setKeyPairAddress(bytes4(idx));
    bytes32[] memory sig = SIG_XMSS.sig;
    bytes32[] memory AUTH = SIG_XMSS.auth;
    bytes32[2] memory node;
    node[0] = wots_pkFromSig(sig, M, PKseed, adrs);
    adrs.setType(TREE);
    adrs.setTreeIndex(bytes4(idx));
    //console.logBytes(adrs.toBytes());
    xmssnsig[xmssn_sig_ind].ht_additional_nodes = new bytes32[](h/d+1);
    xmssnsig[xmssn_sig_ind].ht_additional_nodes[0] =  node[0];
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
        xmssnsig[xmssn_sig_ind].ht_additional_nodes[k+1] = node[0];

        }
    return node[0];
    }

    function wots_pkFromSig(bytes32[] memory sig, bytes32 M, bytes32 PKseed, ADRS adrs) public returns(bytes32){
        uint csum = 0;
        ADRS wotspkADRS = new ADRS();
        wotspkADRS.fillFrom(adrs);
        bytes32[] memory _msg = base_w(M,len1);
        for (uint i = 0; i < len1; i++ ) {
           csum = csum + w - 1 - uint(_msg[i]);
        }
        csum = csum << ( 8 - ( ( len2 * log2(w) ) % 8 ));
        uint len_2_bytes = ceil( ( len2 * log2(w) ), 8 );
        bytes32[] memory _msg2 = base_w(toByte(csum, len_2_bytes),len2);
        bytes32[] memory tmp = new bytes32[](len);
        for (uint i = 0; i < len; i++ ) {
          adrs.setChainAddress(bytes4(uint32(i)));
          if (i < len1){
            tmp[i] = chain(sig[i], uint(_msg[i]), w - 1 - uint(_msg[i]),PKseed, adrs);
          }
          else{
            tmp[i] = chain(sig[i], uint(_msg2[i-len1]), w - 1 - uint(_msg2[i-len1]),PKseed, adrs);
          }

        }
        wotspkADRS.setType(WOTS_PK);
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32 pk = keccak256(abi.encodePacked(PKseed,wotspkADRS.toBytes(),tmp));
        xmssnsig[xmssn_sig_ind].wots_pk_hash=pk;
        xmssnsig[xmssn_sig_ind].wots_pk = tmp;
        return pk;
    }

    function xmss_sign(bytes32 M, bytes32 SKseed, uint32 idx, bytes32 PKseed, ADRS adrs)public returns(Sphincs_plus_naysaer.XMSS_SIG memory){
        bytes32[] memory AUTH = new bytes32[](h/d);
        for (uint j = 0; j < h/d; j++ ) {
            AUTH[j] = treehash(k*(2**j),j, adrs);
        }
        adrs.setType(WOTS_HASH);
        adrs.setKeyPairAddress(bytes4(idx));
        bytes32[] memory sig = wots_sign(M,SKseed,PKseed,adrs);
        Sphincs_plus_naysaer.XMSS_SIG memory xmss_sig = Sphincs_plus_naysaer.XMSS_SIG(sig,AUTH);
        return xmss_sig;
    } 

    function wots_sign(bytes32 M, bytes32 SKseed, bytes32 PKseed, ADRS adrs)public returns(bytes32[] memory){
        uint csum = 0;
        bytes32[] memory _msg = base_w(M, len1);
        for (uint i = 0; i < len1; i++ ) {
            csum = csum + w - 1 - uint256(_msg[i]);
        }
        
        if( (log2(w) % 8) != 0) {
            csum = csum << ( 8 - ( ( len2 * log2(w) ) % 8 ));
        }
        uint len_2_bytes = ceil( ( len2 * log2(w) ), 8 );
        bytes32[] memory _msg2 = base_w(toByte(csum, len_2_bytes), len2);
        ADRS skADRS = new ADRS();
        skADRS.fillFrom(adrs);
        skADRS.setType(WOTS_PRF);
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress());

        bytes32[] memory sig = new bytes32[](len);
        for (uint i = 0; i < len; i++ ) {
            skADRS.setChainAddress(bytes4(uint32(i)));
            skADRS.setHashAddress(0);
            bytes32 sk = PRF(SKseed, skADRS);
            adrs.setChainAddress(bytes4(uint32(i)));
            adrs.setHashAddress(0);
            if (i < len1){
                sig[i] = chain(sk, 0, uint(_msg[i]),PKseed, adrs);
            }
            else{
                sig[i] = chain(sk, 0, uint(_msg2[i-len1]),PKseed, adrs);
            }
        }
        return sig;
    }

    function fors_pkFromSig(Sphincs_plus_naysaer.FORS_SIG memory SIG_FORS, bytes memory M, bytes32 PKseed, ADRS adrs)public  returns (bytes32) {
        bytes32[2] memory  node;
        bytes32[] memory root = new bytes32[](k);
        for(uint i = 0; i < k; i++){
            bytes memory idx = extractBits(M, i*a , (i+1)*a - i*a - 1);
            bytes32 sk = SIG_FORS.sig[i].sk;
            adrs.setTreeHeight(0);
            adrs.setTreeIndex(bytes4(uint32(i*t + uint32(bytesToBytes4(idx)))));
            node[0] = keccak256(abi.encodePacked(PKseed, adrs.toBytes(), sk));
            bytes32[] memory auth = SIG_FORS.sig[i].auth;

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
        forspkADRS.setType(FORS_ROOTS);
        forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        bytes32 pk = keccak256(abi.encodePacked(PKseed,forspkADRS.toBytes(),root));
        return pk;
    }

    function fors_sign( bytes memory M, bytes32 SKseed, bytes32 PKseed, ADRS adrs) public returns (Sphincs_plus_naysaer.FORS_SIG memory){
        Sphincs_plus_naysaer.FORS_SIG memory sig = Sphincs_plus_naysaer.FORS_SIG(new Sphincs_plus_naysaer.FORS_SIG_INNER[](k));
        NAYSAYER_FORS_SIG memory nsig = NAYSAYER_FORS_SIG(new NAYSAYER_FORS_SIG_INNER[](k),0);
        naysayer_fors_proofs = new bytes32[][](k);
        for(uint i = 0; i < k; i++){
            uint idx = bytesToUint256(extractBits(M, i*a, (i+1)*a - i*a));
            bytes32 sk = fors_SKgen(SKseed, adrs, i*t + idx) ;

            bytes32[] memory auth = new bytes32[](a);
            for ( uint j = 0; j < a; j++ ) {
                uint s = (idx/ (2**j)) ^ 1;
                auth[j] = fors_treehash(SKseed, i * t + s * 2**j, j, PKseed, adrs);
            }
            sig.sig[i] = Sphincs_plus_naysaer.FORS_SIG_INNER(sk,auth);
            nsig.sig[i] = NAYSAYER_FORS_SIG_INNER(sk,keccak256(abi.encodePacked(auth)),0); //3rd value should be defined later
            naysayer_fors_proofs[i] = auth;
        }

        naysayer_sig.fors_sig = nsig;
        return sig;
    }

    function fors_treehash(bytes32 SKseed, uint s, uint z, bytes32 PKseed, ADRS adrs)public returns (bytes32){
        require( s % (1 << z) == 0, "fors_treehash condition failed");

        //2^z not needed as we fake path
        bytes32 sk = fors_SKgen(SKseed,adrs,s);
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

    function fors_SKgen(bytes32 SKseed, ADRS adrs, uint idx)public returns (bytes32){
        ADRS skADRS = new ADRS();
        skADRS.fillFrom(adrs);
        skADRS.setType(FORS_PRF);
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        skADRS.setTreeHeight(0);
        skADRS.setTreeIndex(bytes4(uint32(idx)));

        return PRF(SKseed,skADRS);
    }

    function spx_keygen()public{
        sphincs_sk.SKseed = keccak256(abi.encodePacked(block.timestamp, "SKseed"));
        sphincs_sk.SKprf = keccak256(abi.encodePacked(block.timestamp, "SKprf"));

        sphincs_pk.seed =  keccak256(abi.encodePacked(block.timestamp, "PKseed"));

        // key gen does not work properly because of faking
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
            
            //auth[i] = keccak256(abi.encodePacked(block.timestamp,h));
            node = keccak256(abi.encodePacked(sphincs_pk.seed ,adrs.toBytes(),node,bytes32(0)));
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

    function base_w(bytes memory X,uint out_len) public returns (bytes32[] memory){
        uint iin = 0;
        uint out = 0;
        uint8 total = 0;
        uint bits = 0;
        uint consumed;
        bytes32[] memory basew = new bytes32[](out_len);
        for (consumed = 0; consumed < out_len; consumed++ ) {
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

    function base_w(bytes32 X,uint out_len) public returns (bytes32[] memory){
        uint iin = 0;
        uint out = 0;
        uint8 total = 0;
        uint bits = 0;
        uint consumed;
        bytes32[] memory basew = new bytes32[](out_len);
        for (consumed = 0; consumed < out_len; consumed++ ) {
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
        require(b.length <= 4, "Bytes array too long to convert to bytes4");
        bytes4 out;
        if (b.length == 0) {
            return out; // return 0x00000000 if the array is empty
        }
        assembly {
            out := mload(add(b, 32))
        }
        // If the input is shorter than 4 bytes, shift it to the right
        return bytes4(uint32(out) << (8 * (4 - b.length)));
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