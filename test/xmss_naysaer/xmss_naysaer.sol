// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


import {Test, console} from "forge-std/Test.sol";
import {XMSSSNaysayer,ADRS} from "../../src/xmss_naysaer/xmss_naysaer.sol";
import {MerkleTree} from "../../src/merkle_tree.sol";
import "forge-std/console.sol";

//4397356 h=1
//4413730 h=2
//4430119 h=3


//4709188 h=20
//4725636 h=21
contract TestXMSSSNaysayer is Test {
    XMSSSNaysayer xmss;
    MerkleTree mt;
    uint h = 20;
    uint w = 4;
    bytes32 Mp = 0xfffffffffffffffffffffffffffffffffffffc00000000000000000000000000;
    uint m = 32; // constant
    uint n = 32; // constant as we just random 256 bit hashes
    //uint a = 8;
    uint t = 2**8;//2 ** 8;
    bytes32 SK_PRF;
    bytes32 SEED;
    uint256 l1 ;
    uint256 l2;
    uint256 l;
    bytes32[] wots_sk;
    bytes32[] wots_pk;
    bytes32[] r;
    bytes32 k;
    bytes32 root ;

    bytes32[] ht_additional_nodes;
    bytes32[] wots_pk_hash;

    bytes32 ltree_res;

    uint idx = 0;
 
    XMSSSNaysayer.PK xmss_pk;
    XMSSSNaysayer.SIG xmss_sig;

    uint256 len_1;
    uint256 len_2;
    uint256 length_all;


    function setUp() public{
        wots_pk_hash = new bytes32[](1);
        xmss = new XMSSSNaysayer();
        mt = new MerkleTree();
        l1 = (m*8) / log2(w) + ((m*8) % log2(w) == 0 ? 0 : 1);
        l2 = log2(l1*(w-1))/log2(w);
        l = l1+l2;

        len_1 = l1;
        len_2 = l2;
        length_all = l;

        XMSS_keyGen();
        xmss_sig.idx_sig =uint32(idx);
        xmss_sig.r = keccak256(abi.encodePacked(SK_PRF,idx));
        ADRS adrs = new ADRS();
        adrs.setType(0);   // Type = OTS hash address
        adrs.setOTSAddress(uint32(idx));

        xmss_sig.sig_ots = WOTS_sign(adrs);

    }


    function test_xmss_wots() public{
        xmss.set_pk(xmss_pk);
        bytes32[] memory sig = concatenateBytes32Arrays([wots_pk_hash,xmss_sig.auth,xmss_sig.sig_ots,wots_pk,ht_additional_nodes]);
        bytes32 root = mt.build_root(sig);
        bytes32[][] memory tree = mt.build_tree(sig);
        xmss.set_sig(root,xmss_sig.idx_sig,xmss_sig.r, h, Mp,xmss_sig.auth.length, xmss_sig.sig_ots.length,wots_pk.length);
        
        bytes32[] memory p1 = mt.get_proof(tree, xmss_sig.auth.length);
        bytes32[] memory p2 = mt.get_proof(tree, xmss_sig.auth.length + xmss_sig.sig_ots.length);
        /*require(xmss.naysaer_wots(0, xmss_sig.sig_ots[0], p1, wots_pk[0], p2), "failed good path");
        p2[0] = p2[0] ^ bytes1(uint8(1));
        require(xmss.naysaer_wots(0, xmss_sig.sig_ots[0], p1, wots_pk[0], p2) == false, "passed bad path");*/

        //require(xmss.naysaer_wots(0,xmss_sig.auth.length, sig[xmss_sig.auth.length], mt.get_proof(tree,xmss_sig.auth.length)) == false,"good sign failed for xmss");

        require(xmss.naysaer_wots(0, xmss_sig.sig_ots[0], p1, wots_pk[0], p2) == false, "failed no error");

        xmss_sig.sig_ots[0] = xmss_sig.sig_ots[0] ^ bytes1(uint8(1));
        sig = concatenateBytes32Arrays([wots_pk_hash,xmss_sig.auth,xmss_sig.sig_ots,wots_pk,ht_additional_nodes]);
        root = mt.build_root(sig);
        tree = mt.build_tree(sig);
        p1 = mt.get_proof(tree, 1+xmss_sig.auth.length);
        p2 = mt.get_proof(tree, 1+xmss_sig.auth.length + xmss_sig.sig_ots.length);
        xmss.set_sig(root,xmss_sig.idx_sig,xmss_sig.r, h, Mp,xmss_sig.auth.length, xmss_sig.sig_ots.length,wots_pk.length);
        require(xmss.naysaer_wots(0, xmss_sig.sig_ots[0], p1, wots_pk[0], p2) , "failed to detect error");
        xmss_sig.sig_ots[0] = xmss_sig.sig_ots[0] ^ bytes1(uint8(1));
    }


    function test_xmss_ht()public{
        {
        xmss.set_pk(xmss_pk);
        bytes32[] memory sig = concatenateBytes32Arrays([wots_pk_hash,xmss_sig.auth,xmss_sig.sig_ots,wots_pk,ht_additional_nodes]);
        bytes32 root = mt.build_root(sig);
        bytes32[][] memory tree = mt.build_tree(sig);
        xmss.set_sig(root,xmss_sig.idx_sig,xmss_sig.r, h, Mp,xmss_sig.auth.length, xmss_sig.sig_ots.length,wots_pk.length);
        bytes32[] memory p1 = mt.get_proof(tree, 1+xmss_sig.auth.length+xmss_sig.sig_ots.length+wots_pk.length+2);
        bytes32[] memory p2 = mt.get_proof(tree, 1+xmss_sig.auth.length+xmss_sig.sig_ots.length+wots_pk.length+1);
        bytes32[] memory p3 = mt.get_proof(tree, 1);


        //check that elems in signature
        //require(xmss.naysaer_ht(2, ht_additional_nodes[2], p1, ht_additional_nodes[1], p2, xmss_sig.auth[1], p3),"failed good elements");
        //require(xmss.naysaer_ht(2, ht_additional_nodes[1], p1, ht_additional_nodes[1], p2, xmss_sig.auth[1], p3) == false,"passed bad elements");

        require(xmss.naysaer_ht(2, ht_additional_nodes[2], p1, ht_additional_nodes[1], p2, xmss_sig.auth[1], p3)== false,"passed with no mistake");
        }
        {
            xmss.set_pk(xmss_pk);
            ht_additional_nodes[2] = ht_additional_nodes[2] ^ bytes32(uint(1));
            bytes32[] memory sig = concatenateBytes32Arrays([wots_pk_hash,xmss_sig.auth,xmss_sig.sig_ots,wots_pk,ht_additional_nodes]);
            bytes32 root = mt.build_root(sig);
            bytes32[][] memory tree = mt.build_tree(sig);
            xmss.set_sig(root,xmss_sig.idx_sig,xmss_sig.r, h, Mp,xmss_sig.auth.length, xmss_sig.sig_ots.length,wots_pk.length);
            bytes32[] memory p1 = mt.get_proof(tree, 1+xmss_sig.auth.length+xmss_sig.sig_ots.length+wots_pk.length+2);
            bytes32[] memory p2 = mt.get_proof(tree, 1+xmss_sig.auth.length+xmss_sig.sig_ots.length+wots_pk.length+1);
            bytes32[] memory p3 = mt.get_proof(tree, 1+1);


            //check that elems in signature
            //require(xmss.naysaer_ht(2, ht_additional_nodes[2], p1, ht_additional_nodes[1], p2, xmss_sig.auth[1], p3),"failed good elements");
            //require(xmss.naysaer_ht(2, ht_additional_nodes[1], p1, ht_additional_nodes[1], p2, xmss_sig.auth[1], p3) == false,"passed bad elements");

            require(xmss.naysaer_ht(2, ht_additional_nodes[2], p1, ht_additional_nodes[1], p2, xmss_sig.auth[1], p3),"good proof failed");
            ht_additional_nodes[2] = ht_additional_nodes[2] ^ bytes32(uint(1));
        }
    }

    function test_xmss_ltree() public{
        {
            xmss.set_pk(xmss_pk);
            bytes32[] memory sig = concatenateBytes32Arrays([wots_pk_hash,xmss_sig.auth,xmss_sig.sig_ots,wots_pk,ht_additional_nodes]);
            bytes32 root = mt.build_root(sig);
            bytes32[][] memory tree = mt.build_tree(sig);
            xmss.set_sig(root,xmss_sig.idx_sig,xmss_sig.r, h, Mp,xmss_sig.auth.length, xmss_sig.sig_ots.length,wots_pk.length);
            bytes32[] memory p1 = mt.get_proof(tree,0);
            bytes32[] memory p2 = mt.get_proof(tree,1+xmss_sig.auth.length+xmss_sig.sig_ots.length+wots_pk.length);
            //check signature path
            //require(xmss.naysaer_ltree(xmss_sig.sig_ots, p1, ltree_res, p2),"failed good elements");
            //xmss_sig.sig_ots[0] = xmss_sig.sig_ots[0] ^ bytes1(uint8(1));
            //require(xmss.naysaer_ltree(xmss_sig.sig_ots, p1, ltree_res, p2) == false,"pased bad elements");
            //xmss_sig.sig_ots[0] = xmss_sig.sig_ots[0] ^ bytes1(uint8(1));
            
            //console.logBytes();
            require(xmss.naysaer_ltree(wots_pk, p1, ltree_res, p2)==false,"passed when no error");
        }

        {
            ltree_res = ltree_res ^ bytes32(uint(1));
            ht_additional_nodes[0] = ht_additional_nodes[0] ^  bytes32(uint(1));
            xmss.set_pk(xmss_pk);
            bytes32[] memory sig = concatenateBytes32Arrays([wots_pk_hash,xmss_sig.auth,xmss_sig.sig_ots,wots_pk,ht_additional_nodes]);
            bytes32 root = mt.build_root(sig);
            bytes32[][] memory tree = mt.build_tree(sig);
            xmss.set_sig(root,xmss_sig.idx_sig,xmss_sig.r, h, Mp,xmss_sig.auth.length, xmss_sig.sig_ots.length,wots_pk.length);
            bytes32[] memory p1 = mt.get_proof(tree,0);
            bytes32[] memory p2 = mt.get_proof(tree,1+xmss_sig.auth.length+xmss_sig.sig_ots.length+wots_pk.length);
            require(xmss.naysaer_ltree(wots_pk, p1, ltree_res, p2),"failed when valid error");
            ltree_res = ltree_res ^ bytes32(uint(1));
            ht_additional_nodes[0] = ht_additional_nodes[0] ^  bytes32(uint(1));
        }

    }

    
    function WOTS_pkFromSig(bytes32[] memory sig,bytes32 M, ADRS adrs)public returns(bytes32[] memory){
        uint csum = 0;
        bytes32[] memory _msg = base_w(M,len_1);
        for (uint i = 0; i < len_1; i++ ) {
           csum = csum + w - 1 - uint(_msg[i]);
        }
        csum = csum << ( 8 - ( ( len_2 * log2(w) ) % 8 ));
        uint len_2_bytes = ceil( ( len_2 * log2(w) ), 8 );
        bytes32[] memory _msg2 = base_w(toByte(csum, len_2_bytes),len_2);
        bytes32[] memory tmp_pk = new bytes32[](length_all);
        for (uint i = 0; i < length_all; i++ ) {
          adrs.setChainAddress(uint32(i));
          if (i < len_1){
            tmp_pk[i] = chain(sig[i], uint(_msg[i]), w - 1 - uint(_msg[i]), adrs);
          }
          else{
            tmp_pk[i] = chain(sig[i], uint(_msg2[i-len_1]), w - 1 - uint(_msg2[i-len_1]), adrs);
          }
        }
        return tmp_pk;
    }

    function XMSS_keyGen()public {
        wots_sk = wots_key_sk();
        SK_PRF = random();
        SEED = random();
        ADRS adrs = new ADRS();
        //also defines auth path as we anyway fake all nodes
        root = treehash(0,adrs);
        xmss_pk = XMSSSNaysayer.PK(root,SEED);
    }

    function WOTS_sign(ADRS adrs)  public returns (bytes32[] memory sig){
        uint256 csum = 0;
        ADRS adrs_copy = new ADRS();
        adrs_copy.fillFrom(adrs);
        bytes32[] memory _msg = base_w(Mp, l1);
        for (uint i = 0; i < l1; i++ ) {
            csum = csum + w - 1 - uint256(_msg[i]);
        }
        csum = csum << ( 8 - ( ( l2 * log2(w) ) % 8 ));
        uint len_2_bytes = ceil( ( l2 * log2(w) ), 8 );
        bytes32[] memory _msg2 = base_w(toByte(csum, len_2_bytes), l2);
        sig = new bytes32[](l);
        for (uint i = 0; i < l; i++ ) {
          adrs.setChainAddress(uint32(i));
          if (i < l1){
            sig[i] = chain(wots_sk[i], 0, uint(_msg[i]), adrs);
          }
          else{
            sig[i] = chain(wots_sk[i], 0, uint(_msg2[i-l1]), adrs);
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

    function treehash(uint s, ADRS adrs) public returns (bytes32) {
        //require(s % (uint256(1) << h) == 0,"treehash cond fail");
        adrs.setType(0);   // Type = OTS hash address
        adrs.setOTSAddress(uint32(s));
        bytes32[] memory pk = wots_key_pk(adrs);
        adrs.setType(1);   // Type = L-tree address

        adrs.setLTreeAddress(uint32(s));
        wots_pk = pk;
        wots_pk_hash[0] = keccak256(abi.encodePacked(pk));
        bytes32 node = ltree(pk,adrs);
        ltree_res = node;
        adrs.setType(2);   // Type = hash tree address
        adrs.setTreeHeight(0);
        adrs.setTreeIndex(uint32(s));
        //fake other trees with random values, we need only one message tree for verefication testing
        xmss_sig.auth = new bytes32[](h);
        ht_additional_nodes = new bytes32[](h+1);
        for (uint i =0; i < (h); i++){
            ht_additional_nodes[i] = node;
            xmss_sig.auth[i] = random();
            node = RAND_HASH(node,xmss_sig.auth[i], adrs);
            adrs.setTreeHeight(uint32(adrs.getTreeHeight())+1);
        }
        ht_additional_nodes[h] = node;
        return node;
    }
    function ceil(uint a, uint b) internal pure returns (uint) {
        return (a + b - 1) / b;
    }

    function RAND_HASH(bytes32 l, bytes32 r,ADRS adrs)public returns (bytes32){
        adrs.setKeyAndMask(0);
        bytes32 KEY = PRF(adrs);
        adrs.setKeyAndMask(1);
        bytes32 BM_0 = PRF(adrs);
        adrs.setKeyAndMask(2);
        bytes32 BM_1 = PRF(adrs);
        return keccak256(abi.encodePacked(KEY, (l ^ BM_0), (r ^ BM_1)));
    }  


    function ltree(bytes32[] memory pk, ADRS addrs)public  returns (bytes32){
        uint len = l;
        addrs.setTreeHeight(0);
        while ( len > 1 ) {
            for ( uint i = 0; i < (len / 2); i++ ) {
                addrs.setTreeIndex(uint32(i));
                pk[i] = RAND_HASH(pk[2*i], pk[2*i + 1], addrs);
            }
            if ( len % 2 == 1 ) {
                pk[(len / 2)] = pk[len - 1];
            }
            len = ceil(len, 2);
            addrs.setTreeHeight(uint32(addrs.getTreeHeight()) + 1);
        }
        return pk[0];
    } 

    /*function chain(bytes32 X,uint i,uint s, ADRS adrs)public returns(bytes32) {
        if ( s == 0 ) {
            return X;
        }
        if ( (i + s) > (w - 1) ) {
            return 0;
        }
        bytes32 tmp = chain(X, i, s - 1, adrs);
        adrs.setHashAddress(uint32(i + s - 1));
        adrs.setKeyAndMask(0);
        bytes32 KEY = PRF(adrs);
        adrs.setKeyAndMask(1);
        bytes32 BM = PRF(adrs);
        tmp = keccak256(abi.encodePacked(KEY, tmp ^ BM));
        return tmp;
    }*/

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


    function wots_key_pk(ADRS adrs)public returns(bytes32[] memory){
        bytes32[] memory pk = new bytes32[](l);
        for ( uint i = 0; i < l; i++ ) {
            adrs.setChainAddress(uint32(i));
            pk[i] = chain(wots_sk[i], 0, w - 1, adrs);
        }
        return pk;
    }

    function wots_key_sk() public returns (bytes32[] memory sk){
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

    function PRF(ADRS adrs) public returns(bytes32){
        return keccak256(abi.encodePacked(SEED,adrs.toBytes()));
    }
}


