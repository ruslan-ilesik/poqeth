pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";
import {LinkedListStack, StackEnty} from "./LinkedListStack.sol";
import {Sphincs_plus,SIG,ADDRS,ADDRSTypes} from "../../src/sphincs_plus/sphincs_plus.sol";





contract TestSphincsPlus is Test {
    uint n = 32;
    uint w = 16;
    uint h = 60;
    uint d = 10;
    uint k = 248;
    uint a = 8;
    uint t = 2 ** a;
    uint len1;
    uint len2;
    uint len;


    function setUp() public{}


    function test_ADDR() public{
        ADDRS aa = new ADDRS();
        bytes4 b = 0xFFFFBCFF;
        aa.setChainAddress(b);
        assertTrue(b == aa.getChainAddress());

        ADDRS bb = copyADDRS(aa);
        bytes1[12] memory temp;
        for (uint i = 0; i < temp.length; i++) {
            temp[i] = bytes1(0);
        }
        aa.setData(temp);
        bool f = true;
        for (uint i =0; i < aa.getData().length; i++){
            if (aa.getData()[i] != bb.getData()[i]){
                f = false;
            }
        }
        if (f){
            assertTrue(1==2,"Copy does not work properly");
        }

        
    }
    bytes SK;
    bytes PK;


    function test_sphincs_plus() public{
        return;
        Sphincs_plus spc = new Sphincs_plus();
        string memory message = "Hello";
        uint m = 256;
        
        // Calculate m using the given formula
        uint log_t = log2(t);
        uint part1 = (k * log_t + 7) / 8;
        uint part2 = (h - h / d + 7) / 8;
        uint part3 = (h / d + 7) / 8;
        uint calculated_m = part1 + part2 + part3;
        
        // Check if calculated_m equals the given m
        require(calculated_m == m, "Calculated m does not match given m");

        len1 = (n) / log2(w) + ((n) % log2(w) == 0 ? 0 : 1);
        len2 = (log2(len1 * (w - 1)) / log2(w)) + 1;
        len = len1 + len2;

        bytes1[] memory sk_seed = NPRNG(n);
        bytes1[] memory sk_prf = NPRNG(n);
        bytes1[] memory pk_seed = NPRNG(n);


        bytes32 pk_root = ht_PKgen(sk_seed,pk_seed);

        (SK,PK) = key_gen(sk_seed, sk_prf, pk_seed,pk_root);
        spc.set_pk(PK);
        sign(message, SK,sk_prf,pk_seed,pk_root,sk_seed);
        
        SIG memory aaaa = copySIG(signature);
        require (spc.spx_verify(message,aaaa),"VERIFY FAILED");


    }
    function copySIG(SIG memory original) internal pure returns (SIG memory) {
        // Initialize a new SIG struct to hold the copy
        SIG memory copy;

        // Copy randomness array
        copy.randomness = new bytes1[](original.randomness.length);
        for (uint i = 0; i < original.randomness.length; i++) {
            copy.randomness[i] = original.randomness[i];
        }

        // Copy sig_fors array
        copy.sig_fors = new bytes1[](original.sig_fors.length);
        for (uint i = 0; i < original.sig_fors.length; i++) {
            copy.sig_fors[i] = original.sig_fors[i];
        }

        // Copy sig_ht array
        copy.sig_ht = new bytes1[](original.sig_ht.length);
        for (uint i = 0; i < original.sig_ht.length; i++) {
            copy.sig_ht[i] = original.sig_ht[i];
        }

        return copy;
    }



    SIG signature; 
    function sign(string memory M, bytes memory SK, bytes1[] memory sk_prf, bytes1[] memory pk_seed, bytes32 pk_root, bytes1[] memory sk_seed) public {
        ADDRS addrs = new ADDRS();
        bytes1[] memory opt = NPRNG(n);
        bytes1[] memory R = PRF_msg(sk_prf, opt, M);
        signature = SIG(R,new bytes1[](1),new bytes1[](1));
        bytes1[] memory digest = h_msg(R, pk_seed, pk_root, M);


        uint tmp_md_len = (k * (a + 7)) / 8;
        uint tmp_idx_tree_len = (h - (h / d) + 7) / 8;
        uint tmp_idx_leaf_len = (h / d + 7) / 8;

        bytes memory tmp_md = new bytes(tmp_md_len);
        bytes memory tmp_idx_tree = new bytes(tmp_idx_tree_len);
        bytes memory tmp_idx_leaf = new bytes(tmp_idx_leaf_len);

        for (uint i = 0; i < tmp_md_len; i++) {
            tmp_md[i] = digest[i];
        }

        for (uint i = 0; i < tmp_idx_tree_len; i++) {
            tmp_idx_tree[i] = digest[tmp_md_len + i];
        }

        for (uint i = 0; i < tmp_idx_leaf_len; i++) {
            tmp_idx_leaf[i] = digest[tmp_md_len + tmp_idx_tree_len + i];
        }

        // Extract md, idx_tree, and idx_leaf from the digest
  
        bytes1[] memory md = new bytes1[](k*a / 8);
        for (uint i = 0; i < k*a / 8; i++) {
            md[i] = tmp_md[i];
        }

        // Extract idx_tree
        bytes12 idx_tree = 0;
        uint idx_tree_bits = h - (h / d);
        for (uint i = 0; i < idx_tree_bits; i++) {
            uint bytePos = i / 8;
            uint bitPos = i % 8;
            if ((uint8(tmp_idx_tree[bytePos]) & (1 << bitPos)) != 0) {
                idx_tree |= bytes12(uint96(1) << i);
            }
        }

        // Extract idx_leaf
        bytes4 idx_leaf = 0;
        uint idx_leaf_bits = h / d;
        for (uint i = 0; i < idx_leaf_bits; i++) {
            uint bytePos = i / 8;
            uint bitPos = i % 8;
            if ((uint8(tmp_idx_leaf[bytePos]) & (1 << bitPos)) != 0) {
                idx_leaf |= bytes4(uint32(1) << i);
            }
        }
        
        addrs.setLayerAddress(0);
        addrs.setTreeAddress(idx_tree);
        addrs.setType(ADDRSTypes.FORS_TREE);
        addrs.setKeyPairAddress(idx_leaf);

        signature.sig_fors = fors_sign(md, sk_seed, pk_seed, addrs);
        bytes32 PK_FORS = fors_pkFromSig(signature.sig_fors, md, pk_seed, addrs);
        addrs.setType(ADDRSTypes.TREE);
        bytes memory tmp =  ht_sign(PK_FORS, sk_seed, pk_seed, idx_tree, idx_leaf);
        signature.sig_ht = new bytes1[](tmp.length);
        for (uint i=0; i < tmp.length;i++){
            signature.sig_ht[i] = tmp[i];
        }
        //

    }


    function extractBits(bytes12 input, uint startBit, uint length) internal pure returns (bytes12) {
        uint96 mask = (uint96(1) << length) - 1;
        uint96 extractedBits = (uint96(input) >> startBit) & mask;
        return bytes12(extractedBits);
    }

    function ht_sign(bytes32 M, bytes1[] memory sk_seed, bytes1[] memory pk_seed, bytes12 idx_tree, bytes12 idx_leaf) public returns(bytes memory){
        ADDRS ADRS = new ADDRS();
        ADRS.setLayerAddress(0);
        ADRS.setTreeAddress(idx_tree);
        bytes memory SIG_HT = xmss_sign(M,sk_seed,idx_leaf,pk_seed,ADRS);

        //SIG_HT = SIG_TMP
        bytes32 root= xmss_pkFromSig(idx_leaf, SIG_HT, M, pk_seed, ADRS);
        for ( uint j = 1; j < d; j++ ) {
            idx_leaf = bytes4(extractBits(idx_tree, 0, h / d));
            idx_tree = bytes12(extractBits(idx_tree, h / d, h - (j + 1) * (h / d)));
            ADRS.setLayerAddress(bytes4(uint32(j)));
            ADRS.setTreeAddress(idx_tree);
            bytes memory SIG_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, ADRS);
            SIG_HT = abi.encodePacked(SIG_HT,SIG_tmp);
            if ( j < d - 1 ) {
                root = xmss_pkFromSig(idx_leaf, SIG_tmp, root, pk_seed, ADRS);
            }

        }
        return SIG_HT;
    }

    function xmss_pkFromSig(bytes12 idx,  bytes memory SIG_XMSS, bytes32 M, bytes1[] memory pk_seed, ADDRS ADRS) public returns (bytes32){
        ADRS.setType(ADDRSTypes.WOTS_HASH);
        ADRS.setKeyPairAddress(bytes4(idx));
                //first len bytes - sign
        bytes1[] memory sig = new bytes1[](len);
        for (uint i=0; i < len; i++){
            sig[i] = SIG_XMSS[i];
        }

        bytes1[] memory AUTH = new bytes1[](SIG_XMSS.length - len);
        for (uint i=0; i < SIG_XMSS.length - len; i++){
            AUTH[i] = SIG_XMSS[i+len];
        }

        bytes32[] memory node = new bytes32[](2);
        node[0] = wots_pkFromSig(sig,M,pk_seed,ADRS);
        ADRS.setType(ADDRSTypes.TREE);
        ADRS.setTreeIndex(bytes4(idx));
        for (uint k = 0; k < h/d; k++ ) {
            ADRS.setTreeHeight(bytes4(uint32(k+1)));

            uint divisor = 2 ** k;
            uint result = uint96(idx) / divisor;
            if ((result % 2) == 0) {
                ADRS.setTreeIndex(bytes4(uint32(ADRS.getTreeIndex()) / 2));
                node[1] = keccak256(abi.encodePacked(pk_seed, ADRS.toBytes32(), (abi.encodePacked(node[0],AUTH[k]))));
            }
            else{
                ADRS.setTreeIndex(bytes4((uint32(ADRS.getTreeIndex())-1) / 2));
                node[1] = keccak256(abi.encodePacked(pk_seed, ADRS.toBytes32(), (abi.encodePacked(AUTH[k],node[0]))));
            }
            node[0] = node[1];
        }
        return node[0];
    } 

    function wots_pkFromSig( bytes1[] memory sig, bytes32 M, bytes1[] memory pk_seed, ADDRS ADRS) public returns (bytes32){
        uint csum = 0;
        ADDRS wotspkADRS = copyADDRS(ADRS);
        bytes1[] memory output = new bytes1[](32); // bytes32 has 32 bytes

        for (uint i = 0; i < 32; i++) {
            output[i] = M[i];
        }

        bytes1[] memory _msg1 = base_w(output,w,len1);
        for (uint i = 0; i < len1; i++ ) {
            csum += w - 1 - uint8(_msg1[i]);
        }

        uint lg_w = log2(w);
        uint shiftAmount = 8 - ((len2 * lg_w) % 8);
        csum <<= shiftAmount;
        uint len_2_bytes = (len2 * lg_w + 7) / 8;
        bytes memory temp = abi.encodePacked(csum,len_2_bytes);
        output = new bytes1[](temp.length);
        for (uint i = 0; i < temp.length; i++) {
            output[i] = bytes1(temp[i]);
        }

        bytes1[] memory _msg2 = base_w(output, w, len2);
        bytes1[] memory _msg = new bytes1[](len1+len2);
        for (uint i=0; i < len1; i++){
            _msg[i] = _msg1[i];    
        }
        for (uint i=0; i < len2; i++){
            _msg[len1+i] = _msg2[i];
        }

        bytes32[] memory tmp = new bytes32[](len);
        for ( uint i = 0; i < len; i++ ) {
            ADRS.setChainAddress(bytes4(uint32(i)));
            tmp[i] = chain(sig[i], uint8(_msg[i]), w - 1 - uint8(_msg[i]), pk_seed, ADRS);
        }


        wotspkADRS.setType(ADDRSTypes.WOTS_PK);
        wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress());
        return keccak256(abi.encodePacked(pk_seed,wotspkADRS.toBytes32(),tmp));
    }

    function xmss_sign(bytes32 M, bytes1[] memory sk_seed, bytes12 idx, bytes1[] memory pk_seed, ADDRS ADRS) public returns (bytes memory){
        bytes32[] memory AUTH = new bytes32[](h/d);
        for ( uint j = 0; j < h/d; j++ ) {
            uint k = (uint96(idx)/(2**j)) ^ 1;
            AUTH[j] = treehash(sk_seed,k*(2**j),j,pk_seed,ADRS);
        }
        ADRS.setType(ADDRSTypes.WOTS_HASH);
        ADRS.setKeyPairAddress(bytes4(idx));
        return abi.encodePacked(wots_sign(M,sk_seed,pk_seed,ADRS),AUTH);
    }

    function wots_sign(bytes32 M, bytes1[] memory sk_seed, bytes1[] memory pk_seed, ADDRS ADRS) public returns(bytes32[] memory){
        uint csum = 0;
        bytes1[] memory output = new bytes1[](32); // bytes32 has 32 bytes

        for (uint i = 0; i < 32; i++) {
            output[i] = M[i];
        }

        bytes1[] memory _msg1 = base_w(output,w,len1);
        for (uint i = 0; i < len1; i++ ) {
            csum += w - 1 - uint8(_msg1[i]);
        }
        uint lgW = log2(w);
        if (lgW % 8 != 0) {
            uint shiftAmount = 8 - ((len2 * lgW) % 8);
            csum = csum << shiftAmount;
        }

        uint len_2_bytes = (len2 * log2(w) + 7) / 8; 
        bytes memory temp = abi.encodePacked(csum,len_2_bytes);
        output = new bytes1[](temp.length);
        for (uint i = 0; i < temp.length; i++) {
            output[i] = bytes1(temp[i]);
        }

        bytes1[] memory _msg2 = base_w(output, w, len2);

        bytes1[] memory _msg = new bytes1[](len1+len2);
        for (uint i=0; i < len1; i++){
            _msg[i] = _msg1[i];    
        }
        for (uint i=0; i < len2; i++){
            _msg[len1+i] = _msg2[i];
        }

        ADDRS skADRS = copyADDRS(ADRS);
        skADRS.setType(ADDRSTypes.WOTS_PRF);
        skADRS.setKeyPairAddress(ADRS.getKeyPairAddress());
        bytes32[] memory sig = new bytes32[](len);
        for (uint i = 0; i < len; i++ ) {
            skADRS.setChainAddress(bytes4(uint32(i)));
            skADRS.setHashAddress(0);
            bytes1[] memory sk = PRF(sk_seed, skADRS.toBytes32());
            bytes32 sk32;

            for (uint i = 0; i < sk.length; i++) {
                sk32 |= bytes32(sk[i] & 0xFF) >> (i * 8);
            }
            ADRS.setChainAddress(bytes4(uint32(i)));
            ADRS.setHashAddress(0);
            sig[i] = chain(sk32, 0, uint8(_msg[i]), pk_seed, ADRS);
        }
        return sig;
    }

    function base_w(bytes1[] memory X, uint w, uint out_len)public returns(bytes1[] memory){
        uint _in = 0;
        uint out = 0;
        bytes1 total = 0;
        uint bits = 0;
        uint consumed;
        bytes1[] memory basew = new bytes1[](out_len);
        for ( consumed = 0; consumed < out_len; consumed++ ) {
            if ( bits == 0 ) {
                total = X[_in];
                _in++;
                bits += 8;
            }
            bits -= log2(w);
            basew[out] = bytes1(uint8(((uint8(total)) >> uint8(bits)) & (w - 1)));
            out++;
        }
        return basew;
    }

    function sigfors_get_sk(bytes1[] memory sig, uint idx)public returns(bytes1[] memory){
        bytes1[] memory sk = new bytes1[](n);
        uint start_index = (n*a*idx)+(n*idx);
        for (uint i = start_index; i < start_index+n; i++){
            sk[i-start_index] = sig[i];
        }
        return sk;
    }

    function sigfors_get_auth(bytes1[] memory sig, uint idx)public returns(bytes1[] memory){
        bytes1[] memory auth = new bytes1[](n*a);
        uint start_index = (n*a*idx)+(n*idx) + n;
        for (uint i = start_index; i < start_index+n*a; i++){
            auth[i-start_index] = sig[i];
        }
        return auth;
    }

    function fors_pkFromSig(bytes1[] memory SIG_FORS, bytes1[] memory M, bytes1[] memory pk_seed, ADDRS addrs) public returns(bytes32){
        bytes32[] memory node = new bytes32[](2);
        bytes32[] memory root = new bytes32[](k);
        for (uint i = 0; i < k; i++) {
            uint idx = 0;
            uint endBit = (i + 1) * a - 1;
            for (uint bitPos = i * t; bitPos <= endBit; bitPos++) {
                uint bytePos = bitPos / 8;
                uint bitInByte = bitPos % 8;
                if ((uint8(M[bytePos]) & (1 << (7 - bitInByte))) != 0) {
                    idx |= 1 << (endBit - bitPos);
                }
            }
            bytes1[] memory sk = sigfors_get_sk(SIG_FORS,i);
            addrs.setTreeHeight(0);
            addrs.setTreeIndex(bytes4(uint32(i*t + idx)));
            node[0] = keccak256(abi.encodePacked(pk_seed,addrs.toBytes32(),sk));

            bytes1[] memory auth = sigfors_get_auth(SIG_FORS, i);
            addrs.setTreeIndex(bytes4(uint32(i*t + idx)));
            for (uint j = 0; j < a; j++ ) {
                addrs.setTreeHeight(bytes4(uint32(j+1)));
                if (((idx >> j) & 1) == 0) { // floor(idx / (2^j)) % 2) == 0
                    addrs.setTreeIndex(bytes4(uint32(addrs.getTreeIndex()) / 2));
                    node[1] = keccak256(abi.encodePacked(pk_seed, addrs.toBytes32(), (abi.encodePacked(node[0],auth[j]))));

                }else{
                    addrs.setTreeIndex(bytes4((uint32(addrs.getTreeIndex())-1) / 2));
                    node[1] = keccak256(abi.encodePacked(pk_seed, addrs.toBytes32(), (abi.encodePacked(auth[j],node[0]))));
                }
                node[0] = node[1];
            }
            root[i] = node[0];
        }
        ADDRS forspkADRS = copyADDRS(addrs);
        forspkADRS.setType(ADDRSTypes.FORS_ROOTS);
        forspkADRS.setKeyPairAddress((addrs.getKeyPairAddress()));
        return keccak256(abi.encodePacked(pk_seed,forspkADRS.toBytes32(),root));

    }

    function fors_sign(bytes1[] memory M,  bytes1[] memory sk_seed, bytes1[] memory pk_seed, ADDRS addrs)public returns(bytes1[] memory){
        bytes1[] memory SIG_FORS = new bytes1[](k*(a + 1)*n);
        uint sig_fors_byte_rn = 0;
        uint idx;
        for (uint i = 0; i < k; i++) {
            uint endBit = (i + 1) * a - 1;
            for (uint bitPos = i * t; bitPos <= endBit; bitPos++) {
                uint bytePos = bitPos / 8;
                uint bitInByte = bitPos % 8;
                if ((uint8(M[bytePos]) & (1 << (7 - bitInByte))) != 0) {
                    idx |= 1 << (endBit - bitPos);
                }
            }
            addrs.setTreeHeight(0);
            addrs.setTreeIndex(bytes4(uint32(i*t + idx)));
            bytes1[] memory p = PRF(sk_seed, addrs.toBytes32());
            for (uint j =0 ; j < p.length; j++){
                SIG_FORS[sig_fors_byte_rn] = p[j];
                sig_fors_byte_rn++;
            }
            bytes32[] memory AUTH = new bytes32[](a);
            for (uint j = 0; j < a; j++ ) {
                uint s = (idx / (2 ** j)) ^ 1;
               AUTH[j] = fors_treehash(sk_seed, i * k + s * 2^j, j, pk_seed, addrs);
            }
           
            for (uint j = 0; j< a ; j++){
                for (uint k =0; k < n; k++){
                    SIG_FORS[sig_fors_byte_rn] = AUTH[j][k];
                    sig_fors_byte_rn++;
                }
            }
        }
        return SIG_FORS;
    }

    function fors_treehash(bytes1[] memory sk_seed, uint s, uint z, bytes1[] memory pk_seed, ADDRS addrs) public returns(bytes32){
        if(s % (1 << z) != 0){
            return 0;
        }
        LinkedListStack stack = new LinkedListStack();
        StackEnty memory current = StackEnty(0,0);
        stack.push(current);
        current = StackEnty(0,0);
        for (uint i = 0; i < (2 ** z); i++) {
            addrs.setTreeHeight(0);
            addrs.setTreeIndex(bytes4(uint32(s + i)));
            bytes1[] memory sk = PRF(sk_seed, addrs.toBytes32());
            bytes32 node = keccak256(abi.encodePacked(sk_seed,addrs.toBytes32(),sk));
            addrs.setTreeHeight(bytes4(uint32(1)));
            addrs.setTreeIndex(bytes4(uint32(s + i)));
            while (stack.peek().height == uint32(addrs.getTreeHeight())){
                current = stack.pop();
                addrs.setTreeIndex(bytes4((uint32(addrs.getTreeIndex()) - 1) / 2));
                node = keccak256(abi.encodePacked(pk_seed,addrs.toBytes32(),(current.value | node)));
                addrs.setTreeHeight(bytes4(uint32(addrs.getTreeHeight())+1));
            }
            current.height = uint32(addrs.getTreeHeight());
            current.value = node;
            stack.push(current);
            current = StackEnty(0,0);
        }
        return stack.pop().value; 
    }

    function key_gen(bytes1[] memory sk_seed, bytes1[] memory sk_prf, bytes1[] memory pk_seed,bytes32 pk_root) public returns(bytes memory, bytes memory) {
        return ( abi.encodePacked(sk_seed, sk_prf, pk_seed, pk_root), abi.encodePacked(pk_seed, pk_root) );
    }

    function ht_PKgen(bytes1[] memory sk_seed, bytes1[] memory pk_seed) public returns (bytes32){
        ADDRS addrs = new ADDRS();
        addrs.setLayerAddress(bytes4(uint32(d-1)));
        addrs.setTreeAddress(0);
        return xmss_PKgen(sk_seed, pk_seed, addrs);
    }

    function xmss_PKgen(bytes1[] memory sk_seed, bytes1[] memory pk_seed, ADDRS addrs) public returns (bytes32){
        //h' : the height (number of levels - 1) of the tree
        //h' = h/d;
        return treehash(sk_seed,0,h/d,pk_seed,addrs);
    }



    function treehash(bytes1[] memory sk_seed, uint s, uint z,bytes1[] memory pk_seed, ADDRS addrs) public returns (bytes32){
        require(s % (1 << z) == 0, "Invalid start index");

        LinkedListStack stack = new LinkedListStack();
        StackEnty memory current = StackEnty(0,0);
        stack.push(current);
        current = StackEnty(0,0);

        for ( uint i = 0; i < 2**z; i++ ) {
            addrs.setType(ADDRSTypes.WOTS_HASH);
            addrs.setKeyPairAddress(bytes4(uint32(s + i)));
            bytes32 node = wots_PKgen(sk_seed,pk_seed,addrs);
            addrs.setType(ADDRSTypes.TREE);
            addrs.setTreeHeight(bytes4(uint32(1)));
            addrs.setTreeIndex(bytes4(uint32(s+i)));

            while (stack.peek().height == uint32(addrs.getTreeHeight())){
                current = stack.pop();
                addrs.setTreeIndex(bytes4((uint32(addrs.getTreeIndex()) - 1) / 2));
                node = keccak256(abi.encodePacked(pk_seed,addrs.toBytes32(),(current.value | node)));
                addrs.setTreeHeight(bytes4(uint32(addrs.getTreeHeight())+1));
            }
            current.height = uint32(addrs.getTreeHeight());
            current.value = node;
            stack.push(current);
            current = StackEnty(0,0);
        }
        return stack.pop().value; 
    }

    function wots_PKgen(bytes1[] memory sk_seed,bytes1[] memory pk_seed,ADDRS addrs) public returns (bytes32){
        ADDRS wotspkADRS = copyADDRS(addrs);
        bytes32[] memory tmp = new bytes32[](len);
        for (uint32 i =0; i < len; i++){
            addrs.setChainAddress(bytes4(i));
            //addrs.setHashAddress(0);//hashAdrs.setHashAddress(0); TO DO?
            bytes1[] memory sk = PRF(sk_seed, addrs.toBytes32());
            bytes32 result;
            for (uint8 i = 0; i < sk.length; i++) {
                result |= bytes32(sk[i] & 0xFF) >> (i * 8);
            }
            tmp[i] = chain(result, 0, w - 1, pk_seed, addrs);
        }
        wotspkADRS.setType(ADDRSTypes.WOTS_PK);
        wotspkADRS.setKeyPairAddress(addrs.getKeyPairAddress());
        return keccak256(abi.encodePacked(pk_seed,wotspkADRS.toBytes32(),tmp));

    }

    function chain(bytes32 X,uint i,uint s, bytes1[]memory pk_seed, ADDRS addrs) public returns (bytes32){
        if (s==0){
            return X;
        }
        if(i+s > w-1){
            return 0; // NULL
        }
        bytes32 tmp = chain(X, i, s - 1, pk_seed, addrs);
        addrs.setHashAddress(bytes4(uint32(i + s - 1)));
        return keccak256(abi.encodePacked(pk_seed,addrs,tmp));
    }


    function copyADDRS(ADDRS aa) public returns (ADDRS adr){
        adr = new ADDRS();
        adr.setLayerAddress(aa.getLayerAdress());
        adr.setTreeAddress(aa.getTreeAddress());
        adr.setType(aa.getType());
        adr.setData(aa.getData());
        return adr;
    }

    function h_msg(bytes1[] memory R, bytes1[] memory  pk_seed, bytes32 pk_root, string memory M) public returns(bytes1[] memory){
        require(R.length == pk_seed.length && pk_seed.length == 32,"Lengths do not match");
        uint tmp_md_len = (k * (a + 7)) / 8;
        uint tmp_idx_tree_len = (h - (h / d) + 7) / 8;
        uint tmp_idx_leaf_len = (h / d + 7) / 8;
        uint m = tmp_md_len + tmp_idx_leaf_len + tmp_idx_tree_len;
        bytes memory concatenated = abi.encodePacked(R, pk_seed, pk_root, M);
        bytes memory hashedConc = abi.encodePacked(keccak256(concatenated));
        return mgf1(hashedConc, m);
    }
    function mgf1(bytes memory seed, uint length) public pure returns (bytes1[] memory) {
        bytes1[] memory T = new bytes1[](length);
        uint counter = 0;

        for (uint i = 0; i < (length + 31) / 32; i++) {
            bytes32 C = keccak256(abi.encodePacked(seed, (counter)));
            for (uint j = 0; j < 32 && counter * 32 + j < length; j++) {
                T[counter * 32 + j] = C[j];
            }
            counter++;
        }

        return T;
    }


    function PRF(bytes1[] memory seed, bytes32 b32) public returns (bytes1[] memory){
        bytes1[] memory random = new bytes1[](seed.length);
        uint cnt = 0;
        for(uint i =0; i < seed.length;i+=32){
            bytes32 value = keccak256(abi.encodePacked(cnt,seed,b32));
            cnt++;
            for (uint j=0; j < 32 && i*32+j < seed.length; j++){
                random[i*32+j] = value[j];
            }
        }
        return random;
    }

    function PRF_msg(bytes1[] memory a, bytes1[] memory b, string memory c) public returns (bytes1[] memory){
        require(a.length == b.length, "first 2 arguments should have same size");
        bytes1[] memory random = new bytes1[](a.length);
        uint cnt = 0;
        for(uint i =0; i < a.length;i+=32){
            bytes32 value = keccak256(abi.encodePacked(cnt,a,b,c));
            cnt++;
            for (uint j=0; j < 32 && i*32+j < a.length; j++){
                random[i*32+j] = value[j];
            }
        }
        return random;

    }

    function NPRNG(uint bytes_amount) public returns (bytes1[] memory){
        bytes1[] memory random = new bytes1[](bytes_amount);
        for(uint i =0; i < bytes_amount;i+=32){
            bytes32 value = PRNG();
            for (uint j=0; j < 32 && i*32+j < bytes_amount; j++){
                random[i*32+j] = value[j];
            }
        }
        return random;
    }

    uint nonce = 0;
    function PRNG() private returns (bytes32) {
    nonce += 1;
    return
        keccak256(
            abi.encodePacked(nonce, msg.sender, blockhash(block.number - 1))
        );
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
                let m := mload(0x40)
                mstore(m,           0xf8f9cbfae6cc78fbefe7cdc3a1793dfcf4f0e8bbd8cec470b6a28a7a5a3e1efd)
                mstore(add(m,0x20), 0xf5ecf1b3e9debc68e1d9cfabc5997135bfb7a7a3938b7b606b5b4b3f2f1f0ffe)
                mstore(add(m,0x40), 0xf6e4ed9ff2d6b458eadcdf97bd91692de2d4da8fd2d0ac50c6ae9a8272523616)
                mstore(add(m,0x60), 0xc8c0b887b0a8a4489c948c7f847c6125746c645c544c444038302820181008ff)
                mstore(add(m,0x80), 0xf7cae577eec2a03cf3bad76fb589591debb2dd67e0aa9834bea6925f6a4a2e0e)
                mstore(add(m,0xa0), 0xe39ed557db96902cd38ed14fad815115c786af479b7e83247363534337271707)
                mstore(add(m,0xc0), 0xc976c13bb96e881cb166a933a55e490d9d56952b8d4e801485467d2362422606)
                mstore(add(m,0xe0), 0x753a6d1b65325d0c552a4d1345224105391a310b29122104190a110309020100)
                mstore(0x40, add(m, 0x100))
                let magic := 0x818283848586878898a8b8c8d8e8f929395969799a9b9d9e9faaeb6bedeeff
                let shift := 0x100000000000000000000000000000000000000000000000000000000000000
                let _a := div(mul(x, magic), shift)
                y := div(mload(add(m,sub(255,_a))), shift)
                y := add(y, mul(256, gt(arg, 0x8000000000000000000000000000000000000000000000000000000000000000)))
            }  
    }

}



