// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


enum ADDRSTypes{WOTS_HASH, WOTS_PK, TREE,
FORS_TREE, FORS_ROOTS,WOTS_PRF,FORS_PRF}

contract ADDRS{
    bytes4 layer_adress = 0;
    bytes12 tree_adress = 0;
    uint32 _type = 0;
    bytes1[12] data;

    function toBytes32() public view returns (bytes32 result) {
        // Concatenate each property into a bytes32 variable
        bytes memory temp = abi.encodePacked(layer_adress, tree_adress, _type);
        
        for (uint i = 0; i < 12; i++) {
            temp = abi.encodePacked(temp, data[i]);
        }
        
        // Convert the concatenated bytes to bytes32
        assembly {
            result := mload(add(temp, 32))
        }
    }



    function setTreeHeight(bytes4 height) public{
        require(_type == 2 || _type == 3, "Can not set TreeHeight  of address not of type 2,3");
        for (uint8 i=0; i < 4; i++){
            data[4+i] = height[i];
        }
    }

    function getTreeHeight() public returns (bytes4){
        return bytes4(
            uint32(uint8(data[4])) << 24 |
            uint32(uint8(data[5])) << 16 |
            uint32(uint8(data[6])) << 8 |
            uint32(uint8(data[7]))
        );
    }


    function setTreeIndex(bytes4 hashAddress) public {
        require(_type == 2 || _type == 3, "Can not set TreeIndex of address not of type 2,3");
        for (uint8 i=0; i < 4; i++){
            data[8+i] = hashAddress[i];
        }
    }

    function getTreeIndex() public view returns (bytes4) {
        require(_type == 2 || _type == 3, "Can not get TreeIndex of address not of type 2,3");
        return bytes4(
            uint32(uint8(data[8])) << 24 |
            uint32(uint8(data[9])) << 16 |
            uint32(uint8(data[10])) << 8 |
            uint32(uint8(data[11]))
        );
    }


    function setData(bytes1[12] memory d) public {
        for (uint8 i = 0; i < 12; i++) {
           data[i] = d[i];
        }
    }

    function getData() public view returns(bytes1[12] memory){
        bytes1[12] memory temp;
        for (uint8 i = 0; i < 12; i++) {
            temp[i] = data[i];
        }
        return temp;
    }

    function setLayerAddress(bytes4 adr) public{
        layer_adress = adr;
    }

    function getLayerAdress() public view returns (bytes4){
        return layer_adress;
    }

    function setTreeAddress(bytes12 adr) public {
        tree_adress = adr;
    }

    function getTreeAddress() public view returns (bytes12) {
        return tree_adress;
    }

    function setType(uint32 t) public {
        _type = t;
    }

    function setType(ADDRSTypes t) public {
        _type = uint32(uint(t));
        if (t == ADDRSTypes.WOTS_PK){
            for (uint i =3; i < 12; i++){
                data[i] = 0;
            }
        }

        if (t == ADDRSTypes.TREE){
             for (uint i =0; i < 4; i++){
                data[i] = 0;
            }
        }

        if (t == ADDRSTypes.FORS_PRF){
             for (uint i =0; i < 4; i++){
                data[i+4] = 0;
            }
        }

         if (t == ADDRSTypes.WOTS_PRF){
             for (uint i =0; i < 4; i++){
                data[i+8] = 0;
            }
        }
    }

    function getType() public view returns (uint32) {
        return _type;
    }

    function getKeyPairAddress() public returns (bytes4) {
        require(_type == 0 || _type == 1|| _type == 3 || _type == 4||  _type == 5, "Can not get pair address of address not of type 0,1,3,4,5");
        return bytes4(
            uint32(uint8(data[0])) << 24 |
            uint32(uint8(data[1])) << 16 |
            uint32(uint8(data[2])) << 8 |
            uint32(uint8(data[3]))
        );
    }

    function getChainAddress() public view returns (bytes4) {
        require(_type == 0|| _type == 5, "Can not get chain address of address not of type 0,5");
        return bytes4(
            uint32(uint8(data[4])) << 24 |
            uint32(uint8(data[5])) << 16 |
            uint32(uint8(data[6])) << 8 |
            uint32(uint8(data[7]))
        );
    }

    function getHashAddress() public view returns (bytes4) {
        require(_type == 0 || _type == 5, "Can not get hash address of address not of type 0,5");
        return bytes4(
            uint32(uint8(data[8])) << 24 |
            uint32(uint8(data[9])) << 16 |
            uint32(uint8(data[10])) << 8 |
            uint32(uint8(data[11]))
        );
    }


    // Function to set the first 4 bytes of data
    function setKeyPairAddress(bytes4 pairAddress) public {
        require(_type == 0 || _type == 1 || _type == 3 || _type == 4 ||  _type == 5, "Can not set pair address of address not of type 0,1,3,4,5");
        for (uint8 i=0; i < 4; i++){
            data[i] = pairAddress[i];
        }
        
    }
    // Function to set the second 4 bytes of data
    function setChainAddress(bytes4 chainAddress) public {
        require(_type == 0 || _type == 5, "Can not set chain address of address not of type 0,5");
        for (uint8 i=0; i < 4; i++){
            data[4+i] = chainAddress[i];
        }
    }

    // Function to set the third 4 bytes of data
    function setHashAddress(bytes4 hashAddress) public {
        require(_type == 0 || _type == 5, "Can not set hash address of address not of type 0,5");
        for (uint8 i=0; i < 4; i++){
            data[8+i] = hashAddress[i];
        }
    }
}


struct SIG{
    bytes1[] randomness;
    bytes1[] sig_fors;
    bytes1[] sig_ht;

}

contract Sphincs_plus{
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
    bytes PK;

    //getXMSSSignature - 512 bytes each

    function set_pk(bytes memory pk) public{
        PK = pk;
    }

    function spx_verify(string memory M, SIG calldata sig) public returns(bool){
        len1 = (n) / log2(w) + ((n) % log2(w) == 0 ? 0 : 1);
        len2 = (log2(len1 * (w - 1)) / log2(w)) + 1;
        len = len1 + len2;

        ADDRS ADRS = new ADDRS();
        bytes1[] memory R = sig.randomness;
        bytes1[] memory  SIG_FORS = sig.sig_fors;
        bytes1[] memory  SIG_HT = sig.sig_ht;
        bytes1[] memory digest = h_msg(R, M);
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
        ADRS.setLayerAddress(0);
        ADRS.setTreeAddress(idx_tree);
        ADRS.setType(ADDRSTypes.FORS_TREE);
        ADRS.setKeyPairAddress(idx_leaf);

        bytes1[] memory pk_seed = new bytes1[](n);
        for (uint i=0; i < n; i++){
            pk_seed[i] = PK[i];
        }

        bytes32 pk_root;
        for (uint i = 0; i < n; i++) {
            pk_root |= bytes32(PK[n + i] & 0xFF) >> (i * 8);
        }


        bytes32 PK_FORS = fors_pkFromSig(SIG_FORS, md, pk_seed, ADRS);
        ADRS.setType(ADDRSTypes.TREE);
        return ht_verify(PK_FORS, SIG_HT, pk_seed, idx_tree, idx_leaf, pk_root);
    }

    function ht_verify(bytes32 M, bytes1[] memory SIG_HT, bytes1[] memory pk_seed, bytes12 idx_tree, bytes4 idx_leaf, bytes32 PK_HT) public returns (bool){
        ADDRS ADRS = new ADDRS();
        bytes1[] memory SIG_tmp = getXMSSSignature(SIG_HT,0);
        ADRS.setLayerAddress(0);
        ADRS.setTreeAddress(idx_tree);
        bytes32 node = xmss_pkFromSig(idx_leaf, SIG_tmp, M, pk_seed, ADRS);
        for (uint j=1; j < d; j++){
            idx_leaf = bytes4(extractBits(idx_tree, 0, h / d));
            idx_tree = bytes12(extractBits(idx_tree, h / d, h - (j + 1) * (h / d)));
            ADRS.setLayerAddress(bytes4(uint32(j)));
            ADRS.setTreeAddress(idx_tree);
            node = xmss_pkFromSig(idx_leaf, SIG_tmp, node, pk_seed, ADRS);
        }

        return node == PK_HT;
    }


    function getXMSSSignature(bytes1[] memory  SIG_HT, uint indx)public  returns (bytes1[] memory){
        uint sig_size = 512;
        uint start_index = sig_size * indx;
        bytes1[] memory res = new bytes1[](sig_size);
        for (uint i = start_index; i < start_index+sig_size; i++){
            res[i-start_index] = SIG_HT[i];
        }
        return res;
    }

    
    function extractBits(bytes12 input, uint startBit, uint length) internal pure returns (bytes12) {
        uint96 mask = (uint96(1) << length) - 1;
        uint96 extractedBits = (uint96(input) >> startBit) & mask;
        return bytes12(extractedBits);
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

    function copyADDRS(ADDRS aa) public returns (ADDRS adr){
        adr = new ADDRS();
        adr.setLayerAddress(aa.getLayerAdress());
        adr.setTreeAddress(aa.getTreeAddress());
        adr.setType(aa.getType());
        adr.setData(aa.getData());
        return adr;
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

    function h_msg(bytes1[] memory R, string memory M) public returns(bytes1[] memory){
        uint tmp_md_len = (k * (a + 7)) / 8;
        uint tmp_idx_tree_len = (h - (h / d) + 7) / 8;
        uint tmp_idx_leaf_len = (h / d + 7) / 8;
        uint m = tmp_md_len + tmp_idx_leaf_len + tmp_idx_tree_len;
        bytes memory concatenated = abi.encodePacked(R, PK, M);
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

     function xmss_pkFromSig(bytes12 idx,  bytes1[] memory SIG_XMSS, bytes32 M, bytes1[] memory pk_seed, ADDRS ADRS) public returns (bytes32){
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