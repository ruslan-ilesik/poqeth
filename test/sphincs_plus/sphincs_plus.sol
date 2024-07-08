pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";
import {LinkedListStack, StackEnty} from "./LinkedListStack.sol";

enum ADDRSTypes{WOTS_HASH, WOTS_PK, TREE,
FORS_TREE, FORS_ROOTS}

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
        require(_type == 2, "Can not set TreeHeight  of address not of type 2");
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
        require(_type == 2, "Can not set TreeIndex of address not of type 2");
        for (uint8 i=0; i < 4; i++){
            data[8+i] = hashAddress[i];
        }
    }

    function getTreeIndex() public view returns (bytes4) {
        require(_type == 2, "Can not get TreeIndex of address not of type 2");
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

    function setLayerAdress(bytes4 adr) public{
        layer_adress = adr;
    }

    function getLayerAdress() public view returns (bytes4){
        return layer_adress;
    }

    function setTreeAdress(bytes12 adr) public {
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
    }

    function getType() public view returns (uint32) {
        return _type;
    }

    function getKeyPairAddress() public returns (bytes4) {
        require(_type == 0 || _type == 1, "Can not get pair address of address not of type 0,1");
        return bytes4(
            uint32(uint8(data[0])) << 24 |
            uint32(uint8(data[1])) << 16 |
            uint32(uint8(data[2])) << 8 |
            uint32(uint8(data[3]))
        );
    }

    function getChainAddress() public view returns (bytes4) {
        require(_type == 0, "Can not get chain address of address not of type 0");
        return bytes4(
            uint32(uint8(data[4])) << 24 |
            uint32(uint8(data[5])) << 16 |
            uint32(uint8(data[6])) << 8 |
            uint32(uint8(data[7]))
        );
    }

    function getHashAddress() public view returns (bytes4) {
        require(_type == 0, "Can not get hash address of address not of type 0");
        return bytes4(
            uint32(uint8(data[8])) << 24 |
            uint32(uint8(data[9])) << 16 |
            uint32(uint8(data[10])) << 8 |
            uint32(uint8(data[11]))
        );
    }


    // Function to set the first 4 bytes of data
    function setKeyPairAddress(bytes4 pairAddress) public {
        require(_type == 0 || _type == 1, "Can not set pair address of address not of type 0,1");
        for (uint8 i=0; i < 4; i++){
            data[i] = pairAddress[i];
        }
        
    }
    // Function to set the second 4 bytes of data
    function setChainAddress(bytes4 chainAddress) public {
        require(_type == 0, "Can not set chain address of address not of type 0");
        for (uint8 i=0; i < 4; i++){
            data[4+i] = chainAddress[i];
        }
    }

    // Function to set the third 4 bytes of data
    function setHashAddress(bytes4 hashAddress) public {
        require(_type == 0, "Can not set hash address of address not of type 0");
        for (uint8 i=0; i < 4; i++){
            data[8+i] = hashAddress[i];
        }
    }
}



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

    function test_sphincs_plus() public{
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
        bytes memory SK;
        bytes memory PK;
        (SK,PK) = key_gen();

        

    }
    function key_gen() public returns(bytes memory, bytes memory) {
        bytes1[] memory sk_seed = NPRNG(n);
        bytes1[] memory sk_prf = NPRNG(n);
        bytes1[] memory pk_seed = NPRNG(n);
        bytes32 pk_root = ht_PKgen(sk_seed,pk_seed);
        return ( abi.encodePacked(sk_seed, sk_prf, pk_seed, pk_root), abi.encodePacked(pk_seed, pk_root) );
    }

    function ht_PKgen(bytes1[] memory sk_seed, bytes1[] memory pk_seed) public returns (bytes32){
        ADDRS addrs = new ADDRS();
        addrs.setLayerAdress(bytes4(uint32(d-1)));
        addrs.setTreeAdress(0);
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
        adr.setLayerAdress(aa.getLayerAdress());
        adr.setTreeAdress(aa.getTreeAddress());
        adr.setType(aa.getType());
        adr.setData(aa.getData());
        return adr;
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



