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
    bytes PK;

    function set_pk(bytes memory pk) public{
        PK = pk;
    }

    function spx_verify(string memory M, SIG calldata sig) public{
    }
}