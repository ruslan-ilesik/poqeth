// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


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


contract Sphincs_plus{
    uint n = 32;
    uint w = 16;
    uint h = 60;
    uint d = 10;
    uint k = 248;
    uint a = 8;
    uint t = 2 ** a;

    // Struct to represent the public key
    struct SPHINCS_PK {
        bytes32 seed;
        bytes32 root;
    }

    struct XMSS_SIG{
        bytes32[] sig;
        bytes32[] auth;
    }

    struct HT_SIG{
        XMSS_SIG[] sig;
    }

    struct FORS_SIG_INNER{
        bytes32 pk;
        bytes32[] auth;
    }

    struct FORS_SIG{
        FORS_SIG_INNER[] sig;
    }

    struct SPHINCS_SIG{
        bytes32 r;
        FORS_SIG fors_sig;
        HT_SIG ht_sig;
    }

    SPHINCS_PK pk;
    function set_pk(SPHINCS_PK memory p) public {
        pk = p;
    }

}