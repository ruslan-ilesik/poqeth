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

    bytes4 public keyAndMask;

    constructor() {
        layerAddress = bytes4(0);
        treeAddress = bytes8(0);
        adrsType = bytes4(0);

        firstWord = bytes4(0);
        secondWord = bytes4(0);
        thirdWord = bytes4(0);

        keyAndMask = bytes4(0);
    }

    function setType(uint32 typeValue) public {
        adrsType = bytes4(typeValue);
        firstWord = bytes4(0);
        secondWord = bytes4(0);
        thirdWord = bytes4(0);
        keyAndMask = bytes4(0);
    }

    function getTreeHeight() public view returns (bytes4) {
        return secondWord;
    }

    function getTreeIndex() public view returns (bytes4) {
        return thirdWord;
    }

    function setHashAddress(uint32 value) public {
        thirdWord = bytes4(value);
    }

    function setKeyAndMask(uint32 value) public {
        keyAndMask = bytes4(value);
    }

    function setChainAddress(uint32 value) public {
        secondWord = bytes4(value);
    }

    function setTreeHeight(uint32 value) public {
        secondWord = bytes4(value);
    }

    function setTreeIndex(uint32 value) public {
        thirdWord = bytes4(value);
    }

    function setOTSAddress(uint32 value) public {
        firstWord = bytes4(value);
    }

    function setLTreeAddress(uint32 value) public {
        firstWord = bytes4(value);
    }

    function setLayerAddress(uint32 value) public {
        layerAddress = bytes4(value);
    }

    function setTreeAddress(uint64 value) public {
        treeAddress = bytes8(value);
    }
}

contract XMSS{
    struct PK{
        string OID;
        bytes32 root;
        bytes16 n;
    }

    struct SIG{
        uint32 idx_sig;
        bytes32 r;
        bytes32[] sig_ots; 
        bytes32[] auth;
    }

    constructor(){}

    PK pk;

    function set_pk(PK memory _pk) public{
        pk = _pk;
    }


    function verify(SIG calldata Sig, bytes32 M, uint8 w) public returns(bool){
        ADRS _address = new ADRS();
        uint8 n = 32/2 ; // len(M) / 2
        uint len_1;
        uint len_2;
        uint length_all;
        (len_1, len_2, length_all) = compute_lengths(n, w);
        //bytes memory M2 = H_msg(abi.encodePacked(Sig.r,pk.root,toBytes(Sig.idx_sig,n)),M,uint8(len_1));
        //bytes32 node = XMSS_rootFromSig(idx_sig, sig_ots, auth, M2, getSEED(PK), ADRS);
        //console.log(M2);
    }

    function ceil_div(uint a, uint b) internal pure returns (uint) {
        return (a + b - 1) / b;
    }

    function compute_lengths(uint n, uint w) public pure returns (uint len_1, uint len_2, uint len_all) {
        uint log_w = log2(w);
        len_1 = ceil_div(8 * n, log_w);
        len_2 = (log2(len_1 * (w - 1)) + log_w - 1) / log_w + 1;
        len_all = len_1 + len_2;
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

}