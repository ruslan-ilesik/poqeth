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

    function toBytes()public view returns (bytes memory){
        return abi.encodePacked(layerAddress,treeAddress,adrsType,firstWord,secondWord,thirdWord,keyAndMask);
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

contract Xmss{
    uint expectedSigId = 0;

    struct PK{
        bytes32 root;
        bytes32 seed;
    }

    struct SIG{
        uint32 idxSig;
        bytes32 r;
        bytes32[] sigOts; 
        bytes32[] auth;
    }

    constructor(){}

    PK pk;

    function setPk(PK memory _pk) public{
        pk = _pk;
    }

    uint len1;
    uint len2;
    uint lengthAll;
    uint w;
    uint h;
    function verify(SIG calldata Sig, bytes32 M, uint _w, uint _h) public returns(bool){
        if (expectedSigId != Sig.idxSig){
            return false;
        }
        ADRS adrs = new ADRS();
        uint8 n = 32; // len(M) / 2
        h = _h;
        w = _w;
        (len1, len2, lengthAll) = computeLengths(n, w);
        //HMSG skipped to be able to do proper verefication
        //bytes memory M2 = Hmsg(abi.encodePacked(Sig.r,pk.root,toBytes(Sig.idxSig,n)),M,uint8(len1));

        bytes32 temp = xmssRootFromSig(Sig,M, adrs);

        //return true;
        return pk.root == temp;
    }

    function wotsPkFromSig(bytes32[] memory sig,bytes32 M, ADRS adrs)public returns(bytes32[] memory){
        uint csum = 0;
        bytes32[] memory msg = baseW(M,len1);
        for (uint i = 0; i < len1; i++ ) {
           csum = csum + w - 1 - uint(msg[i]);
        }
        csum = csum << ( 8 - ( ( len2 * log2(w) ) % 8 ));
        uint len2Bytes = ceil( ( len2 * log2(w) ), 8 );
        bytes32[] memory msg2 = baseW(toByte(csum, len2Bytes),len2);
        bytes32[] memory tmpPk = new bytes32[](lengthAll);
        for (uint i = 0; i < lengthAll; i++ ) {
          adrs.setChainAddress(uint32(i));
          if (i < len1){
            tmpPk[i] = chain(sig[i], uint(msg[i]), w - 1 - uint(msg[i]), adrs);
          }
          else{
            tmpPk[i] = chain(sig[i], uint(msg2[i-len1]), w - 1 - uint(msg2[i-len1]), adrs);
          }
        }
        return tmpPk;
    }

    function xmssRootFromSig(SIG calldata Sig,bytes32 M, ADRS adrs)public returns (bytes32){
        adrs.setType(0);   // Type = OTS hash address
        adrs.setOTSAddress(Sig.idxSig);
        bytes32[] memory pkOts = wotsPkFromSig(Sig.sigOts, M, adrs);
        adrs.setType(1);   // Type = L-tree address
        adrs.setLTreeAddress(Sig.idxSig);
        bytes32[2] memory node;
        node[0] = ltree(pkOts, adrs);
        //console.logBytes32(node[0]);
        adrs.setType(2);   // Type = hash tree address
        adrs.setTreeIndex(Sig.idxSig);
        for (uint k = 0; k < h; k++ ) {
            adrs.setTreeHeight(uint32(k));
            if ( ((Sig.idxSig / (2**k)) % 2) == 0 ) {
                adrs.setTreeIndex(uint32(adrs.getTreeIndex()) / 2);
                node[1] = randHash(node[0], Sig.auth[k], adrs);
            } 
            else {
                
                adrs.setTreeIndex((uint32(adrs.getTreeIndex()) - 1) / 2);
                node[1] = randHash(Sig.auth[k], node[0], adrs);
            }
            node[0] = node[1];
        }
        //console.logBytes32(node[0]);
        return node[0];
    }

    function ceil(uint a, uint b) internal pure returns (uint) {
        return (a + b - 1) / b;
    }

    function computeLengths(uint n, uint w) public pure returns (uint len1, uint len2, uint lenAll) {
        uint m = 32; // constant
        len1 = (m*8) / log2(w) + ((m*8) % log2(w) == 0 ? 0 : 1);
        len2 = log2(len1*(w-1))/log2(w);
        lenAll = len1 + len2;
    }

    function PRF(ADRS adrs) public returns(bytes32){
        return keccak256(abi.encodePacked(pk.seed,adrs.toBytes()));
    }

    function ltree(bytes32[] memory pk, ADRS addrs)public  returns (bytes32){
        uint len = lengthAll;
        addrs.setTreeHeight(0);
        while ( len > 1 ) {
            for ( uint i = 0; i < (len / 2); i++ ) {
                addrs.setTreeIndex(uint32(i));
                pk[i] = randHash(pk[2*i], pk[2*i + 1], addrs);
            }
            if ( len % 2 == 1 ) {
                pk[(len / 2)] = pk[len - 1];
            }
            len = ceil(len, 2);
            addrs.setTreeHeight(uint32(addrs.getTreeHeight()) + 1);
        }
        return pk[0];

    } 

    function randHash(bytes32 l, bytes32 r,ADRS adrs)public returns (bytes32){
        adrs.setKeyAndMask(0);
        bytes32 KEY = PRF(adrs);
        adrs.setKeyAndMask(1);
        bytes32 BM0 = PRF(adrs);
        adrs.setKeyAndMask(2);
        bytes32 BM1 = PRF(adrs);
        return keccak256(abi.encodePacked(KEY, (l ^ BM0), (r ^ BM1)));
    }  

   
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

    function toByte(uint256 x, uint y) public pure returns (bytes memory) {
        bytes memory b = new bytes(y);
        for (uint i = 0; i < y; i++) {
            b[i] = bytes1(uint8(x >> (8 * (y - 1 - i))));
        }
        return b;
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