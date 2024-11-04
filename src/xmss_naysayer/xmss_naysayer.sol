// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "forge-std/console.sol";
import "../merkle_tree.sol";

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

    function toBytes() public view returns (bytes memory) {
        return abi.encodePacked(layerAddress, treeAddress, adrsType, firstWord, secondWord, thirdWord, keyAndMask);
    }

    function fillFrom(ADRS adrs) public {
        layerAddress = adrs.getLayerAddress();
        treeAddress = adrs.getTreeAddress();
        adrsType = adrs.getType();

        firstWord = adrs.getKeyPairAddress();
        secondWord = adrs.getTreeHeight();
        thirdWord = adrs.getTreeIndex();
    }

    function setType(uint32 typeValue) public {
        adrsType = bytes4(typeValue);
        firstWord = bytes4(0);
        secondWord = bytes4(0);
        thirdWord = bytes4(0);
        keyAndMask = bytes4(0);
    }

    function getLayerAddress() public view returns (bytes4) {
        return layerAddress;
    }

    function getType() public view returns (bytes4) {
        return adrsType;
    }

    function getTreeAddress() public view returns (bytes8) {
        return treeAddress;
    }

    function getKeyPairAddress() public view returns (bytes4) {
        return firstWord;
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


contract XMSSNaysayer is MerkleTree{
    struct PK {
        bytes32 root;
        bytes32 seed;
    }

    struct SIG {
        uint32 idxSig;
        bytes32 r;
        bytes32[] sigOts; 
        bytes32[] auth;
    }

    constructor() {}

    PK public pk;

    function setPk(PK memory _pk) public {
        pk = _pk;
    }

    uint16 public len1;
    uint16 public len2;
    uint16 public lengthAll;
    uint8 public w = 4;
    uint8 public h;
    bytes32 public sig;
    uint32 public idxSig;
    bytes32 public r;
    bytes32 public M;

    uint public xmssAuthLength;
    uint public wotsSigLength;
    uint public wotsPkLength;

    function setSigFromVar(
        bytes32[] memory wotsPkHash,
        bytes32[] memory auth,
        bytes32[] memory sigOts,
        bytes32[] memory wotsPk,
        bytes32[] memory htAdditionalNodes,
        uint32 _idxSig,
        bytes32 _r,
        uint8 _h,
        bytes32 _M
    ) public {
        idxSig = _idxSig;
        r = _r;
        h = _h;
        M = _M;
        xmssAuthLength = auth.length;
        wotsSigLength = sigOts.length;
        wotsPkLength = wotsPk.length;
        bytes32[] memory sigFull = concatenateBytes32Arrays([wotsPkHash, auth, sigOts, wotsPk, htAdditionalNodes]);
        bytes32 root = buildRoot(sigFull);
        sig = root;
    }
    
    function setArgs(uint8 _w, uint8 _h) public {
        w = _w;
        h = _h;
    }

    function concatenateBytes32Arrays(bytes32[][5] memory arrays) public pure returns (bytes32[] memory) {
        uint256 totalLength = 0;
        for (uint256 i = 0; i < arrays.length; i++) {
            totalLength += arrays[i].length;
        }

        bytes32[] memory result = new bytes32[](totalLength);
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

    function setSig(
        bytes32 _sig,
        uint32 _idxSig,
        bytes32 _r,
        uint8 _h,
        bytes32 _M,
        uint xmssAuthL,
        uint wotsSigL,
        uint wotsPkL
    ) public {
        sig = _sig;
        idxSig = _idxSig;
        r = _r;
        h = _h;
        M = _M;
        xmssAuthLength = xmssAuthL;
        wotsSigLength = wotsSigL;
        wotsPkLength = wotsPkL;
    }

    function naysayerHT(
        uint topNodeInd,
        bytes32 topNode,
        bytes32[] memory topNodeProof,
        bytes32 bottomNode,
        bytes32[] memory bottomNodeProof,
        bytes32 authNode,
        bytes32[] memory authNodeProof
    ) public returns (bool) {
        if (!verifyProof(sig, topNode, topNodeProof, 1 + xmssAuthLength + wotsSigLength + wotsPkLength + topNodeInd) ||
            !verifyProof(sig, bottomNode, bottomNodeProof, 1 + xmssAuthLength + wotsSigLength + wotsPkLength + topNodeInd - 1) ||
            !verifyProof(sig, authNode, authNodeProof, 1 + topNodeInd - 1)) {
            return false;
        }

        ADRS adrs = new ADRS();
        adrs.setType(2);   // Type = hash tree address
        adrs.setTreeIndex(idxSig);
        adrs.setTreeHeight(uint32(topNodeInd - 1));
        
        for (uint k = 0; k < topNodeInd - 1; k++) {
            if ((idxSig / (2 ** k)) % 2 == 0) {
                adrs.setTreeIndex(uint32(adrs.getTreeIndex()) / 2);
            } else {
                adrs.setTreeIndex((uint32(adrs.getTreeIndex()) - 1) / 2);
            }
        }
        
        uint k = topNodeInd - 1;
        bytes32 hashed;
        
        if ((idxSig / (2 ** k)) % 2 == 0) {
            adrs.setTreeIndex(uint32(adrs.getTreeIndex()) / 2);
            hashed = randHash(bottomNode, authNode, adrs);
        } else {
            adrs.setTreeIndex((uint32(adrs.getTreeIndex()) - 1) / 2);
            hashed = randHash(authNode, bottomNode, adrs);
        }
        
        return topNode != hashed;
    }

    function naysayerLTree(
        bytes32[] memory wotsPk,
        bytes32[] memory wotsPkProof,
        bytes32 lTreeResult,
        bytes32[] memory lTreeResultProof
    ) public returns (bool) {
        bytes32 wotsHash = keccak256(abi.encodePacked(wotsPk));
        
        if (!verifyProof(sig, wotsHash, wotsPkProof, 0) ||
            !verifyProof(sig, lTreeResult, lTreeResultProof, 1 + xmssAuthLength + wotsSigLength + wotsPkLength)) {
            return false;
        }
        
        uint8 n = 32; 
        (len1, len2, lengthAll) = computeLengths(n, w);
        ADRS adrs = new ADRS();
        adrs.setType(1);   // Type = L-tree address
        adrs.setLTreeAddress(idxSig);
        
        bytes32 node = lTree(wotsPk, adrs);
        return node != lTreeResult;
    }

    function naysayerWots(
        uint wotsSigInd,
        bytes32 wotsSigElem,
        bytes32[] memory wotsSigProof,
        bytes32 wotsPkElem,
        bytes32[] memory wotsPkProof
    ) public returns (bool) {
        if (!verifyProof(sig, wotsSigElem, wotsSigProof, 1 + xmssAuthLength + wotsSigInd) ||
            !verifyProof(sig, wotsPkElem, wotsPkProof, 1 + xmssAuthLength + wotsSigLength + wotsSigInd)) {
            return false;
        }

        uint8 n = 32; 
        uint len1;
        uint len2;
        uint lengthAll;
        
        (len1, len2, lengthAll) = computeLengths(n, w);
        ADRS adrs = new ADRS();
        adrs.setType(0);   // Type = OTS hash address
        adrs.setOTSAddress(uint32(idxSig));

        uint csum = 0;
        bytes1[] memory msg1 = baseW(M, len1);
        
        for (uint i = 0; i < len1; i++) {
            csum = csum + w - 1 - uint8(msg1[i]);
        }
        
        csum = csum << (8 - ((len2 * log2(w)) % 8));
        uint len2Bytes = ceil((len2 * log2(w)), 8);
        bytes1[] memory msg2 = baseW(toByte(csum, len2Bytes), len2);
        
        uint i = wotsSigInd;
        adrs.setChainAddress(uint32(i));
        
        bytes32 root;
        
        if (i < len1) {
            root = chain(wotsSigElem, uint(uint8(msg1[i])), w - 1 - uint(uint8(msg1[i])), adrs);
        } else {
            root = chain(wotsSigElem, uint(uint8(msg2[i - len1])), w - 1 - uint(uint8(msg2[i - len1])), adrs);
        }

        return root != wotsPkElem;
    }

    function lTree(bytes32[] memory pk, ADRS addrs) public returns (bytes32) {
        uint len = lengthAll;
        addrs.setTreeHeight(0);
        
        while (len > 1) {
            for (uint i = 0; i < (len / 2); i++) {
                addrs.setTreeIndex(uint32(i));
                pk[i] = randHash(pk[2 * i], pk[2 * i + 1], addrs);
            }
            
            if (len % 2 == 1) {
                pk[len / 2] = pk[len - 1];
            }
            
            len = ceil(len, 2);
            addrs.setTreeHeight(uint32(addrs.getTreeHeight()) + 1);
        }
        
        return pk[0];
    }


   function randHash(bytes32 left, bytes32 right, ADRS adrs) public returns (bytes32) {
    adrs.setKeyAndMask(0);
    bytes32 key = PRF(adrs);
    adrs.setKeyAndMask(1);
    bytes32 bm0 = PRF(adrs);
    adrs.setKeyAndMask(2);
    bytes32 bm1 = PRF(adrs);
    return keccak256(abi.encodePacked(key, (left ^ bm0), (right ^ bm1)));
}

    function ceil(uint a, uint b) internal pure returns (uint) {
        return (a + b - 1) / b;
    }

    function baseW(bytes32 x, uint outLen) public view returns (bytes1[] memory) {
        uint inputIndex = 0;
        uint outputIndex = 0;
        uint8 total = 0;
        uint bits = 0;
        uint consumed;
        bytes1[] memory baseWArray = new bytes1[](outLen);

        for (consumed = 0; consumed < outLen; consumed++) {
            if (bits == 0) {
                total = uint8(x[inputIndex]);
                inputIndex++;
                bits += 8;
            }
            bits -= log2(w);
            baseWArray[outputIndex] = bytes1(uint8((total >> bits) & (w - 1)));
            outputIndex++;
        }

        return baseWArray;
    }

    function PRF(ADRS adrs) public view returns (bytes32) {
        return keccak256(abi.encodePacked(pk.seed, adrs.toBytes()));
    }

    function chain(bytes32 x, uint i, uint s, ADRS adrs) public returns (bytes32) {
        if ((i + s) > (w - 1)) {
            return 0;
        }

        bytes32 tmp = x;

        for (uint k = 0; k < s; k++) {
            adrs.setHashAddress(uint32(i + k));
            adrs.setKeyAndMask(0);
            bytes32 key = PRF(adrs);
            adrs.setKeyAndMask(1);
            bytes32 bm = PRF(adrs);
            tmp = keccak256(abi.encodePacked(key, tmp ^ bm));
        }

        return tmp;
    }

    function computeLengths(uint8 n, uint8 w) public pure returns (uint16 len1, uint16 len2, uint16 lenAll) {
        uint16 m = 32; // constant
        len1 = (m * 8) / uint16(log2(w)) + ((m * 8) % uint16(log2(w)) == 0 ? 0 : 1);
        len2 = uint16(log2(len1 * (w - 1)) / log2(w));
        lenAll = len1 + len2;
    }

    function baseW(bytes memory x, uint outLen) public view returns (bytes1[] memory) {
        uint inputIndex = 0;
        uint outputIndex = 0;
        uint8 total = 0;
        uint bits = 0;
        uint consumed;
        bytes1[] memory baseWArray = new bytes1[](outLen);

        for (consumed = 0; consumed < outLen; consumed++) {
            if (bits == 0) {
                total = uint8(x[inputIndex]);
                inputIndex++;
                bits += 8;
            }
            bits -= log2(w);
            baseWArray[outputIndex] = bytes1(uint8((total >> bits) & (w - 1)));
            outputIndex++;
        }

        return baseWArray;
    }

    function toByte(uint256 x, uint y) public pure returns (bytes memory) {
        bytes memory byteArray = new bytes(y);
        for (uint i = 0; i < y; i++) {
            byteArray[i] = bytes1(uint8(x >> (8 * (y - 1 - i))));
        }
        return byteArray;
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