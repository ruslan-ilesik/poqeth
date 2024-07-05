//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.26;

// @notice Stack implementation in Solidity via linked list
// @author deor (https://github.com/d3or)
struct StackEnty{
        bytes32 value;
        uint32 height;


}
contract LinkedListStack {

    function toBytes(StackEnty memory m) public returns (bytes memory){
        return abi.encodePacked(m.value,m.height);
    }
    /* 
        State 
    */
    struct Node {
        StackEnty value;
        bytes32 next;
    }   

    mapping (bytes32 => Node) nodes; // 

    Node Top; // The top of the stack

    constructor() {
        Top = Node(StackEnty(0,0),0); // top is initialized as 0,0 to indicate an empty stack
    }

    /* 
        Functions
    */
    function push(StackEnty memory value) public {
        Node memory node;
        node.value = value;

        if (Top.next == 0) {
            // some value other than 0 is used to indicate that stack is not empty.
            node.next = keccak256("top");
            Top = node;
        }  else {
            Node storage OldTop = Top;
            node.next = keccak256(
                abi.encodePacked(
                    toBytes(OldTop.value),
                    OldTop.next,
                    block.timestamp
                )
            );
            nodes[node.next] = OldTop;
            Top = node;
        }
    }

    function pop() public returns (StackEnty memory) {
        require(Top.next != 0, "Stack is empty");
        
        Node storage oldTop = Top;
        StackEnty memory oldValue = Top.value;

        Top = nodes[oldTop.next];
        return oldValue;
    }

    function clear() public {
        Top = Node(StackEnty(0,0),0);
    }

    /* 
        View Functions 
    */
    function peek() public view returns (StackEnty memory) {
        require(Top.next != 0, "Stack is empty");
        return Top.value;
    }

    function isEmpty() public view returns (bool) {
        return Top.next == 0;
    }

    function size() public view returns (uint256) {
        uint256 sizeCount = 0;
        Node storage node = Top;
        while (node.next != 0) {
            sizeCount++;
            node = nodes[node.next];
        }
        return sizeCount;
    }
}