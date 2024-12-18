// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

library BinaryMerkleTreeLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev A dynamic depth binary Merkle tree.
    struct Tree {
        /// @dev The depth of the tree.
        uint8 depth;
        /// @dev The number of nodes in the tree.
        uint256 nodeCount;
        /// @dev The tree nodes.
        mapping(uint256 depth => mapping(uint256 nodeIndex => bytes32 nodeHash)) nodes;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Computes the Merkle tree's root.
    ///
    /// @dev The root also includes the depth of the tree.
    ///
    /// @param tree A storage pointer to a `Tree`.
    ///
    /// @return The Merkle tree's root.
    function treeRoot(Tree storage tree) internal view returns (bytes32) {
        // Include the tree depth in the root.
        uint256 depth = tree.depth;
        return keccak256(abi.encodePacked(depth, tree.nodes[depth][0]));
    }

    /// @notice Commits to the given `dataHash` by inserting it into the provided Merkle tree.
    ///
    /// @param tree A storage pointer to a `Tree`.
    /// @param dataHash The hash of the data to be committed as a new leaf in the Merkle tree.
    function commitTo(Tree storage tree, bytes32 dataHash) internal {
        mapping(uint256 => mapping(uint256 => bytes32)) storage nodes = tree.nodes;

        // Insert the node in the tree at the base layer.
        uint256 index = tree.nodeCount;
        nodes[0][index] = dataHash;
        tree.nodeCount += 1;

        // Increase the tree depth if needed.
        uint256 maxNodeCount = _depthToMaxNodeCount(tree.depth);
        if (tree.nodeCount > maxNodeCount) {
            tree.depth += 1;
        }

        // Loop through the tree from the leaves (level 0) to the root and update sibling hashes.
        bytes32 currentHash = dataHash;
        for (uint256 level; level < tree.depth; level++) {
            bool isLeftNode = _isLeftNode(index);

            currentHash = isLeftNode
                ? keccak256(abi.encodePacked(currentHash, nodes[level][index + 1]))
                : keccak256(abi.encodePacked(nodes[level][index - 1], currentHash));

            index >>= 1;
            nodes[level + 1][index] = currentHash;
        }
    }

    /// @notice Verifies if a `dataHash` belongs to the tree with the given `root`.
    ///
    /// @param root The root of the tree.
    /// @param dataHash The data hash to verify.
    /// @param index The index of the leaf node in the tree.
    /// @param siblings The sibling nodes' hashes required for verification.
    ///
    /// @return True if the data hash is part of the tree, otherwise false.
    function isValid(bytes32 root, bytes32 dataHash, uint256 index, bytes32[] calldata siblings)
        internal
        pure
        returns (bool)
    {
        bytes32 currentHash = dataHash;
        uint256 depth = siblings.length;

        // Compute the Tree's root.
        for (uint256 level; level < depth; level++) {
            bool isLeftNode = _isLeftNode(index);

            currentHash = isLeftNode
                ? keccak256(abi.encodePacked(currentHash, siblings[level]))
                : keccak256(abi.encodePacked(siblings[level], currentHash));

            index >>= 1;
        }

        // Include the tree depth in the root.
        bytes32 recomputedRoot = keccak256(abi.encodePacked(depth, currentHash));

        return recomputedRoot == root;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev Determines whether a node index corresponds to a left child in the tree.
    ///
    /// @param index The index of the node.
    ///
    /// @return True if the node is a left child, otherwise false.
    function _isLeftNode(uint256 index) private pure returns (bool) {
        return (index % 2) == 0;
    }

    /// @dev Computes the maximum number of nodes a tree can hold for a given depth.
    ///
    /// @param depth_ The depth of the tree.
    ///
    /// @return The maximum number of nodes the tree can hold.
    function _depthToMaxNodeCount(uint8 depth_) private pure returns (uint256) {
        return 2 ** depth_;
    }
}
