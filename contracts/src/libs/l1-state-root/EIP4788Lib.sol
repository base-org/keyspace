// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockLib} from "../BlockLib.sol";

library EIP4788Lib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The address of the contract used to fetch beacon roots from the oracle.
    address constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice The generalized index for the path "body -> execution_payload -> block_hash".
    uint256 constant EXECUTION_BLOCK_HASH_GINDEX = 6444;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the call to fetch the beacon root from the oracle fails.
    ///
    /// @param callData The calldata used in the failed staticcall to the beacon oracle.
    error BeaconRootsOracleCallFailed(bytes callData);

    /// @notice Thrown when the provided beacon root does not match the expected root fetched from the oracle.
    ///
    /// @param expected The expected beacon root.
    /// @param actual The actual beacon root fetched from the oracle.
    error BeaconRootDoesNotMatch(bytes32 expected, bytes32 actual);

    /// @notice Thrown when the Merkle proof for the execution block hash fails verification.
    error ExecutionBlockHashMerkleProofFailed();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice An L1 state root proof that relies on the `BeaconRoots` contract.
    struct EIP4788Proof {
        /// @dev The L1 block header to verify, encoded in RLP format.
        bytes l1BlockHeaderRlp;
        /// @dev The beacon root to verify.
        bytes32 beaconRoot;
        /// @dev The timestamp associated with the beacon root.
        uint256 beaconRootTimestamp;
        /// @dev The Merkle proof for the execution block hash.
        bytes32[] executionBlockHashProof;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Extracts the L1 state root from a serialized `EIP4788Proof`.
    ///
    /// @param proof The serialized proof data.
    ///
    /// @return l1StateRoot The L1 state root.
    function verify(bytes memory proof) internal view returns (bytes32 l1StateRoot) {
        // Decode the `EIP4788Proof` proof.
        EIP4788Proof memory eip4788Proof = abi.decode(proof, (EIP4788Proof));

        // Verify the beacon root against the oracle.
        _verifyBeaconRoot({beaconRoot: eip4788Proof.beaconRoot, beaconRootTimestamp: eip4788Proof.beaconRootTimestamp});

        // Parse the L1 block header from the provided RLP data.
        BlockLib.BlockHeader memory l1BlockHeader = BlockLib.parseBlockHeader(eip4788Proof.l1BlockHeaderRlp);

        // Verify the execution block hash using the provided proof.
        _verifyExecutionBlockHash({
            beaconRoot: eip4788Proof.beaconRoot,
            executionBlockHash: l1BlockHeader.hash,
            executionBlockHashProof: eip4788Proof.executionBlockHashProof
        });

        // Return the verified L1 state root.
        l1StateRoot = l1BlockHeader.stateRoot;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Verifies that a given beacon root matches the one fetched from the oracle for the specified timestamp.
    ///
    /// @param beaconRoot The beacon root to verify.
    /// @param beaconRootTimestamp The timestamp corresponding to the beacon root.
    function _verifyBeaconRoot(bytes32 beaconRoot, uint256 beaconRootTimestamp) private view {
        // Prepare the calldata for the staticcall to the beacon oracle.
        bytes memory calldata_ = abi.encode(beaconRootTimestamp);

        // Perform a staticcall to fetch the beacon root from the oracle.
        (bool success, bytes memory result) = BEACON_ROOTS_ADDRESS.staticcall(calldata_);
        require(success, BeaconRootsOracleCallFailed(calldata_));

        // Ensure the fetched root matches the provided beacon root.
        bytes32 resultRoot = abi.decode(result, (bytes32));
        require(resultRoot == beaconRoot, BeaconRootDoesNotMatch({expected: beaconRoot, actual: resultRoot}));
    }

    /// @notice Verifies the execution block hash against the beacon root using a Merkle proof.
    ///
    /// @param beaconRoot The beacon root that anchors the proof.
    /// @param executionBlockHash The execution block hash to verify.
    /// @param executionBlockHashProof The Merkle proof for the execution block hash.
    function _verifyExecutionBlockHash(
        bytes32 beaconRoot,
        bytes32 executionBlockHash,
        bytes32[] memory executionBlockHashProof
    ) private view {
        require(
            _verifyProof({
                proof: executionBlockHashProof,
                root: beaconRoot,
                leaf: executionBlockHash,
                index: EXECUTION_BLOCK_HASH_GINDEX
            }),
            ExecutionBlockHashMerkleProofFailed()
        );
    }

    /// @dev Implementation updated to work with a `memory` proof, taken from
    ///      https://github.com/madlabman/eip-4788-proof/blob/20ec51c3215214a3aa61e1281d4be90c48ede3c9/src/SSZ.sol#L247
    function _verifyProof(bytes32[] memory proof, bytes32 root, bytes32 leaf, uint256 index)
        private
        view
        returns (bool isValid)
    {
        // TODO: verify that the implementation is still valid given the changes made to work with an in memory proof.

        assembly ("memory-safe") {
            let proofLen := mload(proof)

            if proofLen {
                // Initialize `offset` to point to the first proof element in memory.
                let offset := add(proof, 0x20)
                // Left shift by 5 is equivalent to multiplying by 0x20.
                let end := add(offset, shl(5, proofLen))
                // Iterate over proof elements to compute root hash.
                for {} 1 {} {
                    // Slot of `leaf` in scratch space.
                    // If the condition is true: 0x20, otherwise: 0x00.
                    let scratch := shl(5, and(index, 1))
                    index := shr(1, index)
                    if iszero(index) {
                        // revert BranchHasExtraItem()
                        mstore(0x00, 0x5849603f)
                        revert(0x1c, 0x04)
                    }
                    // Store elements to hash contiguously in scratch space.
                    // Scratch space is 64 bytes (0x00 - 0x3f) and both elements are 32 bytes.
                    mstore(scratch, leaf)
                    mstore(xor(scratch, 0x20), mload(offset))
                    // Call sha256 precompile
                    let result := staticcall(gas(), 0x02, 0x00, 0x40, 0x00, 0x20)

                    if eq(result, 0) { revert(0, 0) }

                    // Reuse `leaf` to store the hash to reduce stack operations.
                    leaf := mload(0x00)
                    offset := add(offset, 0x20)
                    if iszero(lt(offset, end)) { break }
                }
            }

            // index != 1
            if gt(sub(index, 1), 0) {
                // revert BranchHasMissingItem()
                mstore(0x00, 0x1b6661c3)
                revert(0x1c, 0x04)
            }
            isValid := eq(leaf, root)
        }
    }
}
