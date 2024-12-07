// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockLib} from "../BlockLib.sol";
import {StorageProofLib} from "../StorageProofLib.sol";

library L1BlockLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Address of the L1Block oracle on OP Stack chains.
    address constant L1BLOCK_PREDEPLOY_ADDRESS = 0x4200000000000000000000000000000000000015;

    /// @notice Storage slot where the L1 block hash is stored on the L1Block oracle.
    bytes32 constant L1BLOCK_HASH_SLOT = bytes32(uint256(2));

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the L2 block header hash does not match the hash retrieved using `blockhash`.
    ///
    /// @param blockHeaderHash The hash of the L2 block header being verified.
    /// @param blockHash The actual block hash retrieved using `blockhash`.
    error InvalidL2BlockHeader(bytes32 blockHeaderHash, bytes32 blockHash);

    /// @notice Thrown when the L1 block hash extracted from the proof does not match the expected value.
    ///
    /// @param l1Blockhash The L1 block hash extracted from the proof.
    /// @param expectedL1BlockHash The expected L1 block hash based on the proof data.
    error L1BlockHashMismatch(bytes32 l1Blockhash, bytes32 expectedL1BlockHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice An L1 state root proof that relies on the OPStack's L1Block predeployed contract.
    struct L1BlockProof {
        /// @dev The L1 block header to verify, encoded in RLP format.
        bytes l1BlockHeaderRlp;
        /// @dev A recent L2 block header (off the replica chain), encoded in RLP format.
        bytes recentl2BlockHeaderRlp;
        /// @dev The Merkle proof for the L1Block oracle account on the L2 chain.
        bytes[] l1BlockAccountProof;
        /// @dev The Merkle proof for the L1 block hash storage slot in the L1Block oracle account.
        bytes[] l1BlockStorageProof;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Extracts the L1 state root from a serialized `L1BlockProof`.
    ///
    /// @param proof The serialized proof data.
    ///
    /// @return l1StateRoot The L1 state root.
    function verify(bytes memory proof) internal view returns (bytes32 l1StateRoot) {
        // Decode the `L1BlockProof` proof.
        L1BlockProof memory l1BlockProof = abi.decode(proof, (L1BlockProof));

        // Parse the L1 block header from the provided RLP data.
        BlockLib.BlockHeader memory l1BlockHeader = BlockLib.parseBlockHeader(l1BlockProof.l1BlockHeaderRlp);

        // Parse the recent replica L2 block header from the provided RLP data.
        BlockLib.BlockHeader memory recentl2BlockHeader = BlockLib.parseBlockHeader(l1BlockProof.recentl2BlockHeaderRlp);

        // Retrieve the block hash for the specified replica L2 block number using `blockhash`.
        bytes32 blockHash = blockhash(recentl2BlockHeader.number);

        // Verify that the recent replica L2 block header hash matches the retrieved block hash.
        // NOTE: Because `recentl2BlockHeader.hash` is guaranteed to not be 0, this also ensure that the provided
        //       `recentl2BlockHeader.number` is not too old.
        require(
            blockHash == recentl2BlockHeader.hash,
            InvalidL2BlockHeader({blockHeaderHash: recentl2BlockHeader.hash, blockHash: blockHash})
        );

        // Extract the `L1block` hash slot value from the recent replica L2 state root.
        (, bytes32 l1Blockhash) = StorageProofLib.extractAccountStorageValue({
            stateRoot: recentl2BlockHeader.stateRoot,
            account: L1BLOCK_PREDEPLOY_ADDRESS,
            accountProof: l1BlockProof.l1BlockAccountProof,
            slot: L1BLOCK_HASH_SLOT,
            storageProof: l1BlockProof.l1BlockStorageProof
        });

        // Verify that the extracted L1 block hash matches the one provided in the L1 block header.
        require(
            l1Blockhash == l1BlockHeader.hash,
            L1BlockHashMismatch({l1Blockhash: l1Blockhash, expectedL1BlockHash: l1BlockHeader.hash})
        );

        // Return the verified L1 state root.
        l1StateRoot = l1BlockHeader.stateRoot;
    }
}
