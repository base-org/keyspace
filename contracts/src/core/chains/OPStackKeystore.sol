// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Keystore} from "../Keystore.sol";
import {BlockLib, L1StateRootLib, StorageProofLib} from "../KeystoreLibs.sol";

abstract contract OPStackKeystore is Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The AnchorStateRegistry contract address on L1 used to prove L2 state roots.
    address constant ANCHOR_STATE_REGISTRY_ADDR = 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205;

    /// @notice The slot where the OutputRoot is stored in the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the provided OutputRoot preimages do not has to the expected OutputRoot.
    error InvalidL2OutputRootPreimages();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev Proof used to extract a Keystore config hash from an OPStack master L2.
    struct OPStackProof {
        /// @dev The L1 state root proof.
        L1StateRootLib.L1StateRootProof l1StateRootProof;
        /// @dev The `AnchorStateRegistry` storage proof on L1.
        StorageProof anchorStateRegistryProof;
        /// @dev The Keystore storage proof on the master L2.
        StorageProof masterKeystoreProof;
        /// @dev The preimages of the OutputRoot.
        OutputRootPreimages outputRootPreimages;
    }

    /// @dev Struct regrouping the proofs to extract a storage value from an account.
    struct StorageProof {
        /// @dev The account proof to from wich the account storage root is extracted.
        bytes[] accountProof;
        /// @dev The storage proof (rooted against the extracted account storage), from which the slot value can be
        ///      extracted.
        bytes[] storageProof;
    }

    /// @dev Struct representing the elements that are hashed together to generate an OutputRoot which itself
    ///      represents a snapshot of the L2 state.
    struct OutputRootPreimages {
        /// @dev Version of the output root.
        bytes32 version;
        /// @dev Root of the state trie at the block of this output.
        bytes32 stateRoot;
        /// @dev Root of the message passer storage trie.
        bytes32 messagePasserStorageRoot;
        /// @dev The master L2 block header, encoded in RLP format.
        ///      NOTE: Must be hashed before being used to recompute the OutputRoot.
        bytes masterL2BlockHeaderRlp;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    constructor(uint256 masterChainId) Keystore(masterChainId) {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @inheritdoc Keystore
    ///
    /// @dev The following proving steps are performed to extract a Keystore config hash from the OPStack master L2:
    ///      1. Extract the L1 state root from a generic L1 state root proof.
    ///
    ///      2. From the L1 state root hash (within the `l1BlockHeader`), prove the storage root of the
    ///         `AnchorStateRegistry` contract on L1 and then prove the L2 OutputRoot stored at slot
    ///         `ANCHOR_STATE_REGISTRY_SLOT`. This slot corresponds to calling `anchors(0)` on the `AnchorStateRegistry`
    ///         contract.
    ///
    ///      3. From the proved L2 OutputRoot, verify the provided `l2StateRoot`. This is done by recomputing the L2
    ///         OutputRoot using the `l2StateRoot`, `l2MessagePasserStorageRoot`, and `l2BlockHash`
    ///         parameters. For more details, see the link:
    ///         https://github.com/ethereum-optimism/optimism/blob/d141b53e4f52a8eb96a552d46c2e1c6c068b032e/op-service/eth/output.go#L49-L63
    ///
    ///      4. From the master `l2StateRoot`, prove the Keystore storage root and prove the stored config hash.
    function _extractConfigHashFromMasterChain(bytes calldata keystoreProof)
        internal
        view
        override
        returns (uint256 masterl2BlockTimestamp, bool isSet, bytes32 configHash)
    {
        // Decode the `OPStackProof`.
        OPStackProof memory proof = abi.decode(keystoreProof, (OPStackProof));

        // 1. Extract the L1 state root from a generic L1 state root proof.
        bytes32 l1StateRoot = L1StateRootLib.verify({proof: proof.l1StateRootProof});

        // 2. Extract the OutputRoot that was submitted to the `AnchorStateRegistry` contract on L1.
        (, bytes32 outputRoot) = StorageProofLib.extractAccountStorageValue({
            stateRoot: l1StateRoot,
            account: ANCHOR_STATE_REGISTRY_ADDR,
            accountProof: proof.anchorStateRegistryProof.accountProof,
            slot: ANCHOR_STATE_REGISTRY_SLOT,
            storageProof: proof.anchorStateRegistryProof.storageProof
        });

        // 3. Ensure the provided preimages of the `outputRoot` are valid.
        //    NOTE: This is needed to verify the `proof.outputRootPreimages.stateRoot` which is used as the root
        //          to extract the config hash from the master L2.
        BlockLib.BlockHeader memory masterl2BlockHeader =
            BlockLib.parseBlockHeader(proof.outputRootPreimages.masterL2BlockHeaderRlp);
        masterl2BlockTimestamp = masterl2BlockHeader.timestamp;

        _validateOutputRootPreimages({
            outputRootPreimages: proof.outputRootPreimages,
            masterL2BlockHash: masterl2BlockHeader.hash,
            expectedOutputRoot: outputRoot
        });

        // 4. Extract the config hash stored in the Keystore on the master L2.
        (isSet, configHash) = StorageProofLib.extractAccountStorageValue({
            stateRoot: proof.outputRootPreimages.stateRoot,
            account: address(this),
            accountProof: proof.masterKeystoreProof.accountProof,
            slot: keccak256(abi.encodePacked(MASTER_KEYSTORE_STORAGE_LOCATION)),
            storageProof: proof.masterKeystoreProof.storageProof
        });
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the OutputRoot preimages values correctly hash to the `expectedOutputRoot`.
    ///
    /// @dev Reverts if the OutputRoot preimages values do not hash to the `expectedOutputRoot`.
    ///
    /// @param outputRootPreimages The `OutputRootPreimages` struct.
    /// @param masterL2BlockHash The master L2 block hash (recomputed from a provided master block header).
    /// @param expectedOutputRoot The expected OutputRoot.
    function _validateOutputRootPreimages(
        OutputRootPreimages memory outputRootPreimages,
        bytes32 masterL2BlockHash,
        bytes32 expectedOutputRoot
    ) private pure {
        bytes32 recomputedOutputRoot = keccak256(
            abi.encodePacked(
                outputRootPreimages.version,
                outputRootPreimages.stateRoot,
                masterL2BlockHash,
                outputRootPreimages.messagePasserStorageRoot
            )
        );

        require(recomputedOutputRoot == expectedOutputRoot, InvalidL2OutputRootPreimages());
    }
}
