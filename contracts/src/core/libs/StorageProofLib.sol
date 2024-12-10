// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {RLPReader} from "Solidity-RLP/RLPReader.sol";

import {MerklePatriciaProofVerifier} from "./MerklePatriciaProofVerifier.sol";

library StorageProofLib {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    bytes32 constant EMPTY_STATE_TRIE_HASH = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Extracts the storage value from the given account and storage proofs.
    ///
    /// @dev Reverts if any of the proofs is invalid.
    ///
    /// @param stateRoot The root of the state trie.
    /// @param account The address of the account whose storage is being read.
    /// @param accountProof The account proof.
    /// @param slot The storage slot being read.
    /// @param storageProof The storage proof.
    ///
    /// @return isSet Whether the slot value is set or not.
    /// @return value The value stored at the given slot.
    function extractAccountStorageValue(
        bytes32 stateRoot,
        address account,
        bytes[] memory accountProof,
        bytes32 slot,
        bytes[] memory storageProof
    ) internal pure returns (bool isSet, bytes32 value) {
        bytes32 storageRoot =
            extractAccountStorageRoot({stateRoot: stateRoot, account: account, accountProof: accountProof});

        return extractSlotValue({storageRoot: storageRoot, slot: slot, storageProof: storageProof});
    }

    /// @notice Extracts the account storage root from the given account proof.
    ///
    /// @dev Reverts if the account proof is invalid.
    ///
    /// @param stateRoot The root of the state trie.
    /// @param account The address of the account.
    /// @param accountProof The account proof.
    ///
    /// @return The account storage root.
    function extractAccountStorageRoot(bytes32 stateRoot, address account, bytes[] memory accountProof)
        internal
        pure
        returns (bytes32)
    {
        bytes32 accountHash = keccak256(abi.encodePacked(account));
        bytes memory value = MerklePatriciaProofVerifier.extractProofValue({
            rootHash: stateRoot,
            path: abi.encodePacked(accountHash),
            stack: _parseRLPItems(accountProof)
        });

        // If the account does not exist, return the hash of an empty trie.
        if (value.length == 0) {
            return EMPTY_STATE_TRIE_HASH;
        }

        return bytes32(value.toRlpItem().toList()[2].toUint());
    }

    /// @notice Extracts the slot value from the given storage proof.
    ///
    /// @dev Reverts if the account proof is invalid.
    ///
    /// @param storageRoot The root of the storage trie.
    /// @param slot The storage slot being read.
    /// @param storageProof The storage proof.
    ///
    /// @return isSet Whether the slot value is set or not.
    /// @return value The value stored at the given slot.
    function extractSlotValue(bytes32 storageRoot, bytes32 slot, bytes[] memory storageProof)
        internal
        pure
        returns (bool isSet, bytes32 value)
    {
        bytes32 slotHash = keccak256(abi.encodePacked(slot));

        RLPReader.RLPItem memory slotRlp = MerklePatriciaProofVerifier.extractProofValue({
            rootHash: storageRoot,
            path: abi.encodePacked(slotHash),
            stack: _parseRLPItems(storageProof)
        }).toRlpItem();

        isSet = slotRlp.len != 0;
        if (isSet) {
            value = bytes32(slotRlp.toUint());
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Parses RLP items from the given proof bytes.
    ///
    /// @param proof The proof bytes.
    ///
    /// @return The parsed RLP items.
    function _parseRLPItems(bytes[] memory proof) private pure returns (RLPReader.RLPItem[] memory) {
        RLPReader.RLPItem[] memory proofItems = new RLPReader.RLPItem[](proof.length);
        for (uint256 i; i < proof.length; i++) {
            proofItems[i] = proof[i].toRlpItem();
        }

        return proofItems;
    }
}
