// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

library UnsafeKeystoreStorageLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Slot for the `MasterKeystoreStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.MasterKeystore")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant MASTER_KEYSTORE_STORAGE_LOCATION =
        0xab0db9dff4dd1cc7cbf1b247b1f1845c685dfd323fb0c6da795f47e8940a2c00;

    /// @notice Slot for the `ReplicaKeystoreStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.ReplicaKeystore")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant REPLICA_KEYSTORE_STORAGE_LOCATION =
        0x1db15b34d880056d333fb6d93991f1076dc9f2ab389771578344740e0968e700;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev Storage layout of the Keystore on the master chain.
    ///
    /// @custom:storage-location erc7201:storage.MasterKeystore
    struct MasterKeystoreStorage {
        /// @dev The hash of the `config`.
        bytes32 configHash;
        /// @dev The Keystore config nonce.
        uint256 configNonce;
    }

    /// @dev Storage layout of the Keystore on replica chains.
    ///
    /// @custom:storage-location erc7201:storage.ReplicaKeystore
    struct ReplicaKeystoreStorage {
        /// @dev The hash of the `confirmedConfig`.
        bytes32 confirmedConfigHash;
        /// @dev The latest preconfirmed config nonce.
        uint256 currentConfigNonce;
        /// @dev The timestamp of the L1 block used to confirm the latest config.
        uint256 masterBlockTimestamp;
        /// @dev Preconfirmed Keystore config hashes.
        ///      NOTE: The preconfirmed configs list can NEVER be empty because:
        ///         1. It is initialized in the `_initialize()` method.
        ///         2. If reset in `confirmConfig()`, the newly confirmed config hash is immediately pushed into it.
        bytes32[] preconfirmedConfigHashes;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `MasterKeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `MasterKeystoreStorage` struct.
    function sMaster() internal pure returns (MasterKeystoreStorage storage $) {
        bytes32 position = MASTER_KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Helper function to get a storage reference to the `ReplicaKeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `ReplicaKeystoreStorage` struct.
    function sReplica() internal pure returns (ReplicaKeystoreStorage storage $) {
        bytes32 position = REPLICA_KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }
}
