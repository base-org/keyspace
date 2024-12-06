// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ConfigLib} from "./KeystoreLibs.sol";

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

abstract contract Keystore {
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

    /// @notice The master chain id.
    uint256 public immutable masterChainId;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the Keystore has already been intiialized.
    error KeystoreAlreadyInitialized();

    /// @notice Thrown when the initial Keystore config does not have a nonce equal to 0.
    error InitialNonceIsNotZero();

    /// @notice Thrown when the call is not performed on a replica chain.
    error NotOnReplicaChain();

    /// @notice Thrown when trying to confirm a Keystore config but the master block timestamp is below the current one.
    ///
    /// @param currentMasterBlockTimestamp The current master block timestamp.
    /// @param newMasterBlockTimestamp The new master block timestamp.
    error ConfirmedConfigOutdated(uint256 currentMasterBlockTimestamp, uint256 newMasterBlockTimestamp);

    /// @notice Thrown when the provided new nonce is not strictly equal the current nonce incremented by one.
    ///
    /// @param currentNonce The current nonce of the Keystore record.
    /// @param newNonce The provided new nonce.
    error NonceNotIncrementedByOne(uint256 currentNonce, uint256 newNonce);

    /// @notice Thrown when the new Keystore config unauthorized.
    error UnauthorizedNewKeystoreConfig();

    /// @notice Thrown when the new Keystore config is invalid.
    error InvalidNewKeystoreConfig();

    /// @notice Thrown when confirming the Keystore config on replica chains is required to achieve eventual
    ///         consistency.
    error ConfirmedConfigTooOld();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when a Keystore config is updated on the master chain.
    ///
    /// @param configHash The new config hash.
    event KeystoreConfigSet(bytes32 indexed configHash);

    /// @notice Emitted when a Keystore config is confirmed on a replica chain.
    ///
    /// @param configHash The new config hash.
    /// @param masterBlockTimestamp The timestamp of the master block associated with the proven config hash.
    event KeystoreConfigConfirmed(bytes32 indexed configHash, uint256 indexed masterBlockTimestamp);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           MODIFIERS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the call is performed on a replica chain.
    modifier onlyOnReplicaChain() {
        require(block.chainid != masterChainId, NotOnReplicaChain());
        _;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Creates the Keystore.
    ///
    /// @param masterChainId_ The master chain id.
    constructor(uint256 masterChainId_) {
        masterChainId = masterChainId_;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Set a Keystore config on the master chain.
    ///
    /// @param newConfig The Keystore config to store.
    /// @param authorizeAndValidateProof The proof(s) to authorize (and optionally validate) the new Keystore config.
    function setConfig(ConfigLib.Config calldata newConfig, bytes calldata authorizeAndValidateProof) external {
        // Determine the current config nonce and the appropriate update logic based on the chain:
        //      - On the master chain, use `_sMaster()` for state and `_applyMasterConfig` for update logic.
        //      - On a replica chain, use `_sReplica()` for state and `_applyReplicaConfig` for update logic.
        (uint256 currentConfigNonce, function (ConfigLib.Config calldata) returns (bytes32) applyConfigInternal) = block
            .chainid == masterChainId
            ? (_sMaster().configNonce, _applyMasterConfig)
            : (_sReplica().currentConfigNonce, _applyReplicaConfig);

        // Ensure the nonce is strictly incrementing.
        require(
            newConfig.nonce == currentConfigNonce + 1,
            NonceNotIncrementedByOne({currentNonce: currentConfigNonce, newNonce: newConfig.nonce})
        );

        // Hook before (to authorize the new Keystore config).
        require(
            _hookIsNewConfigAuthorized({newConfig: newConfig, authorizationProof: authorizeAndValidateProof}),
            UnauthorizedNewKeystoreConfig()
        );

        // Apply the new Keystore config to the internal storage.
        bytes32 newConfigHash = applyConfigInternal(newConfig);

        // Hook between (to apply the new Keystore config).
        bool triggeredUpgrade = _hookApplyNewConfig({newConfig: newConfig});

        // Hook after (to validate the new Keystore config).
        bool isNewConfigValid = triggeredUpgrade
            ? this.hookIsNewConfigValid({newConfig: newConfig, validationProof: authorizeAndValidateProof})
            : hookIsNewConfigValid({newConfig: newConfig, validationProof: authorizeAndValidateProof});

        require(isNewConfigValid, InvalidNewKeystoreConfig());

        emit KeystoreConfigSet(newConfigHash);
    }

    /// @notice Confirms a Keystore config from the master chain.
    ///
    /// @dev Reverts if not called on a replica chain.
    ///
    /// @param newConfirmedConfig The config to confirm.
    /// @param keystoreProof The Keystore proof from which to extract the new confirmed config hash.
    function confirmConfig(ConfigLib.Config calldata newConfirmedConfig, bytes calldata keystoreProof)
        external
        onlyOnReplicaChain
    {
        // Extract the new confirmed config hash from the provided `keystoreProof`.
        (uint256 newMasterBlockTimestamp, bool isSet, bytes32 newConfirmedConfigHash) =
            _extractConfigHashFromMasterChain(keystoreProof);

        // Ensure we are going forward when proving the new confirmed config hash.
        uint256 masterBlockTimestamp = _sReplica().masterBlockTimestamp;
        require(
            newMasterBlockTimestamp > masterBlockTimestamp,
            ConfirmedConfigOutdated({
                currentMasterBlockTimestamp: masterBlockTimestamp,
                newMasterBlockTimestamp: newMasterBlockTimestamp
            })
        );

        // If the config hash was successfully extracted fron the maser chain, keep going with the normal config
        // confirmation flow.
        if (isSet) {
            // Ensure the `newConfirmedConfig` matches with the extracted `newConfirmedConfigHash`.
            ConfigLib.verify({configHash: newConfirmedConfigHash, config: newConfirmedConfig});

            // Ensure the preconfirmed configs list are valid, given the new confirmed config hash.
            bool wasPreconfirmedListReset = _ensurePreconfirmedConfigsAreValid({
                newConfirmedConfigHash: newConfirmedConfigHash,
                newConfirmedConfig: newConfirmedConfig
            });

            // Store the new confirmed config in the Keystore internal storage.
            _sReplica().confirmedConfigHash = newConfirmedConfigHash;
            _sReplica().masterBlockTimestamp = newMasterBlockTimestamp;

            // Run the apply config hook logic if the preconfirmed configs list was reset.
            if (wasPreconfirmedListReset) {
                _hookApplyNewConfig({newConfig: newConfirmedConfig});
            }
        }
        // Otherwise, the config hash was not extracted from the master chain (because the Keystore is not old enough to
        // be committed by the master L2 state root published on L1), so simply acknowledge the new master block
        // timestamp and keep using the initial confirmed config hash (set in the `_initialize()` method).
        else {
            _sReplica().masterBlockTimestamp = newMasterBlockTimestamp;
            newConfirmedConfigHash = _sReplica().confirmedConfigHash;
        }

        emit KeystoreConfigConfirmed({configHash: newConfirmedConfigHash, masterBlockTimestamp: newMasterBlockTimestamp});
    }

    /// @notice Hook triggered right after the Keystore config has been updated.
    ///
    /// @dev This function is intentionnaly public and not internal so that it is possible to call it on the new
    ///      implementation if an upgrade was detected.
    ///
    /// @param newConfig The new Keystore config to validate.
    /// @param validationProof The proof to validate the new Keystore config.
    ///
    /// @return `true` if the `newConfig` is valid, otherwise `false`.
    function hookIsNewConfigValid(ConfigLib.Config calldata newConfig, bytes calldata validationProof)
        public
        view
        virtual
        returns (bool);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Returns the the eventual consistency window within which the Keystore config must be confirmed on
    ///         replica chains.
    ///
    /// @return The duration of the eventual consistency window in seconds.
    function _eventualConsistencyWindow() internal view virtual returns (uint256);

    /// @notice Extracts the Keystore config hash and timestamp from the master chain.
    ///
    /// @param keystoreProof The proof data used to extract the Keystore config hash on the master chain.
    ///
    /// @return masterBlockTimestamp The timestamp of the master block associated with the proven config hash.
    /// @return isSet Whether the config hash is set or not.
    /// @return configHash The config hash extracted from the Keystore on the master chain.
    function _extractConfigHashFromMasterChain(bytes calldata keystoreProof)
        internal
        view
        virtual
        returns (uint256 masterBlockTimestamp, bool isSet, bytes32 configHash);

    /// @notice Hook triggered right before updating the Keystore config.
    ///
    /// @param newConfig The new Keystore config to be authorized.
    /// @param authorizationProof The proof to authorize the new Keystore config.
    ///
    /// @return `true` if the `newConfig` is authorized, otherwise `false`.
    function _hookIsNewConfigAuthorized(ConfigLib.Config calldata newConfig, bytes calldata authorizationProof)
        internal
        view
        virtual
        returns (bool);

    /// @notice Hook triggered whenever a new Keystore config is established as the current one.
    ///
    /// @dev This hook is invoked under different conditions on the master chain and replica chains:
    ///      - On the master chain, it is called when `setConfig` executes successfully.
    ///      - On replica chains, it is called:
    ///         - whenever a preconfirmation operation is successful
    ///         - when confirming a new config, if the list of preconfirmed configs was reset
    ///
    /// @param newConfig The new Keystore config.
    ///
    /// @return A boolean indicating if applying the provided `config` triggered an implementation upgrade.
    function _hookApplyNewConfig(ConfigLib.Config calldata newConfig) internal virtual returns (bool);

    /// @notice Initializes the Keystore.
    ///
    /// @param config The initial Keystore config.
    function _initialize(ConfigLib.Config calldata config) internal {
        // Ensure the Keystore starts at nonce 0.
        require(config.nonce == 0, InitialNonceIsNotZero());

        // Initialize the internal Keystore storage.
        bytes32 configHash = ConfigLib.hash(config);
        if (block.chainid == masterChainId) {
            require(_sMaster().configHash == 0, KeystoreAlreadyInitialized());
            _sMaster().configHash = configHash;
        } else {
            require(_sReplica().confirmedConfigHash == 0, KeystoreAlreadyInitialized());
            _sReplica().confirmedConfigHash = configHash;
            _sReplica().preconfirmedConfigHashes.push(configHash);
        }

        // Call the new config hook.
        _hookApplyNewConfig({newConfig: config});
    }

    /// @notice Returns the current config hash.
    ///
    /// @return The hash of the current Keystore config.
    function _currentConfigHash() internal view returns (bytes32) {
        if (block.chainid == masterChainId) {
            return _sMaster().configHash;
        }

        uint256 preconfirmedCount = _sReplica().preconfirmedConfigHashes.length;
        return _sReplica().preconfirmedConfigHashes[preconfirmedCount - 1];
    }

    /// @notice Enforces eventual consistency by ensuring the confirmed Keystore configuration is recent enough.
    ///
    /// @dev On the master chain, this function always passes without additional checks.
    /// @dev On replica chains, the function reverts if the timestamp of the confirmed Keystore configuration
    ///      is older than the allowable eventual consistency window.
    function _enforceEventualConsistency() internal view {
        // Early return on the master chain.
        if (block.chainid == masterChainId) {
            return;
        }

        // On replica chains, enforce eventual consistency.
        uint256 validUntil = _sReplica().masterBlockTimestamp + _eventualConsistencyWindow();
        require(block.timestamp <= validUntil, ConfirmedConfigTooOld());
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `MasterKeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `MasterKeystoreStorage` struct.
    function _sMaster() private pure returns (MasterKeystoreStorage storage $) {
        bytes32 position = MASTER_KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Helper function to get a storage reference to the `ReplicaKeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `ReplicaKeystoreStorage` struct.
    function _sReplica() private pure returns (ReplicaKeystoreStorage storage $) {
        bytes32 position = REPLICA_KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Applies the new config to the `ReplicaKeystoreStorage`.
    ///
    /// @param newConfig The new Keystore config to apply.
    ///
    /// @return The new config hash.
    function _applyReplicaConfig(ConfigLib.Config calldata newConfig) private returns (bytes32) {
        bytes32 newConfigHash = ConfigLib.hash(newConfig);
        _setPreconfirmedConfig({preconfirmedConfigHash: newConfigHash, preconfirmedConfig: newConfig});

        return newConfigHash;
    }

    /// @notice Applies the new config to the `MasterKeystoreStorage`.
    ///
    /// @param newConfig The new Keystore config to apply.
    ///
    /// @return The new config hash.
    function _applyMasterConfig(ConfigLib.Config calldata newConfig) private returns (bytes32) {
        bytes32 newConfigHash = ConfigLib.hash(newConfig);
        _sMaster().configHash = newConfigHash;
        _sMaster().configNonce = newConfig.nonce;

        return newConfigHash;
    }

    /// @notice Ensures that the preconfirmed configs are valid given the provided `newConfirmedConfigHash`.
    ///
    /// @param newConfirmedConfigHash The new confirmed config hash.
    /// @param newConfirmedConfig The new confirmed config.
    ///
    /// @return wasPreconfirmedListReset True if the preconfirmed configs list has been reset, false otherwise.
    function _ensurePreconfirmedConfigsAreValid(
        bytes32 newConfirmedConfigHash,
        ConfigLib.Config calldata newConfirmedConfig
    ) private returns (bool wasPreconfirmedListReset) {
        // Get a storage reference to the Keystore preconfirmed configs list.
        bytes32[] storage preconfirmedConfigHashes = _sReplica().preconfirmedConfigHashes;

        // If the new confirmed config has a nonce above our current config, reset the preconfirmed configs list.
        uint256 currentConfigNonce = _sReplica().currentConfigNonce;
        if (newConfirmedConfig.nonce > currentConfigNonce) {
            _resetPreconfirmedConfigs({confirmedConfigHash: newConfirmedConfigHash, confirmedConfig: newConfirmedConfig});
            return true;
        }

        // Otherwise, the preconfirmed configs list MUST already include the new confirmed config hash. If it does not,
        // reset it.

        // Using the nonce difference, compute the index where the confirmed config hash should appear in the
        // preconfirmed configs list.
        // NOTE: This is possible because, each preconfirmed config nonce strictly increments by one from the
        //       previous config nonce.
        uint256 nonceDiff = currentConfigNonce - newConfirmedConfig.nonce;
        uint256 confirmedConfigHashIndex = preconfirmedConfigHashes.length - 1 - nonceDiff;

        // If the confirmed config hash is not found at that index, reset the preconfirmed configs list.
        if (preconfirmedConfigHashes[confirmedConfigHashIndex] != newConfirmedConfigHash) {
            _resetPreconfirmedConfigs({confirmedConfigHash: newConfirmedConfigHash, confirmedConfig: newConfirmedConfig});
            return true;
        }
    }

    /// @notice Resets the preconfirmed configs.
    ///
    /// @param confirmedConfigHash The confirmed config hash to start form.
    /// @param confirmedConfig The confirmed config to cache as the current one.
    function _resetPreconfirmedConfigs(bytes32 confirmedConfigHash, ConfigLib.Config memory confirmedConfig) private {
        delete _sReplica().preconfirmedConfigHashes;
        _setPreconfirmedConfig({preconfirmedConfigHash: confirmedConfigHash, preconfirmedConfig: confirmedConfig});
    }

    /// @notice Sets a new preconfirmed config.
    ///
    /// @param preconfirmedConfigHash The preconfirmed config hash.
    /// @param preconfirmedConfig The preconfirmed config.
    function _setPreconfirmedConfig(bytes32 preconfirmedConfigHash, ConfigLib.Config memory preconfirmedConfig)
        private
    {
        _sReplica().preconfirmedConfigHashes.push(preconfirmedConfigHash);
        _sReplica().currentConfigNonce = preconfirmedConfig.nonce;
    }
}
