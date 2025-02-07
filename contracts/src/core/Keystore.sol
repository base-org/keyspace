// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {ConfigLib, KeystoreStorageLib} from "./KeystoreLibs.sol";

abstract contract Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

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

    /// @notice Thrown when syncing an outdated Keystore config from the master chain.
    ///
    /// @param currentMasterBlockTimestamp The current master block timestamp.
    /// @param newMasterBlockTimestamp The new master block timestamp.
    error MasterConfigOutdated(uint256 currentMasterBlockTimestamp, uint256 newMasterBlockTimestamp);

    /// @notice Thrown when the provided new nonce is not strictly equal the current nonce incremented by one.
    ///
    /// @param currentNonce The current nonce of the Keystore record.
    /// @param newNonce The provided new nonce.
    error NonceNotIncrementedByOne(uint256 currentNonce, uint256 newNonce);

    /// @notice Thrown when the Keystore config is unauthorized.
    error UnauthorizedKeystoreConfig();

    /// @notice Thrown when the Keystore config is invalid.
    error InvalidKeystoreConfig();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when a Keystore config is updated on the master chain.
    ///
    /// @param configHash The config hash.
    event KeystoreConfigSet(bytes32 indexed configHash);

    /// @notice Emitted when a Keystore config is synced from the master chain on a replica chain.
    ///
    /// @param masterConfigHash The master config hash.
    /// @param masterBlockTimestamp The timestamp of the master block associated with the proven config hash.
    event KeystoreConfigSynced(bytes32 indexed masterConfigHash, uint256 indexed masterBlockTimestamp);

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

    /// @notice Constructor.
    ///
    /// @param masterChainId_ The master chain id.
    constructor(uint256 masterChainId_) {
        masterChainId = masterChainId_;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Returns the master config hash and corresponding master block timestamp.
    ///
    /// @return masterConfigHash The hash of the master Keystore config.
    /// @return masterBlockTimestamp The timestamp of the master block associated with the master config hash.
    function masterConfigHashAndTimestamp()
        public
        view
        returns (bytes32 masterConfigHash, uint256 masterBlockTimestamp)
    {
        (masterConfigHash, masterBlockTimestamp) = block.chainid == masterChainId
            ? (KeystoreStorageLib.sMaster().configHash, block.timestamp)
            : (KeystoreStorageLib.sReplica().masterConfigHash, KeystoreStorageLib.sReplica().masterBlockTimestamp);
    }

    /// @notice Set a Keystore config.
    ///
    /// @param config The Keystore config to store.
    /// @param authorizeAndValidateProof The proof(s) to authorize (and optionally validate) the Keystore config.
    function setConfig(ConfigLib.Config calldata config, bytes calldata authorizeAndValidateProof) external {
        // Determine the current config nonce and the appropriate update logic based on the chain:
        //      - On the master chain, use `_sMaster()` for state and `_setMasterConfig` for update logic.
        //      - On a replica chain, use `_sReplica()` for state and `_setReplicaConfig` for update logic.
        (uint256 currentConfigNonce, function (ConfigLib.Config calldata) returns (bytes32) setConfigInternal) = block
            .chainid == masterChainId
            ? (KeystoreStorageLib.sMaster().configNonce, _setMasterConfig)
            : (KeystoreStorageLib.sReplica().currentConfigNonce, _setReplicaConfig);

        // Ensure the nonce is strictly incrementing.
        require(
            config.nonce == currentConfigNonce + 1,
            NonceNotIncrementedByOne({currentNonce: currentConfigNonce, newNonce: config.nonce})
        );

        // Hook before (to authorize the Keystore config).
        require(
            _hookIsConfigAuthorized({config: config, authorizationProof: authorizeAndValidateProof}),
            UnauthorizedKeystoreConfig()
        );

        // Apply the Keystore config to the internal storage.
        bytes32 configHash = setConfigInternal(config);

        // Hook between (to apply the Keystore config).
        bool triggeredUpgrade = _hookApplyConfig({config: config});

        // Hook after (to validate the Keystore config).
        bool isConfigValid = triggeredUpgrade
            ? this.hookIsConfigValid({config: config, validationProof: authorizeAndValidateProof})
            : hookIsConfigValid({config: config, validationProof: authorizeAndValidateProof});

        require(isConfigValid, InvalidKeystoreConfig());

        emit KeystoreConfigSet(configHash);
    }

    /// @notice Syncs a Keystore config from the master chain.
    ///
    /// @dev Reverts if not called on a replica chain.
    ///
    /// @param masterConfig The master config to sync.
    /// @param keystoreProof The Keystore proof from which to extract the master config hash.
    function syncConfig(ConfigLib.Config calldata masterConfig, bytes calldata keystoreProof)
        external
        onlyOnReplicaChain
    {
        // Extract the master config hash from the provided `keystoreProof`.
        (uint256 masterBlockTimestamp, bool isSet, bytes32 masterConfigHash) =
            _extractConfigHashFromMasterChain(keystoreProof);

        // Ensure we are going forward when syncing a master config.
        uint256 currentMasterBlockTimestamp = KeystoreStorageLib.sReplica().masterBlockTimestamp;
        require(
            masterBlockTimestamp > currentMasterBlockTimestamp,
            MasterConfigOutdated({
                currentMasterBlockTimestamp: currentMasterBlockTimestamp,
                newMasterBlockTimestamp: masterBlockTimestamp
            })
        );

        // If config hash was extracted from the master chain, proceed with syncing.
        if (isSet) {
            // Ensure the `masterConfig` matches with the extracted `masterConfigHash`.
            ConfigLib.verify({config: masterConfig, account: address(this), configHash: masterConfigHash});

            // Apply the master config to the replica chain.
            _applyMasterConfig({
                masterConfigHash: masterConfigHash,
                masterConfig: masterConfig,
                masterBlockTimestamp: masterBlockTimestamp
            });
        }
        // Otherwise, the config hash was not extracted from the master chain (because the Keystore is not old enough to
        // be committed by the master L2 state root published on L1), so simply acknowledge the master block timestamp
        // and keep using the initial master config hash (set in the `_initialize()` method).
        else {
            KeystoreStorageLib.sReplica().masterBlockTimestamp = masterBlockTimestamp;
            masterConfigHash = KeystoreStorageLib.sReplica().masterConfigHash;
        }

        emit KeystoreConfigSynced({masterConfigHash: masterConfigHash, masterBlockTimestamp: masterBlockTimestamp});
    }

    /// @notice Hook triggered right after the Keystore config has been updated.
    ///
    /// @dev This function is intentionnaly public and not internal so that it is possible to call it on the new
    ///      implementation if an upgrade was performed.
    ///
    /// @param config The Keystore config to validate.
    /// @param validationProof The proof to validate the Keystore config.
    ///
    /// @return `true` if the `config` is valid, otherwise `false`.
    function hookIsConfigValid(ConfigLib.Config calldata config, bytes calldata validationProof)
        public
        view
        virtual
        returns (bool);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

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
    /// @param config The Keystore config to be authorized.
    /// @param authorizationProof The proof to authorize the Keystore config.
    ///
    /// @return `true` if the `config` is authorized, otherwise `false`.
    function _hookIsConfigAuthorized(ConfigLib.Config calldata config, bytes calldata authorizationProof)
        internal
        view
        virtual
        returns (bool);

    /// @notice Hook triggered whenever a Keystore config is established as the current one.
    ///
    /// @dev This hook is invoked under different conditions on the master chain and replica chains:
    ///      - On the master chain, it is called when `setConfig` executes successfully.
    ///      - On replica chains, it is called:
    ///         - whenever a config is set successfully
    ///         - when syncing a master config, if the replica log was reset
    ///
    /// @param config The Keystore config.
    ///
    /// @return A boolean indicating if applying the provided `config` triggered an implementation upgrade.
    function _hookApplyConfig(ConfigLib.Config calldata config) internal virtual returns (bool);

    /// @notice Returns the current config hash.
    ///
    /// @return The hash of the current Keystore config.
    function _currentConfigHash() internal view returns (bytes32) {
        if (block.chainid == masterChainId) {
            return KeystoreStorageLib.sMaster().configHash;
        }

        uint256 replicaLogCount = KeystoreStorageLib.sReplica().replicaLog.length;
        return KeystoreStorageLib.sReplica().replicaLog[replicaLogCount - 1];
    }

    /// @notice Initializes the Keystore.
    ///
    /// @param config The initial Keystore config.
    function _initializeKeystore(ConfigLib.Config calldata config) internal {
        // Ensure the Keystore starts at nonce 0.
        require(config.nonce == 0, InitialNonceIsNotZero());

        // Initialize the internal Keystore storage.
        bytes32 configHash = ConfigLib.hash({config: config, account: address(this)});
        if (block.chainid == masterChainId) {
            require(KeystoreStorageLib.sMaster().configHash == 0, KeystoreAlreadyInitialized());
            KeystoreStorageLib.sMaster().configHash = configHash;
        } else {
            require(KeystoreStorageLib.sReplica().masterConfigHash == 0, KeystoreAlreadyInitialized());
            KeystoreStorageLib.sReplica().masterConfigHash = configHash;
            KeystoreStorageLib.sReplica().replicaLog.push(configHash);
        }

        // Call the apply config hook.
        _hookApplyConfig({config: config});
    }

    /// @notice Applies the provided master Keystore config on a replica chain.
    ///
    /// @param masterConfigHash The hash of the master Keystore config.
    /// @param masterConfig The master Keystore config.
    /// @param masterBlockTimestamp The master block timestamp associated with the master Keystore config.
    function _applyMasterConfig(
        bytes32 masterConfigHash,
        ConfigLib.Config calldata masterConfig,
        uint256 masterBlockTimestamp
    ) internal {
        // Ensure the replica log is valid, given the master config hash.
        bool wasReplicaLogReset =
            _ensureReplicaLogIsValid({masterConfigHash: masterConfigHash, masterConfigNonce: masterConfig.nonce});

        // Store the master config in the Keystore internal storage.
        KeystoreStorageLib.sReplica().masterConfigHash = masterConfigHash;
        KeystoreStorageLib.sReplica().masterBlockTimestamp = masterBlockTimestamp;

        // Run the apply config hook logic if the replica log was reset.
        if (wasReplicaLogReset) {
            _hookApplyConfig({config: masterConfig});
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Sets the config to the `MasterKeystoreStorage`.
    ///
    /// @param config The Keystore config to apply.
    ///
    /// @return The config hash.
    function _setMasterConfig(ConfigLib.Config calldata config) private returns (bytes32) {
        bytes32 configHash = ConfigLib.hash({config: config, account: address(this)});
        KeystoreStorageLib.sMaster().configHash = configHash;
        KeystoreStorageLib.sMaster().configNonce = config.nonce;

        return configHash;
    }

    /// @notice Sets the config to the `ReplicaKeystoreStorage`.
    ///
    /// @param config The Keystore config to set.
    ///
    /// @return The config hash.
    function _setReplicaConfig(ConfigLib.Config calldata config) private returns (bytes32) {
        bytes32 configHash = ConfigLib.hash({config: config, account: address(this)});
        _applyReplicaConfig({configHash: configHash, configNonce: config.nonce});

        return configHash;
    }

    /// @notice Ensures that the replica log is valid given the provided `masterConfigHash`.
    ///
    /// @param masterConfigHash The master config hash.
    /// @param masterConfigNonce The master config nonce.
    ///
    /// @return wasReplicaLogReset True if the replica log has been reset, false otherwise.
    function _ensureReplicaLogIsValid(bytes32 masterConfigHash, uint256 masterConfigNonce)
        private
        returns (bool wasReplicaLogReset)
    {
        // Get a storage reference to the Keystore replica log.
        bytes32[] storage replicaLog = KeystoreStorageLib.sReplica().replicaLog;

        // If the master config has a nonce above our current config, reset the replica log.
        uint256 currentConfigNonce = KeystoreStorageLib.sReplica().currentConfigNonce;
        if (masterConfigNonce > currentConfigNonce) {
            _resetReplicaLog({masterConfigHash: masterConfigHash, masterConfigNonce: masterConfigNonce});
            return true;
        }

        // Otherwise, the replica log MUST already include the master config hash. If it does not, reset it.

        // Using the nonce difference, compute the index where the master config hash should appear in the replica log.
        // NOTE: This is possible because, each config nonce strictly increments by one from the previous config nonce.
        uint256 nonceDiff = currentConfigNonce - masterConfigNonce;
        uint256 masterConfigHashIndex = replicaLog.length - 1 - nonceDiff;

        // If the master config hash is not found at that index, reset the replica log.
        if (replicaLog[masterConfigHashIndex] != masterConfigHash) {
            _resetReplicaLog({masterConfigHash: masterConfigHash, masterConfigNonce: masterConfigNonce});
            return true;
        }
    }

    /// @notice Resets the replica log.
    ///
    /// @param masterConfigHash The master config hash to start form.
    /// @param masterConfigNonce The master config nonce.
    function _resetReplicaLog(bytes32 masterConfigHash, uint256 masterConfigNonce) private {
        delete KeystoreStorageLib.sReplica().replicaLog;
        _applyReplicaConfig({configHash: masterConfigHash, configNonce: masterConfigNonce});
    }

    /// @notice Sets a replica config.
    ///
    /// @param configHash The config hash.
    /// @param configNonce The config nonce.
    function _applyReplicaConfig(bytes32 configHash, uint256 configNonce) private {
        KeystoreStorageLib.sReplica().replicaLog.push(configHash);
        KeystoreStorageLib.sReplica().currentConfigNonce = configNonce;
    }
}
