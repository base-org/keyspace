// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Keystore} from "../../core/Keystore.sol";
import {ConfigLib} from "../../core/KeystoreLibs.sol";

import {BinaryMerkleTreeLib} from "./state/BinaryMerkleTreeLib.sol";

import {KeystoreBridge} from "./KeystoreBridge.sol";

abstract contract KeystoreBridgeableExt is Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The address of the `KeystoreBridge` contract.
    address public immutable keystoreBridge;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the confirmed Keystore config Merkle proof verification fails against the `KeystoreBridge`
    ///         received Keystore state root.
    error InvalidKeystoreConfigMerkleProof();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Constructor.
    ///
    /// @param keystoreBridge_ The address of the `KeystoreBridge` contract.
    constructor(address keystoreBridge_) {
        keystoreBridge = keystoreBridge_;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Confirms a Keystore config from the `KeystoreBridge` contract.
    ///
    /// @param masterConfig The new master configuration to synchronize.
    /// @param newMasterBlockTimestamp The block timestamp for the new master configuration.
    /// @param index The index of the leaf in the Merkle tree.
    /// @param siblings The Merkle proof sibling hashes.
    function confirmConfigFromBridge(
        ConfigLib.Config calldata masterConfig,
        uint256 newMasterBlockTimestamp,
        uint256 index,
        bytes32[] calldata siblings
    ) external {
        // Retrieve the received Keystore state root from the bridge.
        bytes32 receivedStateRoot = KeystoreBridge(keystoreBridge).receivedTreeRoots(masterChainId);

        // Recompute the data hash that was committed in the Keystore state root.
        bytes32 newConfirmedConfigHash = ConfigLib.hash({config: masterConfig, account: address(this)});

        // Ensure the provided `masterConfig` and `newMasterBlockTimestamp` are valid for this Keystore contract.
        require(
            BinaryMerkleTreeLib.isValid({
                root: receivedStateRoot,
                // NOTE: Ensure that the `dataHash` commits to `address(this)`, proving that `newConfirmedConfigHash`
                //       was effectively fetched from this contract on the master chain.
                dataHash: keccak256(abi.encodePacked(address(this), newConfirmedConfigHash, newMasterBlockTimestamp)),
                index: index,
                siblings: siblings
            }),
            InvalidKeystoreConfigMerkleProof()
        );

        // Ensure we are going forward when confirming a new config.
        (, uint256 masterBlockTimestamp) = confirmedConfigHash();
        require(
            newMasterBlockTimestamp > masterBlockTimestamp,
            ConfirmedConfigOutdated({
                currentMasterBlockTimestamp: masterBlockTimestamp,
                newMasterBlockTimestamp: newMasterBlockTimestamp
            })
        );

        // Apply the new confirmed config to the Keystore storage.
        _applyNewConfirmedConfig({
            newConfirmedConfigHash: newConfirmedConfigHash,
            newConfirmedConfig: masterConfig,
            newMasterBlockTimestamp: newMasterBlockTimestamp
        });
    }
}
