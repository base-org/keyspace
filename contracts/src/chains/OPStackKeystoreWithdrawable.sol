// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Predeploys} from "optimism-contracts/libraries/Predeploys.sol";
import {ICrossDomainMessenger} from "optimism-interfaces/universal/ICrossDomainMessenger.sol";

import {Keystore} from "../Keystore.sol";
import {ConfigLib} from "../KeystoreLibs.sol";

abstract contract OPStackKeystoreWithdrawable is Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The address of the `L2CrossDomainMessenger`.
    address constant L1_CROSS_DOMAIN_MESSENGER = 0x25ace71c97B33Cc4729CF772ae268934F7ab5fA1;

    /// @notice The minimum gas limit required for cross-chain message execution.
    uint32 constant MIN_GAS_LIMIT = 100_000;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Withdraws the confirmed Keystore config for cross-chain propagation.
    ///
    /// @param confirmedConfig The confirmed Keystore config to propagate.
    function withdrawConfig(ConfigLib.Config calldata confirmedConfig) external {
        (bytes32 confirmedConfigHash, uint256 masterBlockTimestamp) = _confirmedConfigHash();

        // Ensure the provided `confirmedConfig` hashes to `confirmedConfigHash`.
        ConfigLib.verify({configHash: confirmedConfigHash, config: confirmedConfig});

        // Send a crosschain message.
        ICrossDomainMessenger(Predeploys.L2_CROSS_DOMAIN_MESSENGER).sendMessage({
            _target: address(this),
            _message: abi.encodeCall(this.withdrawConfigReceiver, (confirmedConfig, masterBlockTimestamp)),
            _minGasLimit: MIN_GAS_LIMIT
        });
    }

    /// @notice Receives and applies the confirmed Keystore config on a replica chain.
    ///
    /// @param confirmedConfig The confirmed Keystore config to apply.
    /// @param newMasterBlockTimestamp The master block timestamp associated with the new confirmed Keystore config.
    function withdrawConfigReceiver(ConfigLib.Config calldata confirmedConfig, uint256 newMasterBlockTimestamp)
        external
        onlyOnReplicaChain
    {
        // Ensure the tx sender is the expected CrossDomainMessenger.
        address xDomainMessageSender =
            block.chainid == 1 ? L1_CROSS_DOMAIN_MESSENGER : Predeploys.L2_CROSS_DOMAIN_MESSENGER;
        require(msg.sender == xDomainMessageSender, "TxSenderIsNotCrossDomainMessenger");

        // Ensure the message originates from this contract.
        require(
            ICrossDomainMessenger(xDomainMessageSender).xDomainMessageSender() == address(this),
            "MessageSenderIsNotThisContract"
        );

        // Ensure we are going forward when confirming a new config.
        (, uint256 masterBlockTimestamp) = _confirmedConfigHash();
        require(
            newMasterBlockTimestamp > masterBlockTimestamp,
            ConfirmedConfigOutdated({
                currentMasterBlockTimestamp: masterBlockTimestamp,
                newMasterBlockTimestamp: newMasterBlockTimestamp
            })
        );

        // Apply the new confirmed config to the Keystore storage.
        _applyNewConfirmedConfig({
            newConfirmedConfigHash: ConfigLib.hash(confirmedConfig),
            newConfirmedConfig: confirmedConfig,
            newMasterBlockTimestamp: newMasterBlockTimestamp
        });
    }
}
