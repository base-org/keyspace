// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Keystore} from "../../core/Keystore.sol";
import {ConfigLib} from "../../core/KeystoreLibs.sol";

abstract contract WithdrawableKeystore is Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the call is not performed on the master chain.
    ///
    /// @param chainId The current `block.chainid`.
    /// @param masterChainId The master chain id.
    error NotOnMasterChain(uint256 chainId, uint256 masterChainId);

    /// @notice Thrown when the call is not performed on the L1.
    ///
    /// @param chainId The current `block.chainid`.
    error NotOnL1(uint256 chainId);

    /// @notice Thrown when the call to `withdrawConfigReceiver()` was not initiated by a Keystore config withdrawal
    ///         on the master chain.
    error CallNotInitiatedByWithdrawalFromMasterChain();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           MODIFIERS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the call is performed on the master chain.
    modifier onlyOnMasterChain() {
        require(
            block.chainid == masterChainId, NotOnMasterChain({chainId: block.chainid, masterChainId: masterChainId})
        );
        _;
    }

    /// @notice Ensures the call is performed on the L1.
    modifier onlyOnL1() {
        require(block.chainid == 1, NotOnL1(block.chainid));
        _;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Withdraws the master Keystore config to the L1.
    ///
    /// @dev Reverts if not called on the master chain.
    ///
    /// @param masterConfig The master Keystore config to withdraw.
    function withdrawMasterConfig(ConfigLib.Config calldata masterConfig) external onlyOnMasterChain {
        // Ensure the provided `masterConfig` hashes to `masterConfigHash`.
        (bytes32 masterConfigHash, uint256 masterBlockTimestamp) = _confirmedConfigHash();
        ConfigLib.verify({config: masterConfig, account: address(this), configHash: masterConfigHash});

        // Withdraw the config to L1.
        // FIXME: If the contract on L1 is compromised it could lead to account takeover on all chains.
        //        Current solution would be to not withdraw to the account directly but to a dedicated L1 contract.
        _withdrawConfig({masterConfig: masterConfig, masterBlockTimestamp: masterBlockTimestamp});
    }

    /// @notice Receives a Keystore config withdrawal on L1.
    ///
    /// @dev Reverts if not called on the L1.
    ///
    /// @param masterConfig The master Keystore config to apply.
    /// @param newMasterBlockTimestamp The master chain block timestamp.
    function withdrawConfigReceiver(ConfigLib.Config calldata masterConfig, uint256 newMasterBlockTimestamp)
        external
        onlyOnL1
    {
        require(_isWithdrawalFromMasterKeystore(), CallNotInitiatedByWithdrawalFromMasterChain());

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
            newConfirmedConfigHash: ConfigLib.hash({config: masterConfig, account: address(this)}),
            newConfirmedConfig: masterConfig,
            newMasterBlockTimestamp: newMasterBlockTimestamp
        });
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Checks if the call was initiated by withdrawal from the master Keystore.
    ///
    /// @return A boolean indicating whether the withdrawal originates from the master Keystore.
    function _isWithdrawalFromMasterKeystore() internal virtual returns (bool);

    /// @notice Performs a chain-specific Keystore config withdrawal to L1.
    ///
    /// @param masterConfig The master Keystore config to withdraw.
    /// @param masterBlockTimestamp The master chain block timestamp.
    function _withdrawConfig(ConfigLib.Config calldata masterConfig, uint256 masterBlockTimestamp) internal virtual;
}
