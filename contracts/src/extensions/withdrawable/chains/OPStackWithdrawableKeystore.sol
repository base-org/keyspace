// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Predeploys} from "optimism-contracts/libraries/Predeploys.sol";
import {ICrossDomainMessenger} from "optimism-interfaces/universal/ICrossDomainMessenger.sol";

import {ConfigLib} from "../../../core/KeystoreLibs.sol";

import {WithdrawableKeystore} from "../WithdrawableKeystore.sol";

abstract contract OPStackWithdrawableKeystore is WithdrawableKeystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The minimum gas limit required for cross-chain message execution.
    uint32 constant MIN_GAS_LIMIT = 200_000;

    /// @notice The `L1CrossDomainMessenger` address.
    address public immutable l1CrossDomainMessenger;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Constructor.
    ///
    /// @param l1CrossDomainMessenger_ The `L1CrossDomainMessenger` address.
    constructor(address l1CrossDomainMessenger_) {
        l1CrossDomainMessenger = l1CrossDomainMessenger_;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @inheritdoc WithdrawableKeystore
    function _isWithdrawalFromMasterKeystore() internal virtual override returns (bool) {
        // Checks the tx sender is the `L1CrossDomainMessenger` and that the message was sent from this contract.
        return msg.sender == l1CrossDomainMessenger
            && ICrossDomainMessenger(l1CrossDomainMessenger).xDomainMessageSender() == address(this);
    }

    /// @inheritdoc WithdrawableKeystore
    function _withdrawConfig(ConfigLib.Config calldata masterConfig, uint256 masterBlockTimestamp)
        internal
        virtual
        override
    {
        // Send a message to the `L2CrossDomainMessenger`.
        ICrossDomainMessenger(Predeploys.L2_CROSS_DOMAIN_MESSENGER).sendMessage({
            _target: address(this),
            _message: abi.encodeCall(this.withdrawConfigReceiver, (masterConfig, masterBlockTimestamp)),
            _minGasLimit: MIN_GAS_LIMIT
        });
    }
}
