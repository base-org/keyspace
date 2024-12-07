// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {AddressAliasHelper} from "optimism-contracts/vendor/AddressAliasHelper.sol";

import {KeystoreStateManager} from "../state/KeystoreStateManager.sol";

import {L1ToL2MsgSenderIsNotThisContract} from "./PortalErrors.sol";

contract ReceiverAliasedAddress is KeystoreStateManager {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Receives a Keystore state root sent from an aliased L1 address.
    ///
    /// @param originChainid The origin chain id.
    /// @param stateRoot_ The state root being received.
    function receiveFromAliasedAddress(uint256 originChainid, bytes32 stateRoot_) external {
        // Ensure the `msg.sender` is the aliased address of this contract.
        require(AddressAliasHelper.undoL1ToL2Alias(msg.sender) == address(this), L1ToL2MsgSenderIsNotThisContract());

        // Register the Keystore state root.
        receivedStateRoots[originChainid] = stateRoot_;
    }
}
