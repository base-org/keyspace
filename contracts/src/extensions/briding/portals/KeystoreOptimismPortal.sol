// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ICrossDomainMessenger} from "optimism-interfaces/universal/ICrossDomainMessenger.sol";

import {L2ToL1MsgSenderIsNotThisContract, L2ToL1TxSenderIsNotRollupContract} from "./PortalErrors.sol";
import {ReceiverAliasedAddress} from "./ReceiverAliasedAddress.sol";

contract KeystoreOptimismPortal is ReceiverAliasedAddress {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The address of the Optimism `L1CrossDomainMessenger` on L1.
    address constant OPTIMISM_L1_CROSS_DOMAIN_MESSENGER = 0x25ace71c97B33Cc4729CF772ae268934F7ab5fA1;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Sends the Keystore tree state root to Optimism.
    ///
    /// @param chainid The chain id key to look up the Keystore state root to send. If `chainid` is 0, the local state
    ///                root is sent.
    /// @param xDomainMessenger The address of the `CrossDomainMessenger` contract.
    /// @param minGasLimit The minimum gas limit for the cross-domain message.
    function sendToOptimism(uint256 chainid, address xDomainMessenger, uint32 minGasLimit) external {
        (uint256 originChainid, bytes32 stateRoot) =
            chainid == 0 ? (block.chainid, localStateRoot()) : (chainid, receivedStateRoots[chainid]);

        ICrossDomainMessenger(xDomainMessenger).sendMessage({
            _target: address(this),
            _message: abi.encodeCall(ReceiverAliasedAddress.receiveFromAliasedAddress, (originChainid, stateRoot)),
            _minGasLimit: minGasLimit
        });
    }

    /// @notice Sends the Keystore tree state root back to L1.
    ///
    /// @param chainid The chain id key to look up the Keystore state root to send. If `chainid` is 0, the local state
    ///                root is sent.
    /// @param xDomainMessenger The address of the `CrossDomainMessenger` contract.
    /// @param minGasLimit The minimum gas limit for the cross-domain message.
    function sendFromOptimismToL1(uint256 chainid, address xDomainMessenger, uint32 minGasLimit) external {
        (uint256 originChainid, bytes32 stateRoot) =
            chainid == 0 ? (block.chainid, localStateRoot()) : (chainid, receivedStateRoots[chainid]);

        ICrossDomainMessenger(xDomainMessenger).sendMessage({
            _target: address(this),
            _message: abi.encodeCall(KeystoreOptimismPortal.receiveOnL1FromOptimism, (originChainid, stateRoot)),
            _minGasLimit: minGasLimit
        });
    }

    /// @notice Receives a Keystore state root sent from Optimism.
    ///
    /// @param originChainid The origin chain id.
    /// @param stateRoot The Keystore state root being received.
    function receiveOnL1FromOptimism(uint256 originChainid, bytes32 stateRoot) external {
        // Ensure the tx sender is the expected `L1CrossDomainMessenger`.
        require(msg.sender == OPTIMISM_L1_CROSS_DOMAIN_MESSENGER, L2ToL1TxSenderIsNotRollupContract());

        // Ensure the message originates from this contract.
        address xDomainMessageSender = ICrossDomainMessenger(OPTIMISM_L1_CROSS_DOMAIN_MESSENGER).xDomainMessageSender();
        require(xDomainMessageSender == address(this), L2ToL1MsgSenderIsNotThisContract());

        // Register the Keystore state root.
        receivedStateRoots[originChainid] = stateRoot;
    }
}
