// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {ICrossDomainMessenger} from "optimism-interfaces/universal/ICrossDomainMessenger.sol";

import {KeystoreBridgeStorageLib} from "../state/KeystoreBridgeStorageLib.sol";

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

    /// @notice Sends the root to Optimism.
    ///
    /// @dev This function is intended to be called to send roots from L1 to Optimism and potentially from Optimism to
    ///      Optimism L3s. For this reason the caller is allowed to specify a `xDomainMessenger` to which the message
    ///      will be sent to.
    ///
    /// @param chainid The chain id key to look up the root to send. If `chainid` is 0, the local root is sent.
    /// @param xDomainMessenger The address of the `CrossDomainMessenger` contract.
    /// @param minGasLimit The minimum gas limit for the cross-domain message.
    function sendToOptimism(uint256 chainid, address xDomainMessenger, uint32 minGasLimit) external {
        (uint256 originChainid, bytes32 root) = chainid == 0
            ? (block.chainid, KeystoreBridgeStorageLib.localRoot())
            : (chainid, KeystoreBridgeStorageLib.receivedRoot(chainid));

        ICrossDomainMessenger(xDomainMessenger).sendMessage({
            _target: address(this),
            _message: abi.encodeCall(ReceiverAliasedAddress.receiveFromAliasedAddress, (originChainid, root)),
            _minGasLimit: minGasLimit
        });
    }

    /// @notice Sends the local root back to L1.
    ///
    /// @dev Only withdrawals from Optimism (and not its L3s) are supported as the targeted `receiveOnL1FromOptimism`
    ///      method only works on L1.
    /// @dev This method does not accept a `chainid` as "withdrawals" to L1 should only ever use the local root (and not
    ///      a received one).
    ///
    /// @param xDomainMessenger The address of the `CrossDomainMessenger` contract.
    /// @param minGasLimit The minimum gas limit for the cross-domain message.
    function sendFromOptimismToL1(address xDomainMessenger, uint32 minGasLimit) external {
        ICrossDomainMessenger(xDomainMessenger).sendMessage({
            _target: address(this),
            _message: abi.encodeCall(
                KeystoreOptimismPortal.receiveOnL1FromOptimism, (block.chainid, KeystoreBridgeStorageLib.localRoot())
            ),
            _minGasLimit: minGasLimit
        });
    }

    /// @notice Receives a root sent from Optimism.
    ///
    /// @param originChainid The origin chain id.
    /// @param root The root being received.
    function receiveOnL1FromOptimism(uint256 originChainid, bytes32 root) external {
        // Ensure the tx sender is the expected `L1CrossDomainMessenger`.
        require(msg.sender == OPTIMISM_L1_CROSS_DOMAIN_MESSENGER, L2ToL1TxSenderIsNotRollupContract());

        // Ensure the message originates from this contract.
        address xDomainMessageSender = ICrossDomainMessenger(OPTIMISM_L1_CROSS_DOMAIN_MESSENGER).xDomainMessageSender();
        require(xDomainMessageSender == address(this), L2ToL1MsgSenderIsNotThisContract());

        // Register the root.
        KeystoreBridgeStorageLib.sKeystoreBridge().receivedRoots[originChainid] = root;
    }
}
