// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IBridge} from "arbitrum-nitro-contracts/bridge/IBridge.sol";
import {IInbox} from "arbitrum-nitro-contracts/bridge/IInbox.sol";
import {IOutbox} from "arbitrum-nitro-contracts/bridge/IOutbox.sol";
import {ArbSys} from "arbitrum-nitro-contracts/precompiles/ArbSys.sol";

import {L2ToL1MsgSenderIsNotThisContract, L2ToL1TxSenderIsNotRollupContract} from "./PortalErrors.sol";
import {ReceiverAliasedAddress} from "./ReceiverAliasedAddress.sol";

contract KeystoreArbitrumPortal is ReceiverAliasedAddress {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Address of the Arbitrum `Inbox` contract on L1.
    address constant ARBITRUM_INBOX = 0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f;

    /// @notice Address of the `ArbSys` contract on Arbitrum.
    address constant ARBSYS = 0x0000000000000000000000000000000000000064;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Sends the Keystore tree state root to Arbitrum.
    ///
    /// @param chainid The chain id key to look up the Keystore state root to send. If `chainid` is 0, the local state
    ///                root is sent.
    /// @param maxSubmissionCost The maximum cost of submitting the retryable ticket.
    /// @param gasLimit The gas limit for the retryable ticket on L2.
    /// @param maxFeePerGas The maximum fee per gas for the retryable ticket.
    function sendToArbitrum(uint256 chainid, uint256 maxSubmissionCost, uint256 gasLimit, uint256 maxFeePerGas)
        external
    {
        (uint256 originChainid, bytes32 stateRoot) =
            chainid == 0 ? (block.chainid, localStateRoot()) : (chainid, receivedStateRoots[chainid]);

        IInbox(ARBITRUM_INBOX).createRetryableTicket({
            to: address(this),
            l2CallValue: 0,
            maxSubmissionCost: maxSubmissionCost,
            excessFeeRefundAddress: msg.sender,
            callValueRefundAddress: msg.sender,
            gasLimit: gasLimit,
            maxFeePerGas: maxFeePerGas,
            data: abi.encodeCall(ReceiverAliasedAddress.receiveFromAliasedAddress, (originChainid, stateRoot))
        });
    }

    /// @notice Sends the Keystore tree state root back to L1.
    ///
    /// @param chainid The chain id key to look up the Keystore state root to send. If `chainid` is 0, the local state
    ///                root is sent.
    function sendFromArbitrumToL1(uint256 chainid) external {
        (uint256 originChainid, bytes32 stateRoot) =
            chainid == 0 ? (block.chainid, localStateRoot()) : (chainid, receivedStateRoots[chainid]);

        ArbSys(ARBSYS).sendTxToL1({
            destination: address(this),
            data: abi.encodeCall(KeystoreArbitrumPortal.receiveOnL1FromArbitrum, (originChainid, stateRoot))
        });
    }

    /// @notice Receives a Keystore state root sent from Arbitrum.
    ///
    /// @param originChainid The origin chain id.
    /// @param stateRoot The Keystore state root being received.
    function receiveOnL1FromArbitrum(uint256 originChainid, bytes32 stateRoot) external {
        // Ensure the tx sender is the Arbitrum Bridge contract.
        IBridge bridge = IInbox(ARBITRUM_INBOX).bridge();
        require(msg.sender == address(bridge), L2ToL1TxSenderIsNotRollupContract());

        // Ensure the message originates from this contract.
        IOutbox outbox = IOutbox(bridge.activeOutbox());
        require(outbox.l2ToL1Sender() == address(this), L2ToL1MsgSenderIsNotThisContract());

        // Register the Keystore state root.
        receivedStateRoots[originChainid] = stateRoot;
    }
}
