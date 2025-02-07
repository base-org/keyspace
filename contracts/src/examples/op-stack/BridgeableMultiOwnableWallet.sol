// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {KeystoreBridgeableExt} from "../../extensions/bridging/KeystoreBridgeableExt.sol";

import {MultiOwnableWallet} from "./MultiOwnableWallet.sol";

contract BridgeableMultiOwnableWallet is MultiOwnableWallet, KeystoreBridgeableExt {
    constructor(uint256 masterChainId, address keystoreBridge_)
        MultiOwnableWallet(masterChainId)
        KeystoreBridgeableExt(keystoreBridge_)
    {}
}
