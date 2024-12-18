// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreArbitrumPortal} from "./portals/KeystoreArbitrumPortal.sol";
import {KeystoreBasePortal} from "./portals/KeystoreBasePortal.sol";
import {KeystoreOptimismPortal} from "./portals/KeystoreOptimismPortal.sol";

import {KeystoreStateManager} from "./state/KeystoreStateManager.sol";

contract KeystoreBridge is KeystoreStateManager, KeystoreBasePortal, KeystoreOptimismPortal, KeystoreArbitrumPortal {}
