// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {LibClone} from "solady/utils/LibClone.sol";

import {ConfigLib} from "../core/KeystoreLibs.sol";

import {MultiOwnableWallet} from "./MultiOwnableWallet.opstack.sol";

contract MultiOwnableWalletFactory {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
    address public immutable implementation;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Factory constructor used to initialize the implementation address to use for future
    ///         `MultiOwnableWallet` deployments.
    ///
    /// @param implementation_ The address of the `MultiOwnableWallet` implementation which new accounts will proxy to.
    constructor(address implementation_) {
        implementation = implementation_;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Returns the deterministic address of the account that would be created by `createAccount`.
    ///
    /// @param config The initial Keystore config used to set up the wallet.
    /// @param salt A initialization salt allowing multiple accounts with the same initial Keystore config to exist at
    ///             different addresses.
    ///
    /// @return The predicted address of the new wallet.
    function getAddress(ConfigLib.Config calldata config, uint256 salt) external view returns (address) {
        return
            LibClone.predictDeterministicAddress(initCodeHash(), _getSalt({config: config, salt: salt}), address(this));
    }

    /// @notice Returns the initialization code hash of the account, used for generating deterministic addresses.
    ///
    /// @return The initialization code hash of the ERC1967 proxy.
    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }

    /// @notice Deploys a new `MultiOwnableWallet` contract or returns an existing one if already deployed.
    ///
    /// @param config The configuration data used to initialize the wallet.
    /// @param salt A unique value used to generate a deterministic address.
    ///
    /// @return account The deployed `MultiOwnableWallet` contract.
    function createAccount(ConfigLib.Config calldata config, uint256 salt)
        external
        payable
        virtual
        returns (MultiOwnableWallet account)
    {
        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(msg.value, implementation, _getSalt({config: config, salt: salt}));

        account = MultiOwnableWallet(payable(accountAddress));

        // If the account is newly deployed, initialize it with the provided Keystore config.
        if (!alreadyDeployed) {
            account.initialize(config);
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Generates a unique salt value by combining a Keystore config hash with a provided salt.
    ///
    /// @param config The Keystore config.
    /// @param salt A unique value used to generate the deterministic address.
    ///
    /// @return A combined hash value used as a unique salt.
    function _getSalt(ConfigLib.Config calldata config, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(config, salt));
    }
}
