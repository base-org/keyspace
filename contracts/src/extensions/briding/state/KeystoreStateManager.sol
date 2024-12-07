// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BinaryMerkleTreeLib} from "./BinaryMerkleTreeLib.sol";

import {Keystore} from "../../../core/Keystore.sol";

contract KeystoreStateManager {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STORAGE                                             //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The latest received Keystore state root per origin chain id.
    mapping(uint256 originChainid => bytes32 receivedRoot) public receivedStateRoots;

    /// @notice Mapping of authority addresses to local Merkle Trees.
    BinaryMerkleTreeLib.Tree private _tree;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Retrieves the local Keystore state root.
    ///
    /// @return The local Keystore state root.
    function localStateRoot() public view returns (bytes32) {
        return BinaryMerkleTreeLib.stateRoot({tree: _tree});
    }

    /// @notice Commits Keystore configs to the local Merkle Tree.
    ///
    /// @param keystores An array of Keystore addresses whose configs will be committed.
    function append(address[] calldata keystores) external {
        BinaryMerkleTreeLib.Tree storage tree = _tree;

        for (uint256 i; i < keystores.length; i++) {
            address keystore = keystores[i];
            (bytes32 confirmedConfigHash, uint256 masterBlockTimestamp) = Keystore(keystore).confirmedConfigHash();

            BinaryMerkleTreeLib.commitTo({
                tree: tree,
                // NOTE: The `dataHash` must commit to the `keystore` address, as it could potentially be malicious and
                //       return an arbitrary `confirmedConfigHash`.
                dataHash: keccak256(abi.encodePacked(keystore, confirmedConfigHash, masterBlockTimestamp))
            });
        }
    }
}
