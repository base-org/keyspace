// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {EIP4788Lib} from "./EIP4788Lib.sol";
import {L1BlockLib} from "./L1BlockLib.sol";

library L1StateRootLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when an unsupported proof type is provided in an L1 state root proof.
    ///
    /// @param proofType The invalid proof type that caused the error.
    error InvalidProofType(uint8 proofType);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev The supported L1 state root proof types.
    enum L1StateRootProofType {
        FromL1Block,
        FromBeaconRoot
    }

    /// @notice A generic L1 state root proof.
    struct L1StateRootProof {
        /// @dev The type of the proof, indicating its source.
        L1StateRootProofType type_;
        /// @dev The encoded proof data to decode and verify.
        bytes data;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Verifies a generic L1 state root proof and extracts the L1 state root and its corresponding timestamp.
    ///
    /// @param proof The generic L1 state root proof to verify.
    ///
    /// @return l1BlockTimestamp The timestamp of the L1 block or root.
    /// @return l1StateRoot The verified L1 state root.
    function verify(L1StateRootProof memory proof)
        internal
        view
        returns (uint256 l1BlockTimestamp, bytes32 l1StateRoot)
    {
        if (proof.type_ == L1StateRootProofType.FromL1Block) {
            return L1BlockLib.verify(proof.data);
        }

        if (proof.type_ == L1StateRootProofType.FromBeaconRoot) {
            return EIP4788Lib.verify(proof.data);
        }

        revert InvalidProofType(uint8(proof.type_));
    }
}
