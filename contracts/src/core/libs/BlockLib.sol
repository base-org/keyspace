// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {RLPReader} from "Solidity-RLP/RLPReader.sol";

library BlockLib {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev Block header structure returned by `parseBlockHeader()`.
    struct BlockHeader {
        /// @dev The block hash.
        bytes32 hash;
        /// @dev The state root.
        bytes32 stateRoot;
        /// @dev The block number.
        uint256 number;
        /// @dev The block timestam
        uint256 timestamp;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Parses an RLP-encoded block header.
    ///
    /// @dev Implementation is taken from:
    ///      https://github.com/lidofinance/curve-merkle-oracle/blob/fffd375659358af54a6e8bbf8c3aa44188894c81/contracts/StateProofVerifier.sol.
    ///
    /// @param headerRlpBytes The RLP-encoded block header.
    ///
    /// @return The decoded `_BlockHeader`.
    function parseBlockHeader(bytes memory headerRlpBytes) internal pure returns (BlockHeader memory) {
        BlockHeader memory result;
        RLPReader.RLPItem[] memory headerFields = headerRlpBytes.toRlpItem().toList();

        result.stateRoot = bytes32(headerFields[3].toUint());
        result.number = headerFields[8].toUint();
        result.timestamp = headerFields[11].toUint();
        result.hash = keccak256(headerRlpBytes);

        return result;
    }
}
