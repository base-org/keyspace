// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

library ConfigLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the provided `configHash` does not match the recomputed `recomputedConfigHash`.
    ///
    /// @param configHash The expected config hash.
    /// @param recomputedConfigHash The recomputed config hash.
    error InvalidConfig(bytes32 configHash, bytes32 recomputedConfigHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev A Keystore config.
    struct Config {
        /// @dev The nonce associated with the Keystore record.
        uint256 nonce;
        /// @dev The Keystore record authentication data.
        //       NOTE: Wallet implementors are free to put any data here, including binding commitments
        //             if the data gets too big to be fully provided.
        bytes data;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that the provided `config` hash to `configHash`.
    ///
    /// @dev Reverts if the parameters hashes do not match.
    ///
    /// @param config The Keystore config.
    /// @param account The account address.
    /// @param configHash The Keystore config hash.
    function verify(Config calldata config, address account, bytes32 configHash) internal pure {
        // Ensure the recomputed config hash matches witht the given `configHash` parameter.
        bytes32 recomputedConfigHash = hash({config: config, account: account});

        require(
            recomputedConfigHash == configHash,
            InvalidConfig({configHash: configHash, recomputedConfigHash: recomputedConfigHash})
        );
    }

    /// @notice Computes the hash of the provided `config`.
    ///
    /// @dev To avoid replay of similar config signatures on different wallets with the same signers, the account
    ///      address is also hashed with the config.
    ///
    /// @param config The Keystore config.
    /// @param account The account address.
    ///
    /// @return The corresponding config hash.
    function hash(Config calldata config, address account) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(account, config.nonce, config.data));
    }
}
