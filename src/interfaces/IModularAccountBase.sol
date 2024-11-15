// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

interface IModularAccountBase {
    /// @notice Create a contract.
    /// @param value The value to send to the new contract constructor
    /// @param initCode The initCode to deploy.
    /// @param isCreate2 The bool to indicate which method to use to deploy.
    /// @param salt The salt for deployment.
    /// @return createdAddr The created contract address.
    function performCreate(uint256 value, bytes calldata initCode, bool isCreate2, bytes32 salt)
        external
        payable
        returns (address createdAddr);

    /// @notice Invalidate a nonce for deferred actions
    /// @param nonce the nonce to invalidate.
    function invalidateDeferredValidationInstallNonce(uint256 nonce) external;
}
