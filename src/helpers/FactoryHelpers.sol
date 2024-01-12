// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

library FactoryHelpers {
    /// @dev The owner array must be in strictly ascending order and not include the 0 address.
    /// @param owners encoded bytes array of owner addresses
    /// @return bool if the owners array is valid
    function isValidOwnerArray(address[] calldata owners) internal pure returns (bool) {
        address currentOwnerValue;
        for (uint256 i = 0; i < owners.length;) {
            if (owners[i] <= currentOwnerValue) {
                return false;
            }
            currentOwnerValue = owners[i];

            unchecked {
                ++i;
            }
        }
        return true;
    }

    /// @notice Gets this factory's create2 salt based on the input params
    /// @param salt additional entropy for create2
    /// @param owners encoded bytes array of owner addresses
    /// @return combinedSalt of salt and owners
    function getCombinedSalt(uint256 salt, bytes memory owners) internal pure returns (bytes32) {
        return keccak256(abi.encode(salt, owners));
    }
}
