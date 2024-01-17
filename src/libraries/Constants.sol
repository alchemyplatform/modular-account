// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

type SetValue is bytes30;

/// @dev The sentinel value is used to indicate the head and tail of the list.
bytes32 constant SENTINEL_VALUE = bytes32(uint256(1));

/// @dev Removing the last element will result in this flag not being set correctly, but all operations will
/// function normally, albeit with one extra sload for getAll.
bytes32 constant HAS_NEXT_FLAG = bytes32(uint256(2));

/// @dev as defined by ERC4337
uint256 constant SIG_VALIDATION_PASSED = 0;
uint256 constant SIG_VALIDATION_FAILED = 1;
