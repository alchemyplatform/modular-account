// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: MIT
//
// See LICENSE-MIT file for more information

pragma solidity ^0.8.22;

type SetValue is bytes30;

/// @dev The sentinel value is used to indicate the head and tail of the list.
bytes32 constant SENTINEL_VALUE = bytes32(uint256(1));

/// @dev Removing the last element will result in this flag not being set correctly, but all operations will
/// function normally, albeit with one extra sload for getAll.
bytes32 constant HAS_NEXT_FLAG = bytes32(uint256(2));

/// @dev As defined by ERC-4337.
uint256 constant SIG_VALIDATION_PASSED = 0;
uint256 constant SIG_VALIDATION_FAILED = 1;
