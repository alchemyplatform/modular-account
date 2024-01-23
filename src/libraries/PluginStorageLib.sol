// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: MIT
//
// See LICENSE-MIT file for more information

pragma solidity ^0.8.22;

type StoragePointer is bytes32;

/// @title Plugin Storage Library
/// @author Alchemy
/// @notice Library for allocating and accessing ERC-4337 address-associated storage within plugins.
library PluginStorageLib {
    /// @notice Allocates a memory buffer for an associated storage key, and sets the associated address and batch
    /// index.
    /// @param addr The address to associate with the storage key.
    /// @param batchIndex The batch index to associate with the storage key.
    /// @param keySize The size of the key in words, where each word is 32 bytes. Not inclusive of the address and
    /// batch index.
    /// @return key The allocated memory buffer.
    function allocateAssociatedStorageKey(address addr, uint256 batchIndex, uint8 keySize)
        internal
        pure
        returns (bytes memory key)
    {
        assembly ("memory-safe") {
            // Clear any dirty upper bits of keySize to prevent overflow
            keySize := and(keySize, 0xff)

            // compute the total size of the buffer, include the address and batch index
            let totalSize := add(64, mul(32, keySize))

            // Allocate memory for the key
            key := mload(0x40)
            mstore(0x40, add(add(key, totalSize), 32))
            mstore(key, totalSize)

            // Clear any dirty upper bits of address
            addr := and(addr, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            // Store the address and batch index in the key buffer
            mstore(add(key, 32), addr)
            mstore(add(key, 64), batchIndex)
        }
    }

    function associatedStorageLookup(bytes memory key, bytes32 input) internal pure returns (StoragePointer ptr) {
        assembly ("memory-safe") {
            mstore(add(key, 96), input)
            ptr := keccak256(add(key, 32), mload(key))
        }
    }

    function associatedStorageLookup(bytes memory key, bytes32 input1, bytes32 input2)
        internal
        pure
        returns (StoragePointer ptr)
    {
        assembly ("memory-safe") {
            mstore(add(key, 96), input1)
            mstore(add(key, 128), input2)
            ptr := keccak256(add(key, 32), mload(key))
        }
    }
}
