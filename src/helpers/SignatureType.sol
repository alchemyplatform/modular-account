// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

/// @notice An enum that is prepended to signatures to differentiate between EOA and contract owner signatures.
enum SignatureType {
    EOA,
    CONTRACT_OWNER
}
