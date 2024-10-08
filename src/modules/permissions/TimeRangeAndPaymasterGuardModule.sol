// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {_packValidationData} from "@eth-infinitism/account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";

import {BaseModule} from "../../modules/BaseModule.sol";

/// @title Time Range Module
/// @author Alchemy
/// @notice This module allows for the setting and enforcement of time ranges for a validation function. Enforcement
/// relies on `block.timestamp`, either within this module for runtime validation, or by the EntryPoint for user op
/// validation. Time ranges are inclusive of both the beginning and ending timestamps.
contract TimeRangeAndPaymasterGuardModule is IValidationHookModule, BaseModule {
    struct TimeRangeAndPaymasterGuard {
        uint48 validUntil;
        uint48 validAfter;
        address requiredPaymaster;
    }

    mapping(uint32 entityId => mapping(address account => TimeRangeAndPaymasterGuard)) public
        timeRangeAndPaymasterGuards;

    error TimeRangeNotValid();
    error BadPaymasterSpecified();

    /// @inheritdoc IModule
    /// @notice Initializes the module with the given time range for `msg.sender` with a given entity id.
    /// @dev data is abi-encoded as (uint32 entityId, uint48 validUntil, uint48 validAfter)
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, uint48 validUntil, uint48 validAfter, address requiredPaymaster) =
            abi.decode(data, (uint32, uint48, uint48, address));

        setTimeRangeAndPaymasterGuard(entityId, validUntil, validAfter, requiredPaymaster);
    }

    /// @inheritdoc IModule
    /// @notice Resets module state for `msg.sender` with the given entity id.
    /// @dev data is abi-encoded as (uint32 entityId)
    function onUninstall(bytes calldata data) external override {
        uint32 entityId = abi.decode(data, (uint32));

        delete timeRangeAndPaymasterGuards[entityId][msg.sender];
    }

    /// @inheritdoc IValidationHookModule
    /// @notice Enforces the time range for a user op by returning the range in the ERC-4337 validation data.
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        returns (uint256)
    {
        // todo: optimize between memory / storage
        TimeRangeAndPaymasterGuard memory timeRangeAndPaymasterGuard =
            timeRangeAndPaymasterGuards[entityId][msg.sender];
        if (timeRangeAndPaymasterGuard.requiredPaymaster != address(0)) {
            address payingPaymaster = address(bytes20(userOp.paymasterAndData));
            if (payingPaymaster != timeRangeAndPaymasterGuard.requiredPaymaster) {
                revert BadPaymasterSpecified();
            }
        }
        return timeRangeAndPaymasterGuard.validUntil == uint48(0)
            && timeRangeAndPaymasterGuard.validAfter == uint48(0)
            ? 0
            : _packValidationData({
                sigFailed: false,
                validUntil: timeRangeAndPaymasterGuard.validUntil,
                validAfter: timeRangeAndPaymasterGuard.validAfter
            });
    }

    /// @inheritdoc IValidationHookModule
    /// @notice Enforces the time range for a runtime validation by reverting if `block.timestamp` is not within
    /// the range.
    function preRuntimeValidationHook(uint32 entityId, address, uint256, bytes calldata, bytes calldata)
        external
        view
        override
    {
        TimeRangeAndPaymasterGuard memory timeRangeAndPaymasterGuard =
            timeRangeAndPaymasterGuards[entityId][msg.sender];
        if (timeRangeAndPaymasterGuard.validUntil == uint48(0)) {
            // no time range restriction, pass
            return;
        }
        if (
            block.timestamp > timeRangeAndPaymasterGuard.validUntil
                || block.timestamp < timeRangeAndPaymasterGuard.validAfter
        ) {
            revert TimeRangeNotValid();
        }
    }

    /// @inheritdoc IValidationHookModule
    /// @dev No-op, signature checking is not enforced to be within a time range,  due to uncertainty about whether
    /// the `timestamp` opcode is allowed during this operation. If the validation should not be allowed to
    /// generate 1271 signatures, the flag `isSignatureValidation` should be set to false when calling
    /// `installValidation`.
    // solhint-disable-next-line no-empty-blocks
    function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override {}

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "alchemy.timerange-module.0.0.1";
    }

    /// @notice Sets the time range for the sending account (`msg.sender`) and a given entity id.
    /// @param entityId The entity id to set the time range for.
    /// @param validUntil The timestamp until which the time range is valid, inclusive.
    /// @param validAfter The timestamp after which the time range is valid, inclusive.
    /// @param requiredPaymaster The required paymaster for the validation entity.
    function setTimeRangeAndPaymasterGuard(
        uint32 entityId,
        uint48 validUntil,
        uint48 validAfter,
        address requiredPaymaster
    ) public {
        if (validUntil != uint48(0) && validAfter > validUntil) {
            revert TimeRangeNotValid();
        }
        timeRangeAndPaymasterGuards[entityId][msg.sender] =
            TimeRangeAndPaymasterGuard(validUntil, validAfter, requiredPaymaster);
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(BaseModule, IERC165)
        returns (bool)
    {
        return interfaceId == type(IValidationHookModule).interfaceId || super.supportsInterface(interfaceId);
    }
}
