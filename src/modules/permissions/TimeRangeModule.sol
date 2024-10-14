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
contract TimeRangeModule is IValidationHookModule, BaseModule {
    struct TimeRange {
        uint48 validUntil;
        uint48 validAfter;
    }

    mapping(uint32 entityId => mapping(address account => TimeRange)) public timeRanges;

    error TimeRangeNotValid();

    /// @inheritdoc IModule
    /// @notice Initializes the module with the given time range for `msg.sender` with a given entity id.
    /// @dev data is abi-encoded as (uint32 entityId, uint48 validUntil, uint48 validAfter)
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, uint48 validUntil, uint48 validAfter) = abi.decode(data, (uint32, uint48, uint48));

        setTimeRange(entityId, validUntil, validAfter);
    }

    /// @inheritdoc IModule
    /// @notice Resets module state for `msg.sender` with the given entity id.
    /// @dev data is abi-encoded as (uint32 entityId)
    function onUninstall(bytes calldata data) external override {
        uint32 entityId = abi.decode(data, (uint32));

        delete timeRanges[entityId][msg.sender];
    }

    /// @inheritdoc IValidationHookModule
    /// @notice Enforces the time range for a user op by returning the range in the ERC-4337 validation data.
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        noValidationData(userOp.signature)
        returns (uint256)
    {
        // todo: optimize between memory / storage
        TimeRange memory timeRange = timeRanges[entityId][msg.sender];
        return _packValidationData({
            sigFailed: false,
            validUntil: timeRange.validUntil,
            validAfter: timeRange.validAfter
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
        TimeRange memory timeRange = timeRanges[entityId][msg.sender];
        if (block.timestamp > timeRange.validUntil || block.timestamp < timeRange.validAfter) {
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
    function setTimeRange(uint32 entityId, uint48 validUntil, uint48 validAfter) public {
        timeRanges[entityId][msg.sender] = TimeRange(validUntil, validAfter);
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
