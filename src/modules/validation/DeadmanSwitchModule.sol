// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.26;

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {_packValidationData} from "@eth-infinitism/account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {ModuleBase} from "../ModuleBase.sol";

/// @title Deadman Switch Module
/// @author Rhinestone (adapted for ERC-6900 by @armanmamyan)
/// @notice Module that allows users to set a nominee that can recover their account if they are
/// inactive for a certain period of time. Combines validation and execution hook functionality.
/// NOTE:
/// - This module implements both IValidationModule and IExecutionHookModule
/// - The execution hook updates the last access time on every transaction
/// - The validation module allows the nominee to control the account after timeout
/// - Uninstallation will NOT disable all installed entity IDs of an account. It only uninstalls the
///   entity ID that is passed in. Account must remove access for each entity ID if want to disable all.
contract DeadmanSwitchModule is IValidationModule, IExecutionHookModule, ModuleBase {
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    struct DeadmanSwitchConfig {
        uint48 lastAccess;
        uint48 timeout;
        address nominee;
    }

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    // entityId => account => config
    mapping(uint32 entityId => mapping(address account => DeadmanSwitchConfig)) public configs;

    /*//////////////////////////////////////////////////////////////////////////
                                     EVENTS
    //////////////////////////////////////////////////////////////////////////*/

    event DeadmanSwitchConfigured(
        address indexed account, 
        uint32 indexed entityId, 
        address nominee, 
        uint48 timeout
    );
    event NomineeUpdated(address indexed account, uint32 indexed entityId, address nominee);
    event TimeoutUpdated(address indexed account, uint32 indexed entityId, uint48 timeout);
    event LastAccessUpdated(address indexed account, uint32 indexed entityId, uint48 lastAccess);

    /*//////////////////////////////////////////////////////////////////////////
                                     ERRORS
    //////////////////////////////////////////////////////////////////////////*/

    error UnsupportedOperation();
    error NotInitialized();
    error InvalidNominee();
    error InvalidTimeout();
    error NotAuthorized();

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LIFECYCLE
    //////////////////////////////////////////////////////////////////////////*/

    /// @inheritdoc IModule
    /// @notice Initializes the module with the nominee and timeout
    /// @dev data is encoded as: abi.encode(uint32 entityId, address nominee, uint48 timeout)
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, address nominee, uint48 timeout) = abi.decode(data, (uint32, address, uint48));
        
        if (nominee == address(0)) revert InvalidNominee();
        if (timeout == 0) revert InvalidTimeout();

        configs[entityId][msg.sender] = DeadmanSwitchConfig({
            lastAccess: uint48(block.timestamp),
            timeout: timeout,
            nominee: nominee
        });

        emit DeadmanSwitchConfigured(msg.sender, entityId, nominee, timeout);
    }

    /// @inheritdoc IModule
    /// @notice Handles the uninstallation of the module and clears the config
    /// @dev data is encoded as: abi.encode(uint32 entityId)
    function onUninstall(bytes calldata data) external override {
        uint32 entityId = abi.decode(data, (uint32));
        delete configs[entityId][msg.sender];
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Sets the nominee for a specific entity ID
    /// @param entityId The entity ID to configure
    /// @param nominee Address of the nominee
    function setNominee(uint32 entityId, address nominee) external {
        if (!isInitialized(entityId, msg.sender)) revert NotInitialized();
        if (nominee == address(0)) revert InvalidNominee();
        
        configs[entityId][msg.sender].nominee = nominee;
        emit NomineeUpdated(msg.sender, entityId, nominee);
    }

    /// @notice Sets the timeout for a specific entity ID
    /// @param entityId The entity ID to configure
    /// @param timeout Timeout in seconds
    function setTimeout(uint32 entityId, uint48 timeout) external {
        if (!isInitialized(entityId, msg.sender)) revert NotInitialized();
        if (timeout == 0) revert InvalidTimeout();
        
        configs[entityId][msg.sender].timeout = timeout;
        emit TimeoutUpdated(msg.sender, entityId, timeout);
    }

    /// @notice Checks if the module is initialized for a specific entity ID and account
    /// @param entityId The entity ID to check
    /// @param account Address of the account
    /// @return true if initialized, false otherwise
    function isInitialized(uint32 entityId, address account) public view returns (bool) {
        return configs[entityId][account].nominee != address(0);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     VALIDATION MODULE
    //////////////////////////////////////////////////////////////////////////*/

    /// @inheritdoc IValidationModule
    /// @notice Validates a user operation - allows nominee to control account after timeout
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        DeadmanSwitchConfig memory config = configs[entityId][userOp.sender];
        
        // If not initialized, validation fails
        if (config.nominee == address(0)) {
            return _SIG_VALIDATION_FAILED;
        }

        // Check if signature is from the nominee
        bytes32 ethSignedHash = userOpHash.toEthSignedMessageHash();
        bool sigValid = SignatureChecker.isValidSignatureNow(config.nominee, ethSignedHash, userOp.signature);
        
        // Calculate when the nominee can act (lastAccess + timeout)
        uint48 validAfter = config.lastAccess + config.timeout;

        return _packValidationData({
            sigFailed: !sigValid,
            validAfter: validAfter,
            validUntil: type(uint48).max
        });
    }

    /// @inheritdoc IValidationModule
    /// @notice Runtime validation - only allows the account owner during normal operation
    function validateRuntime(
        address account,
        uint32 entityId,
        address sender,
        uint256,
        bytes calldata,
        bytes calldata
    ) external view override {
        DeadmanSwitchConfig memory config = configs[entityId][account];
        
        // During runtime, only allow if sender is the account itself (self-calls)
        // or if timeout has passed and sender is the nominee
        bool timeoutPassed = block.timestamp >= config.lastAccess + config.timeout;
        
        if (sender != account && !(timeoutPassed && sender == config.nominee)) {
            revert NotAuthorized();
        }
    }

    /// @inheritdoc IValidationModule
    /// @notice ERC-1271 signature validation
    /// @dev The signature is valid if signed by the nominee and timeout has passed
    function validateSignature(
        address account,
        uint32 entityId,
        address,
        bytes32 digest,
        bytes calldata signature
    ) external view override returns (bytes4) {
        DeadmanSwitchConfig memory config = configs[entityId][account];
        
        if (config.nominee == address(0)) {
            return _1271_INVALID;
        }

        // Only allow ERC-1271 signatures after timeout
        bool timeoutPassed = block.timestamp >= config.lastAccess + config.timeout;
        if (!timeoutPassed) {
            return _1271_INVALID;
        }

        if (SignatureChecker.isValidSignatureNow(config.nominee, digest, signature)) {
            return _1271_MAGIC_VALUE;
        }
        
        return _1271_INVALID;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     EXECUTION HOOK MODULE
    //////////////////////////////////////////////////////////////////////////*/

    /// @inheritdoc IExecutionHookModule
    /// @notice Pre-execution hook that updates the last access time
    function preExecutionHook(uint32 entityId, address, uint256, bytes calldata)
        external
        override
        returns (bytes memory)
    {
        // Update last access time if module is initialized
        if (isInitialized(entityId, msg.sender)) {
            configs[entityId][msg.sender].lastAccess = uint48(block.timestamp);
            emit LastAccessUpdated(msg.sender, entityId, uint48(block.timestamp));
        }
        
        return "";
    }

    /// @inheritdoc IExecutionHookModule
    /// @notice Post-execution hook (unused)
    function postExecutionHook(uint32, bytes calldata) external pure override {
        revert NotImplemented();
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "rhinestone.deadman-switch-module.1.0.0";
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ModuleBase, IERC165)
        returns (bool)
    {
        return interfaceId == type(IValidationModule).interfaceId
            || interfaceId == type(IExecutionHookModule).interfaceId
            || super.supportsInterface(interfaceId);
    }
} 