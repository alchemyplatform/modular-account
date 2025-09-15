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

import {ExecutionManifest, ManifestExecutionFunction} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {ModuleBase} from "../ModuleBase.sol";

/// @title Scheduling Base Module
/// @author Rhinestone (adapted for ERC-6900 by @armanmamyan)
/// @notice Base module that provides scheduling functionality for executing transactions at specific intervals
/// NOTE:
/// - This is an abstract contract that provides core scheduling logic
/// - Concrete implementations should inherit from this and implement specific execution logic
/// - Each entity ID can have multiple scheduled jobs
/// - Jobs can be enabled/disabled and have configurable execution intervals
abstract contract SchedulingBaseModule is IExecutionModule, ModuleBase {
    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    struct ExecutionConfig {
        uint48 executeInterval;
        uint16 numberOfExecutions;
        uint16 numberOfExecutionsCompleted;
        uint48 startDate;
        bool isEnabled;
        uint48 lastExecutionTime;
        bytes executionData;
    }

    struct ExecutorAccess {
        uint256 jobId;
    }

    // entityId => account => jobId => config
    mapping(uint32 entityId => mapping(address account => mapping(uint256 jobId => ExecutionConfig))) public executionLog;
    
    // entityId => account => jobCount
    mapping(uint32 entityId => mapping(address account => uint256 jobCount)) public accountJobCount;

    /*//////////////////////////////////////////////////////////////////////////
                                     EVENTS
    //////////////////////////////////////////////////////////////////////////*/

    event ExecutionAdded(address indexed smartAccount, uint32 indexed entityId, uint256 indexed jobId);
    event ExecutionTriggered(address indexed smartAccount, uint32 indexed entityId, uint256 indexed jobId);
    event ExecutionStatusUpdated(address indexed smartAccount, uint32 indexed entityId, uint256 indexed jobId);
    event ExecutionsCancelled(address indexed smartAccount, uint32 indexed entityId);

    /*//////////////////////////////////////////////////////////////////////////
                                     ERRORS
    //////////////////////////////////////////////////////////////////////////*/

    error InvalidExecution();
    error NotInitialized();
    error JobNotFound();
    error ExecutionNotReady();

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LIFECYCLE
    //////////////////////////////////////////////////////////////////////////*/

    /// @inheritdoc IModule
    /// @notice Initializes the module with initial scheduling data
    /// @dev data is encoded as: abi.encode(uint32 entityId, bytes orderData)
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, bytes memory orderData) = abi.decode(data, (uint32, bytes));
        
        if (orderData.length > 0) {
            _createExecution(entityId, orderData);
        }
    }

    /// @inheritdoc IModule
    /// @notice Handles the uninstallation of the module and clears all jobs for the entity
    /// @dev data is encoded as: abi.encode(uint32 entityId)
    function onUninstall(bytes calldata data) external override {
        uint32 entityId = abi.decode(data, (uint32));
        address account = msg.sender;

        uint256 count = accountJobCount[entityId][account];
        for (uint256 i = 1; i <= count; i++) {
            delete executionLog[entityId][account][i];
        }
        accountJobCount[entityId][account] = 0;

        emit ExecutionsCancelled(account, entityId);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     EXECUTION MODULE
    //////////////////////////////////////////////////////////////////////////*/

    /// @inheritdoc IExecutionModule
    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;
        
        manifest.executionFunctions = new ManifestExecutionFunction[](4);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.addOrder.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: false
        });
        manifest.executionFunctions[1] = ManifestExecutionFunction({
            executionSelector: this.toggleOrder.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: false
        });
        manifest.executionFunctions[2] = ManifestExecutionFunction({
            executionSelector: this.executeOrder.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: true
        });
        manifest.executionFunctions[3] = ManifestExecutionFunction({
            executionSelector: this.getExecutionConfig.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: true
        });

        // No required interfaces or hooks for basic scheduling
        return manifest;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Checks if the module is initialized for a specific entity ID and account
    /// @param entityId The entity ID to check
    /// @param account Address of the account
    /// @return true if initialized, false otherwise
    function isInitialized(uint32 entityId, address account) public view returns (bool) {
        return accountJobCount[entityId][account] != 0;
    }

    /// @notice Adds a new scheduled order
    /// @param entityId The entity ID for this scheduling context
    /// @param orderData Encoded order data specific to the implementation
    function addOrder(uint32 entityId, bytes calldata orderData) external {
        address account = msg.sender;
        if (!isInitialized(entityId, account)) {
            revert NotInitialized();
        }

        _createExecution(entityId, orderData);
    }

    /// @notice Toggles the enabled state of a scheduled order
    /// @param entityId The entity ID for this scheduling context
    /// @param jobId The job ID to toggle
    function toggleOrder(uint32 entityId, uint256 jobId) external {
        address account = msg.sender;
        
        ExecutionConfig storage executionConfig = executionLog[entityId][account][jobId];
        
        if (executionConfig.numberOfExecutions == 0) {
            revert JobNotFound();
        }

        executionConfig.isEnabled = !executionConfig.isEnabled;
        
        emit ExecutionStatusUpdated(account, entityId, jobId);
    }

    /// @notice Gets the execution configuration for a specific job
    /// @param entityId The entity ID
    /// @param account The account address
    /// @param jobId The job ID
    /// @return config The execution configuration
    function getExecutionConfig(uint32 entityId, address account, uint256 jobId) 
        external 
        view 
        returns (ExecutionConfig memory config) 
    {
        return executionLog[entityId][account][jobId];
    }

    /// @notice Executes a scheduled order (to be implemented by concrete contracts)
    /// @param entityId The entity ID for this scheduling context
    /// @param jobId The job ID to execute
    function executeOrder(uint32 entityId, uint256 jobId) external virtual;

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Creates a new execution configuration
    /// @param entityId The entity ID for this scheduling context
    /// @param orderData The encoded order data
    function _createExecution(uint32 entityId, bytes memory orderData) internal {
        address account = msg.sender;

        uint256 jobId = accountJobCount[entityId][account] + 1;
        accountJobCount[entityId][account]++;

        // Parse order data: executeInterval (6 bytes) + numberOfExecutions (2 bytes) + startDate (6 bytes) + executionData
        if (orderData.length < 14) {
            revert InvalidExecution();
        }

        uint48 executeInterval;
        uint16 numberOfExecutions;
        uint48 startDate;
        bytes memory executionData;
        
        assembly {
            let dataPtr := add(orderData, 0x20)
            executeInterval := shr(208, mload(dataPtr))  // Extract first 6 bytes (48 bits)
            numberOfExecutions := shr(240, mload(add(dataPtr, 6)))  // Extract next 2 bytes (16 bits)
            startDate := shr(208, mload(add(dataPtr, 8)))  // Extract next 6 bytes (48 bits)
        }
        
        // Extract execution data (remaining bytes after first 14)
        executionData = new bytes(orderData.length - 14);
        for (uint256 i = 0; i < executionData.length; i++) {
            executionData[i] = orderData[i + 14];
        }

        // Prevent user from supplying an invalid number of executions (0)
        if (numberOfExecutions == 0) {
            revert InvalidExecution();
        }

        executionLog[entityId][account][jobId] = ExecutionConfig({
            numberOfExecutionsCompleted: 0,
            isEnabled: true,
            lastExecutionTime: 0,
            executeInterval: executeInterval,
            numberOfExecutions: numberOfExecutions,
            startDate: startDate,
            executionData: executionData
        });

        emit ExecutionAdded(account, entityId, jobId);
    }

    /// @notice Validates if an execution is ready to run
    /// @param entityId The entity ID
    /// @param jobId The job ID to validate
    function _validateExecution(uint32 entityId, uint256 jobId) internal view {
        ExecutionConfig storage executionConfig = executionLog[entityId][msg.sender][jobId];

        if (!executionConfig.isEnabled) {
            revert InvalidExecution();
        }

        if (executionConfig.lastExecutionTime + executionConfig.executeInterval > block.timestamp) {
            revert ExecutionNotReady();
        }

        if (executionConfig.numberOfExecutionsCompleted >= executionConfig.numberOfExecutions) {
            revert InvalidExecution();
        }

        if (executionConfig.startDate > block.timestamp) {
            revert ExecutionNotReady();
        }
    }

    /// @notice Updates execution state after a successful execution
    /// @param entityId The entity ID
    /// @param jobId The job ID that was executed
    function _updateExecutionState(uint32 entityId, uint256 jobId) internal {
        ExecutionConfig storage executionConfig = executionLog[entityId][msg.sender][jobId];
        
        executionConfig.lastExecutionTime = uint48(block.timestamp);
        executionConfig.numberOfExecutionsCompleted += 1;

        emit ExecutionTriggered(msg.sender, entityId, jobId);
    }

    /// @notice Modifier to validate execution before allowing it
    modifier canExecute(uint32 entityId, uint256 jobId) {
        _validateExecution(entityId, jobId);
        _;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /// @inheritdoc IModule
    function moduleId() external pure virtual returns (string memory) {
        return "rhinestone.scheduling-base-module.1.0.0";
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ModuleBase, IERC165)
        returns (bool)
    {
        return interfaceId == type(IExecutionModule).interfaceId || super.supportsInterface(interfaceId);
    }
} 