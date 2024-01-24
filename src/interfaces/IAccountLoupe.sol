// This work is marked with CC0 1.0 Universal.
//
// SPDX-License-Identifier: CC0-1.0
//
// To view a copy of this license, visit http://creativecommons.org/publicdomain/zero/1.0

pragma solidity ^0.8.22;

import {FunctionReference} from "./IPluginManager.sol";

/// @title Account Loupe Interface
interface IAccountLoupe {
    /// @notice Config for an execution function, given a selector.
    struct ExecutionFunctionConfig {
        address plugin;
        FunctionReference userOpValidationFunction;
        FunctionReference runtimeValidationFunction;
    }

    /// @notice Pre and post hooks for a given selector.
    /// @dev It's possible for one of either `preExecHook` or `postExecHook` to be empty.
    struct ExecutionHooks {
        FunctionReference preExecHook;
        FunctionReference postExecHook;
    }

    /// @notice Get the validation functions and plugin address for a selector.
    /// @dev If the selector is a native function, the plugin address will be the address of the account.
    /// @param selector The selector to get the configuration for.
    /// @return The configuration for this selector.
    function getExecutionFunctionConfig(bytes4 selector) external view returns (ExecutionFunctionConfig memory);

    /// @notice Get the pre and post execution hooks for a selector.
    /// @param selector The selector to get the hooks for.
    /// @return The pre and post execution hooks for this selector.
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHooks[] memory);

    /// @notice Get the pre user op and runtime validation hooks associated with a selector.
    /// @param selector The selector to get the hooks for.
    /// @return preUserOpValidationHooks The pre user op validation hooks for this selector.
    /// @return preRuntimeValidationHooks The pre runtime validation hooks for this selector.
    function getPreValidationHooks(bytes4 selector)
        external
        view
        returns (
            FunctionReference[] memory preUserOpValidationHooks,
            FunctionReference[] memory preRuntimeValidationHooks
        );

    /// @notice Get an array of all installed plugins.
    /// @return The addresses of all installed plugins.
    function getInstalledPlugins() external view returns (address[] memory);
}
