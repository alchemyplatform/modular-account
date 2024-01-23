// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {AccountStorageV1} from "../account/AccountStorageV1.sol";
import {CastLib} from "../helpers/CastLib.sol";
import {KnownSelectors} from "../helpers/KnownSelectors.sol";
import {IAccountLoupe} from "../interfaces/IAccountLoupe.sol";
import {FunctionReference} from "../interfaces/IPluginManager.sol";
import {CountableLinkedListSetLib} from "../libraries/CountableLinkedListSetLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";

/// @title Account Loupe
/// @author Alchemy
/// @notice Provides view functions for querying the configuration of a modular account.
abstract contract AccountLoupe is IAccountLoupe, AccountStorageV1 {
    using LinkedListSetLib for LinkedListSet;
    using CountableLinkedListSetLib for LinkedListSet;

    /// @inheritdoc IAccountLoupe
    function getExecutionFunctionConfig(bytes4 selector)
        external
        view
        returns (ExecutionFunctionConfig memory config)
    {
        AccountStorage storage storage_ = _getAccountStorage();

        if (KnownSelectors.isNativeFunction(selector)) {
            config.plugin = address(this);
        } else {
            config.plugin = storage_.selectorData[selector].plugin;
        }

        config.userOpValidationFunction = storage_.selectorData[selector].userOpValidation;
        config.runtimeValidationFunction = storage_.selectorData[selector].runtimeValidation;
    }

    /// @inheritdoc IAccountLoupe
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHooks[] memory execHooks) {
        execHooks = _getHooks(_getAccountStorage().selectorData[selector].executionHooks);
    }

    /// @inheritdoc IAccountLoupe
    function getPreValidationHooks(bytes4 selector)
        external
        view
        returns (
            FunctionReference[] memory preUserOpValidationHooks,
            FunctionReference[] memory preRuntimeValidationHooks
        )
    {
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];
        preUserOpValidationHooks = CastLib.toFunctionReferenceArray(selectorData.preUserOpValidationHooks.getAll());
        preRuntimeValidationHooks =
            CastLib.toFunctionReferenceArray(selectorData.preRuntimeValidationHooks.getAll());
    }

    /// @inheritdoc IAccountLoupe
    function getInstalledPlugins() external view returns (address[] memory pluginAddresses) {
        pluginAddresses = CastLib.toAddressArray(_getAccountStorage().plugins.getAll());
    }

    /// @dev Collects hook data from stored execution hooks and prepares it for returning as the `ExecutionHooks`
    /// type defined by `IAccountLoupe`.
    function _getHooks(HookGroup storage storedHooks) internal view returns (ExecutionHooks[] memory execHooks) {
        FunctionReference[] memory preExecHooks = CastLib.toFunctionReferenceArray(storedHooks.preHooks.getAll());
        FunctionReference[] memory postOnlyExecHooks =
            CastLib.toFunctionReferenceArray(storedHooks.postOnlyHooks.getAll());

        uint256 preExecHooksLength = preExecHooks.length;
        uint256 postOnlyExecHooksLength = postOnlyExecHooks.length;
        uint256 maxExecHooksLength = postOnlyExecHooksLength;

        // There can only be as many associated post hooks to run as there are pre hooks.
        for (uint256 i = 0; i < preExecHooksLength; ++i) {
            unchecked {
                maxExecHooksLength += storedHooks.preHooks.getCount(CastLib.toSetValue(preExecHooks[i]));
            }
        }

        // Overallocate on length - not all of this may get filled up. We set the correct length later.
        execHooks = new ExecutionHooks[](maxExecHooksLength);
        uint256 actualExecHooksLength = 0;

        for (uint256 i = 0; i < preExecHooksLength; ++i) {
            FunctionReference[] memory associatedPostExecHooks =
                CastLib.toFunctionReferenceArray(storedHooks.associatedPostHooks[preExecHooks[i]].getAll());
            uint256 associatedPostExecHooksLength = associatedPostExecHooks.length;

            if (associatedPostExecHooksLength > 0) {
                for (uint256 j = 0; j < associatedPostExecHooksLength; ++j) {
                    execHooks[actualExecHooksLength].preExecHook = preExecHooks[i];
                    execHooks[actualExecHooksLength].postExecHook = associatedPostExecHooks[j];

                    unchecked {
                        ++actualExecHooksLength;
                    }
                }
            } else {
                execHooks[actualExecHooksLength].preExecHook = preExecHooks[i];

                unchecked {
                    ++actualExecHooksLength;
                }
            }
        }

        for (uint256 i = 0; i < postOnlyExecHooksLength; ++i) {
            execHooks[actualExecHooksLength].postExecHook = postOnlyExecHooks[i];

            unchecked {
                ++actualExecHooksLength;
            }
        }

        // "Trim" the exec hooks array to the actual length, since we may have overallocated.
        assembly ("memory-safe") {
            mstore(execHooks, actualExecHooksLength)
        }
    }
}
