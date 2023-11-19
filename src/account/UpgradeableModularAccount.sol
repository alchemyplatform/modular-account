// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {AccountExecutor} from "./AccountExecutor.sol";
import {AccountLoupe} from "./AccountLoupe.sol";
import {AccountStorageInitializable} from "./AccountStorageInitializable.sol";
import {PluginManagerInternals} from "./PluginManagerInternals.sol";

import {_coalescePreValidation, _coalesceValidation} from "../helpers/ValidationDataHelpers.sol";

import {Call, IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {IAccount} from "../interfaces/erc4337/IAccount.sol";
import {IAccountInitializable} from "../interfaces/IAccountInitializable.sol";
import {IAccountView} from "../interfaces/IAccountView.sol";
import {IEntryPoint} from "../interfaces/erc4337/IEntryPoint.sol";
import {IPlugin, PluginManifest} from "../interfaces/IPlugin.sol";
import {IPluginExecutor} from "../interfaces/IPluginExecutor.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {UserOperation} from "../interfaces/erc4337/UserOperation.sol";

import {CastLib} from "../libraries/CastLib.sol";
import {CountableLinkedListSetLib} from "../libraries/CountableLinkedListSetLib.sol";
import {FunctionReference, FunctionReferenceLib} from "../libraries/FunctionReferenceLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";
import {UUPSUpgradeable} from "../../ext/UUPSUpgradeable.sol";

/// @title Upgradeable Modular Account
/// @author Alchemy
/// @notice An ERC-6900 compatible modular smart contract account (MSCA) that supports upgradeability and plugins.
contract UpgradeableModularAccount is
    AccountExecutor,
    AccountLoupe,
    AccountStorageInitializable,
    PluginManagerInternals,
    IAccount,
    IAccountInitializable,
    IAccountView,
    IERC165,
    IPluginExecutor,
    IStandardExecutor,
    UUPSUpgradeable
{
    using CountableLinkedListSetLib for LinkedListSet;
    using LinkedListSetLib for LinkedListSet;

    /// @dev Struct to hold optional configuration data for uninstalling a plugin. This should be encoded and
    /// passed to the `config` parameter of `uninstallPlugin`.
    struct UninstallPluginConfig {
        // ABI-encoding of a `PluginManifest` to specify the original manifest
        // used to install the plugin now being uninstalled, in cases where the
        // plugin manifest has changed. If empty, uses the default behavior of
        // calling the plugin to get its current manifest.
        bytes serializedManifest;
        // If true, will complete the uninstall even if `onUninstall` or
        // `onHookUnapply` callbacks revert. Available as an escape hatch if a
        // plugin is blocking uninstall.
        bool forceUninstall;
        // Maximum amount of gas allowed for each uninstall callback function
        // (`onUninstall` and `onHookUnapply`), or zero to set no limit. Should
        // typically be used with `forceUninstall` to remove plugins that are
        // preventing uninstallation by consuming all remaining gas.
        uint256 callbackGasLimit;
    }

    IEntryPoint private immutable _ENTRY_POINT;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // As per the EIP-165 spec, no interface should ever match 0xffffffff
    bytes4 internal constant _INTERFACE_ID_INVALID = 0xffffffff;
    bytes4 internal constant _IERC165_INTERFACE_ID = 0x01ffc9a7;

    event ModularAccountInitialized(IEntryPoint indexed entryPoint);

    error AlwaysDenyRule();
    error AuthorizeUpgradeReverted(bytes revertReason);
    error ExecFromPluginNotPermitted(address plugin, bytes4 selector);
    error ExecFromPluginExternalNotPermitted(address plugin, address target, uint256 value, bytes data);
    error NativeTokenSpendingNotPermitted(address plugin);
    error PostExecHookReverted(address plugin, uint8 functionId, bytes revertReason);
    error PreExecHookReverted(address plugin, uint8 functionId, bytes revertReason);
    error PreRuntimeValidationHookFailed(address plugin, uint8 functionId, bytes revertReason);
    error RuntimeValidationFunctionMissing(bytes4 selector);
    error RuntimeValidationFunctionReverted(address plugin, uint8 functionId, bytes revertReason);
    error UnexpectedAggregator(address plugin, uint8 functionId, address aggregator);
    error UnrecognizedFunction(bytes4 selector);
    error UserOpNotFromEntryPoint();
    error UserOpValidationFunctionMissing(bytes4 selector);

    constructor(IEntryPoint anEntryPoint) {
        _ENTRY_POINT = anEntryPoint;
        _disableInitializers();
    }

    // EXTERNAL FUNCTIONS

    /// @inheritdoc IAccountInitializable
    function initialize(address[] memory plugins, bytes calldata pluginInitData) external initializer {
        (bytes32[] memory manifestHashes, bytes[] memory pluginInstallDatas) =
            abi.decode(pluginInitData, (bytes32[], bytes[]));

        uint256 length = plugins.length;

        if (length != manifestHashes.length || length != pluginInstallDatas.length) {
            revert ArrayLengthMismatch();
        }

        FunctionReference[] memory emptyDependencies = new FunctionReference[](0);
        InjectedHook[] memory emptyInjectedHooks = new InjectedHook[](0);

        for (uint256 i = 0; i < length;) {
            _installPlugin(
                plugins[i], manifestHashes[i], pluginInstallDatas[i], emptyDependencies, emptyInjectedHooks
            );

            unchecked {
                ++i;
            }
        }

        emit ModularAccountInitialized(_ENTRY_POINT);
    }

    receive() external payable {}

    /// @notice Fallback function that routes calls to plugin execution functions.
    /// @dev We route calls to execution functions based on incoming msg.sig. If there's no plugin associated with
    /// this function selector, revert.
    /// @return Data returned from the called execution function.
    fallback(bytes calldata) external payable returns (bytes memory) {
        SelectorData storage selectorData = _getAccountStorage().selectorData[msg.sig];

        address execPlugin = selectorData.plugin;
        if (execPlugin == address(0)) {
            revert UnrecognizedFunction(msg.sig);
        }

        // Either reuse the call buffer from runtime validation, or allocate a new one. It may or may not be used
        // for pre exec hooks but it will be used for the plugin execution itself.
        bytes memory callBuffer =
            (msg.sender != address(_ENTRY_POINT)) ? _doRuntimeValidation() : _allocateRuntimeCallBuffer(msg.data);

        bool hasPreExecHooks = selectorData.hasPreExecHooks;
        bool hasPostOnlyExecHooks = selectorData.hasPostOnlyExecHooks;

        FunctionReference[] memory postExecHooksToRun;
        bytes[] memory postExecHookArgs;
        if (hasPreExecHooks) {
            // Cache post-exec hooks in memory
            (postExecHooksToRun, postExecHookArgs) = _doPreExecHooks(msg.sig, callBuffer);
        }

        // execute the function, bubbling up any reverts
        bool execSuccess = _executeRaw(execPlugin, _convertRuntimeCallBufferToExecBuffer(callBuffer));
        bytes memory execReturnData = _collectReturnData();

        if (!execSuccess) {
            // Bubble up revert reasons from plugins
            assembly ("memory-safe") {
                revert(add(execReturnData, 32), mload(execReturnData))
            }
        }

        _doCachedPostHooks(postExecHooksToRun, postExecHookArgs);

        if (hasPostOnlyExecHooks) {
            _doCachedPostHooks(
                CastLib.toFunctionReferenceArray(selectorData.executionHooks.postOnlyHooks.getAll()),
                new bytes[](0)
            );
        }

        return execReturnData;
    }

    /// @inheritdoc IAccount
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        override
        returns (uint256 validationData)
    {
        if (msg.sender != address(_ENTRY_POINT)) {
            revert UserOpNotFromEntryPoint();
        }

        bool hasPreValidationHooks;

        if (userOp.callData.length < 4) {
            revert UnrecognizedFunction(bytes4(userOp.callData));
        }
        bytes4 selector = _selectorFromCallData(userOp.callData);
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];

        FunctionReference userOpValidationFunction = selectorData.userOpValidation;
        hasPreValidationHooks = selectorData.hasPreUserOpValidationHooks;

        validationData =
            _doUserOpValidation(selector, userOpValidationFunction, userOp, userOpHash, hasPreValidationHooks);

        if (missingAccountFunds != 0) {
            // entry point verifies if call succeeds so we don't need to do here
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
        }
    }

    /// @inheritdoc IStandardExecutor
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        override
        returns (bytes memory result)
    {
        (FunctionReference[] memory postExecHooks, bytes[] memory postExecHookArgs) = _preNativeFunction();
        result = _exec(target, value, data);
        _postNativeFunction(postExecHooks, postExecHookArgs);
    }

    /// @inheritdoc IStandardExecutor
    function executeBatch(Call[] calldata calls) external payable override returns (bytes[] memory results) {
        (FunctionReference[] memory postExecHooks, bytes[] memory postExecHookArgs) = _preNativeFunction();

        uint256 callsLength = calls.length;
        results = new bytes[](callsLength);

        for (uint256 i = 0; i < callsLength;) {
            results[i] = _exec(calls[i].target, calls[i].value, calls[i].data);

            unchecked {
                ++i;
            }
        }

        _postNativeFunction(postExecHooks, postExecHookArgs);
    }

    /// @inheritdoc IPluginExecutor
    function executeFromPlugin(bytes calldata data) external payable override returns (bytes memory returnData) {
        bytes4 selector = _selectorFromCallData(data);
        bytes24 permittedCallKey = _getPermittedCallKey(msg.sender, selector);

        AccountStorage storage storage_ = _getAccountStorage();
        PermittedCallData storage permittedCallData = storage_.permittedCalls[permittedCallKey];

        if (!permittedCallData.callPermitted) {
            revert ExecFromPluginNotPermitted(msg.sender, selector);
        }

        bytes memory callBuffer = _allocateRuntimeCallBuffer(data);

        FunctionReference[] memory postPermittedCallHooks;
        bytes[] memory postPermittedCallHookArgs;
        if (permittedCallData.hasPrePermittedCallHooks) {
            // Cache post-permitted call hooks in memory
            (postPermittedCallHooks, postPermittedCallHookArgs) =
                _doPrePermittedCallHooks(permittedCallKey, callBuffer);
        }

        SelectorData storage selectorData = storage_.selectorData[selector];
        address execFunctionPlugin = selectorData.plugin;

        if (execFunctionPlugin == address(0)) {
            revert UnrecognizedFunction(selector);
        }

        FunctionReference[] memory postExecHooks;
        bytes[] memory postExecHookArgs;
        if (selectorData.hasPreExecHooks) {
            // Cache post-exec hooks in memory
            (postExecHooks, postExecHookArgs) = _doPreExecHooks(selector, callBuffer);
        }

        bool success = _executeRaw(execFunctionPlugin, _convertRuntimeCallBufferToExecBuffer(callBuffer));
        returnData = _collectReturnData();

        if (!success) {
            assembly ("memory-safe") {
                revert(add(returnData, 32), mload(returnData))
            }
        }

        _doCachedPostHooks(postExecHooks, postExecHookArgs);

        if (selectorData.hasPostOnlyExecHooks) {
            _doCachedPostHooks(
                CastLib.toFunctionReferenceArray(selectorData.executionHooks.postOnlyHooks.getAll()),
                new bytes[](0)
            );
        }

        _doCachedPostHooks(postPermittedCallHooks, postPermittedCallHookArgs);

        if (permittedCallData.hasPostOnlyPermittedCallHooks) {
            _doCachedPostHooks(
                CastLib.toFunctionReferenceArray(permittedCallData.permittedCallHooks.postOnlyHooks.getAll()),
                new bytes[](0)
            );
        }

        return returnData;
    }

    /// @inheritdoc IPluginExecutor
    function executeFromPluginExternal(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        AccountStorage storage storage_ = _getAccountStorage();
        address callingPlugin = msg.sender;

        // Make sure plugin is allowed to spend native token.
        if (value > 0 && value > msg.value && !storage_.pluginData[callingPlugin].canSpendNativeToken) {
            revert NativeTokenSpendingNotPermitted(callingPlugin);
        }

        // Check the caller plugin's permission to make this call on the target address.
        //
        // 1. Check that the target is permitted at all, and if so check that any one of the following is true:
        //   a. Is any selector permitted?
        //   b. Is the calldata is empty? (allow empty data calls by default if the target address is permitted)
        //   c. Is the selector in the call permitted?
        // 2. If the target is not permitted, instead check whether all external calls are permitted.
        //
        // `addressPermitted` can only be true if `anyExternalAddressPermitted` is false, so we can reduce our
        // worst-case `sloads` by 1 by not checking `anyExternalAddressPermitted` if `addressPermitted` is true.
        //
        // We allow calls where the data may be less than 4 bytes - it's up to the calling contract to
        // determine how to handle this.
        bool isTargetCallPermitted;
        if (storage_.permittedExternalCalls[IPlugin(callingPlugin)][target].addressPermitted) {
            isTargetCallPermitted = (
                storage_.permittedExternalCalls[IPlugin(callingPlugin)][target].anySelectorPermitted
                    || data.length == 0
                    || storage_.permittedExternalCalls[IPlugin(callingPlugin)][target].permittedSelectors[bytes4(data)]
            );
        } else {
            isTargetCallPermitted = storage_.pluginData[callingPlugin].anyExternalAddressPermitted;
        }

        // If the target is not permitted, check if the caller plugin is permitted to make any external calls.
        if (!isTargetCallPermitted) {
            revert ExecFromPluginExternalNotPermitted(callingPlugin, target, value, data);
        }

        // Run permitted call hooks and execution hooks. `execfuteFromPluginExternal` doesn't use PermittedCallData
        // to check call permissions, nor do they have an address entry in SelectorData, so it doesn't make sense
        // to use cached booleans (hasPreExecHooks, hasPostOnlyExecHooks, etc.) to conditionally bypass certain
        // steps, as it would just be an added `sload` in the nonzero hooks case.

        // Run any pre permitted call hooks specific to this caller and the `executeFromPluginExternal` selector
        bytes24 permittedCallKey =
            _getPermittedCallKey(callingPlugin, IPluginExecutor.executeFromPluginExternal.selector);
        (FunctionReference[] memory postPermittedCallHooks, bytes[] memory postPermittedCallHookArgs) =
            _doPrePermittedCallHooks(permittedCallKey, "");

        // Run any pre exec hooks for the `executeFromPluginExternal` selector
        (FunctionReference[] memory postExecHooks, bytes[] memory postExecHookArgs) =
            _doPreExecHooks(IPluginExecutor.executeFromPluginExternal.selector, "");

        // Perform the external call
        bytes memory returnData = _exec(target, value, data);

        // Run any post exec hooks for the `executeFromPluginExternal` selector
        _doCachedPostHooks(postExecHooks, postExecHookArgs);

        // Run any post only exec hooks for the `executeFromPluginExternal` selector
        _doCachedPostHooks(
            CastLib.toFunctionReferenceArray(
                storage_.selectorData[IPluginExecutor.executeFromPluginExternal.selector]
                    .executionHooks
                    .postOnlyHooks
                    .getAll()
            ),
            new bytes[](0)
        );

        // Run any post permitted call hooks specific to this caller and the `executeFromPluginExternal` selector
        _doCachedPostHooks(postPermittedCallHooks, postPermittedCallHookArgs);

        // Run any post only permitted call hooks specific to this caller and the `executeFromPluginExternal`
        // selector
        _doCachedPostHooks(
            CastLib.toFunctionReferenceArray(
                storage_.permittedCalls[permittedCallKey].permittedCallHooks.postOnlyHooks.getAll()
            ),
            new bytes[](0)
        );

        return returnData;
    }

    /// @inheritdoc IPluginManager
    function installPlugin(
        address plugin,
        bytes32 manifestHash,
        bytes calldata pluginInitData,
        FunctionReference[] calldata dependencies,
        InjectedHook[] calldata injectedHooks
    ) external override {
        (FunctionReference[] memory postExecHooks, bytes[] memory postHookArgs) = _preNativeFunction();
        _installPlugin(plugin, manifestHash, pluginInitData, dependencies, injectedHooks);
        _postNativeFunction(postExecHooks, postHookArgs);
    }

    /// @inheritdoc IPluginManager
    function uninstallPlugin(
        address plugin,
        bytes calldata config,
        bytes calldata pluginUninstallData,
        bytes[] calldata hookUnapplyData
    ) external override {
        (FunctionReference[] memory postExecHooks, bytes[] memory postHookArgs) = _preNativeFunction();

        UninstallPluginArgs memory args;
        args.plugin = plugin;
        bool hasSetManifest;

        if (config.length > 0) {
            UninstallPluginConfig memory decodedConfig = abi.decode(config, (UninstallPluginConfig));
            if (decodedConfig.serializedManifest.length > 0) {
                args.manifest = abi.decode(decodedConfig.serializedManifest, (PluginManifest));
                hasSetManifest = true;
            }
            args.forceUninstall = decodedConfig.forceUninstall;
            args.callbackGasLimit = decodedConfig.callbackGasLimit;
        }
        if (!hasSetManifest) {
            args.manifest = IPlugin(plugin).pluginManifest();
        }
        if (args.callbackGasLimit == 0) {
            args.callbackGasLimit = type(uint256).max;
        }

        _uninstallPlugin(args, pluginUninstallData, hookUnapplyData);

        _postNativeFunction(postExecHooks, postHookArgs);
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external view override returns (bool) {
        if (interfaceId == _INTERFACE_ID_INVALID) {
            return false;
        }
        if (interfaceId == _IERC165_INTERFACE_ID) {
            return true;
        }

        return _getAccountStorage().supportedInterfaces[interfaceId] > 0;
    }

    /// @inheritdoc UUPSUpgradeable
    function upgradeToAndCall(address newImplementation, bytes calldata data) public payable override onlyProxy {
        (FunctionReference[] memory postExecHooks, bytes[] memory postHookArgs) = _preNativeFunction();
        UUPSUpgradeable.upgradeToAndCall(newImplementation, data);
        _postNativeFunction(postExecHooks, postHookArgs);
    }

    /// @inheritdoc IAccountView
    function entryPoint() public view override returns (IEntryPoint) {
        return _ENTRY_POINT;
    }

    /// @inheritdoc IAccountView
    function getNonce() public view virtual override returns (uint256) {
        return _ENTRY_POINT.getNonce(address(this), 0);
    }

    // INTERNAL FUNCTIONS

    /// @dev Wraps execution of a native function with runtime validation and hooks. Used for upgradeToAndCall,
    /// execute, executeBatch, installPlugin, uninstallPlugin.
    function _preNativeFunction()
        internal
        returns (FunctionReference[] memory postExecHooks, bytes[] memory postExecHookArgs)
    {
        bytes memory callBuffer = "";

        if (msg.sender != address(_ENTRY_POINT)) {
            callBuffer = _doRuntimeValidation();
        }

        (postExecHooks, postExecHookArgs) = _doPreExecHooks(msg.sig, callBuffer);
    }

    /// @dev Wraps execution of a native function with runtime validation and hooks. Used for upgradeToAndCall,
    /// execute, executeBatch, installPlugin, uninstallPlugin.
    function _postNativeFunction(FunctionReference[] memory postExecHooks, bytes[] memory postExecHookArgs)
        internal
    {
        _doCachedPostHooks(postExecHooks, postExecHookArgs);

        _doCachedPostHooks(
            CastLib.toFunctionReferenceArray(
                _getAccountStorage().selectorData[msg.sig].executionHooks.postOnlyHooks.getAll()
            ),
            new bytes[](0)
        );
    }

    /// @dev To support gas estimation, we don't fail early when the failure is caused by a signature failure.
    function _doUserOpValidation(
        bytes4 selector,
        FunctionReference userOpValidationFunction,
        UserOperation calldata userOp,
        bytes32 userOpHash,
        bool doPreValidationHooks
    ) internal returns (uint256 validationData) {
        if (userOpValidationFunction == FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE) {
            revert UserOpValidationFunctionMissing(selector);
        }

        bytes memory callBuffer =
            _allocateUserOpCallBuffer(IPlugin.preUserOpValidationHook.selector, userOp, userOpHash);

        uint256 currentValidationData;
        uint256 preUserOpValidationHooksLength;

        if (doPreValidationHooks) {
            // Do preUserOpValidation hooks
            FunctionReference[] memory preUserOpValidationHooks = CastLib.toFunctionReferenceArray(
                _getAccountStorage().selectorData[selector].preUserOpValidationHooks.getAll()
            );

            preUserOpValidationHooksLength = preUserOpValidationHooks.length;
            for (uint256 i = 0; i < preUserOpValidationHooksLength;) {
                // FunctionReference preUserOpValidationHook = preUserOpValidationHooks[i];

                if (preUserOpValidationHooks[i].isEmptyOrMagicValue()) {
                    // Empty function reference is impossible here due to the element coming from a LinkedListSet.
                    // Runtime Validation Always Allow is not assignable here.
                    // Pre Hook Always Deny is the only assignable magic value here.
                    revert AlwaysDenyRule();
                }

                (address plugin, uint8 functionId) = preUserOpValidationHooks[i].unpack();

                _updatePluginCallBufferFunctionId(callBuffer, functionId);

                currentValidationData = _executeUserOpPluginFunction(callBuffer, plugin);

                if (uint160(currentValidationData) > 1) {
                    // If the aggregator is not 0 or 1, it is an unexpected value
                    revert UnexpectedAggregator(plugin, functionId, address(uint160(currentValidationData)));
                }
                validationData = _coalescePreValidation(validationData, currentValidationData);

                unchecked {
                    ++i;
                }
            }
        }

        // Run the user op validation function
        {
            _updatePluginCallBufferSelector(callBuffer, IPlugin.userOpValidationFunction.selector);
            // No magic values are assignable here, and we already checked whether or not the function was empty,
            // so we're OK to use the function immediately
            (address plugin, uint8 functionId) = userOpValidationFunction.unpack();

            _updatePluginCallBufferFunctionId(callBuffer, functionId);

            currentValidationData = _executeUserOpPluginFunction(callBuffer, plugin);

            if (preUserOpValidationHooksLength != 0) {
                // If we have other validation data we need to coalesce with
                validationData = _coalesceValidation(validationData, currentValidationData);
            } else {
                validationData = currentValidationData;
            }
        }
    }

    function _doRuntimeValidation() internal returns (bytes memory callBuffer) {
        AccountStorage storage storage_ = _getAccountStorage();
        FunctionReference runtimeValidationFunction = storage_.selectorData[msg.sig].runtimeValidation;
        bool doPreRuntimeValidationHooks = storage_.selectorData[msg.sig].hasPreRuntimeValidationHooks;

        // Allocate the call buffer for preRuntimeValidationHook
        callBuffer = _allocateRuntimeCallBuffer(msg.data);

        if (doPreRuntimeValidationHooks) {
            _updatePluginCallBufferSelector(callBuffer, IPlugin.preRuntimeValidationHook.selector);

            // run all preRuntimeValidation hooks
            FunctionReference[] memory preRuntimeValidationHooks = CastLib.toFunctionReferenceArray(
                _getAccountStorage().selectorData[msg.sig].preRuntimeValidationHooks.getAll()
            );

            uint256 preRuntimeValidationHooksLength = preRuntimeValidationHooks.length;
            for (uint256 i = 0; i < preRuntimeValidationHooksLength;) {
                FunctionReference preRuntimeValidationHook = preRuntimeValidationHooks[i];

                if (preRuntimeValidationHook.isEmptyOrMagicValue()) {
                    // The function reference must be the Always Deny magic value in this case,
                    // because zero and any other magic value is unassignable here.
                    revert AlwaysDenyRule();
                }

                (address plugin, uint8 functionId) = preRuntimeValidationHook.unpack();

                _updatePluginCallBufferFunctionId(callBuffer, functionId);

                _executeRuntimePluginFunction(callBuffer, plugin, PreRuntimeValidationHookFailed.selector);

                unchecked {
                    ++i;
                }
            }
        }

        // Identifier scope limiting
        {
            if (runtimeValidationFunction.isEmptyOrMagicValue()) {
                if (
                    runtimeValidationFunction == FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE
                        && (msg.sig != IPluginManager.installPlugin.selector || msg.sender != address(this))
                ) {
                    // Runtime calls cannot be made against functions with no
                    // validator, except in the special case of self-calls to
                    // `installPlugin`, to enable removing the plugin protecting
                    // `installPlugin` and installing a different one as part of
                    // a single batch execution.
                    revert RuntimeValidationFunctionMissing(msg.sig);
                }
                // If _RUNTIME_VALIDATION_ALWAYS_ALLOW, or we're in the
                // `installPlugin` special case,just let the function finish,
                // without the else branch.
            } else {
                _updatePluginCallBufferSelector(callBuffer, IPlugin.runtimeValidationFunction.selector);

                (address plugin, uint8 functionId) = runtimeValidationFunction.unpack();

                _updatePluginCallBufferFunctionId(callBuffer, functionId);

                _executeRuntimePluginFunction(callBuffer, plugin, RuntimeValidationFunctionReverted.selector);
            }
        }
    }

    function _doPreExecHooks(bytes4 selector, bytes memory callBuffer)
        internal
        returns (FunctionReference[] memory, bytes[] memory)
    {
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];
        return _doPreHooks(
            selectorData.executionHooks.preHooks, selectorData.executionHooks.associatedPostHooks, callBuffer
        );
    }

    function _doPrePermittedCallHooks(bytes24 permittedCallKey, bytes memory callBuffer)
        internal
        returns (FunctionReference[] memory, bytes[] memory)
    {
        PermittedCallData storage permittedCallData = _getAccountStorage().permittedCalls[permittedCallKey];
        return _doPreHooks(
            permittedCallData.permittedCallHooks.preHooks,
            permittedCallData.permittedCallHooks.associatedPostHooks,
            callBuffer
        );
    }

    function _doPreHooks(
        LinkedListSet storage preHookSet,
        mapping(FunctionReference => LinkedListSet) storage associatedPostHooks,
        bytes memory callBuffer
    ) internal returns (FunctionReference[] memory postHooks, bytes[] memory postHookArgs) {
        FunctionReference[] memory preExecHooks = CastLib.toFunctionReferenceArray(preHookSet.getAll());

        uint256 preExecHooksLength = preExecHooks.length;
        uint256 maxPostHooksToRunLength;

        // There can only be as many associated post hooks to run as there are pre hooks.
        for (uint256 i = 0; i < preExecHooksLength;) {
            unchecked {
                maxPostHooksToRunLength += preHookSet.getCount(CastLib.toSetValue(preExecHooks[i]));
                ++i;
            }
        }

        // Overallocate on length, but not all of this may get filled up.
        postHooks = new FunctionReference[](maxPostHooksToRunLength);
        postHookArgs = new bytes[](maxPostHooksToRunLength);
        uint256 actualPostHooksToRunLength;

        // If not running anything, short-circuit before allocating more memory for the call buffers.
        if (preExecHooksLength == 0) {
            return (postHooks, postHookArgs);
        }

        if (callBuffer.length == 0) {
            // Allocate the call buffer for preExecHook. This case MUST NOT be reached by `executeFromPlugin`,
            // otherwise the call will execute with the wrong calldata. This case should only be reachable by
            // native functions with no runtime validation (i.e. being calling via a user operation).
            callBuffer = _allocateRuntimeCallBuffer(msg.data);
        }
        _updatePluginCallBufferSelector(callBuffer, IPlugin.preExecutionHook.selector);

        for (uint256 i = 0; i < preExecHooksLength;) {
            FunctionReference preExecHook = preExecHooks[i];

            if (preExecHook.isEmptyOrMagicValue()) {
                // The function reference must be the Always Deny magic value in this case,
                // because zero and any other magic value is unassignable here.
                revert AlwaysDenyRule();
            }

            (address plugin, uint8 functionId) = preExecHook.unpack();

            _updatePluginCallBufferFunctionId(callBuffer, functionId);

            if (preHookSet.flagsEnabled(CastLib.toSetValue(preExecHook), _PRE_EXEC_HOOK_HAS_POST_FLAG)) {
                FunctionReference[] memory associatedPostExecHooks =
                    CastLib.toFunctionReferenceArray(associatedPostHooks[preExecHook].getAll());
                uint256 associatedPostExecHooksLength = associatedPostExecHooks.length;

                for (uint256 j = 0; j < associatedPostExecHooksLength;) {
                    // Execute the pre-hook as many times as there are unique associated post-hooks.
                    _executeRuntimePluginFunction(callBuffer, plugin, PreExecHookReverted.selector);

                    postHooks[actualPostHooksToRunLength] = associatedPostExecHooks[j];
                    postHookArgs[actualPostHooksToRunLength] = abi.decode(_collectReturnData(), (bytes));

                    unchecked {
                        ++actualPostHooksToRunLength;
                        ++j;
                    }
                }
            } else {
                _executeRuntimePluginFunction(callBuffer, plugin, PreExecHookReverted.selector);
            }

            unchecked {
                ++i;
            }
        }

        // "Trim" the associated post hook arrays to the actual length, since we may have overallocated. This
        // allows for exeuction of post hooks in reverse order.
        assembly ("memory-safe") {
            mstore(postHooks, actualPostHooksToRunLength)
            mstore(postHookArgs, actualPostHooksToRunLength)
        }
    }

    function _doCachedPostHooks(FunctionReference[] memory postHooks, bytes[] memory postHookArgs) internal {
        uint256 postHooksToRunLength = postHooks.length;
        bool hasPostHookArgs = postHookArgs.length > 0;
        for (uint256 i = postHooksToRunLength; i > 0;) {
            FunctionReference postExecHook = postHooks[i - 1];
            (address plugin, uint8 functionId) = postExecHook.unpack();
            // solhint-disable-next-line no-empty-blocks
            try IPlugin(plugin).postExecutionHook(functionId, hasPostHookArgs ? postHookArgs[i - 1] : bytes("")) {}
            catch (bytes memory revertReason) {
                revert PostExecHookReverted(plugin, functionId, revertReason);
            }

            unchecked {
                --i;
            }
        }
    }

    /// @inheritdoc UUPSUpgradeable
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override {}

    /// @dev Revert with an appropriate error if the calldata does not include a function selector.
    function _selectorFromCallData(bytes calldata data) internal pure returns (bytes4) {
        if (data.length < 4) {
            revert UnrecognizedFunction(bytes4(data));
        }
        return bytes4(data);
    }
}