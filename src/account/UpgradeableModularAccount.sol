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
/// @notice A modular smart contract account (MSCA) that supports upgradeability and plugins.
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
    function initialize(address[] calldata plugins, bytes calldata pluginInitData) external initializer {
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
        // Either reuse the call buffer from runtime validation, or allocate a new one. It may or may not be used
        // for pre exec hooks but it will be used for the plugin execution itself.
        bytes memory callBuffer =
            (msg.sender != address(_ENTRY_POINT)) ? _doRuntimeValidation() : _allocateRuntimeCallBuffer(msg.data);

        // To comply with ERC-6900 phase rules, defer the loading of execution phase data until the completion of
        // runtime validation.
        // Validation may update account state and therefore change execution phase data. These values should also
        // be loaded before
        // we run the pre exec hooks, because they may modify which plugin is defined.
        SelectorData storage selectorData = _getAccountStorage().selectorData[msg.sig];
        address execPlugin = selectorData.plugin;
        if (execPlugin == address(0)) {
            revert UnrecognizedFunction(msg.sig);
        }

        (FunctionReference[][] memory postHooksToRun, bytes[] memory postHookArgs) =
            _doPreExecHooks(selectorData, callBuffer);

        // execute the function, bubbling up any reverts
        bool execSuccess = _executeRaw(execPlugin, _convertRuntimeCallBufferToExecBuffer(callBuffer));
        bytes memory execReturnData = _collectReturnData();

        if (!execSuccess) {
            // Bubble up revert reasons from plugins
            assembly ("memory-safe") {
                revert(add(execReturnData, 32), mload(execReturnData))
            }
        }

        _doCachedPostHooks(postHooksToRun, postHookArgs);

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

        bytes4 selector = _selectorFromCallData(userOp.callData);
        SelectorData storage selectorData = _getAccountStorage().selectorData[selector];

        FunctionReference userOpValidationFunction = selectorData.userOpValidation;
        bool hasPreValidationHooks = selectorData.hasPreUserOpValidationHooks;

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
        (FunctionReference[][] memory postExecHooks, bytes[] memory postHookArgs) = _preNativeFunction();
        result = _exec(target, value, data);
        _postNativeFunction(postExecHooks, postHookArgs);
    }

    /// @inheritdoc IStandardExecutor
    function executeBatch(Call[] calldata calls) external payable override returns (bytes[] memory results) {
        (FunctionReference[][] memory postExecHooks, bytes[] memory postHookArgs) = _preNativeFunction();

        uint256 callsLength = calls.length;
        results = new bytes[](callsLength);

        for (uint256 i = 0; i < callsLength;) {
            results[i] = _exec(calls[i].target, calls[i].value, calls[i].data);

            unchecked {
                ++i;
            }
        }

        _postNativeFunction(postExecHooks, postHookArgs);
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

        SelectorData storage selectorData = storage_.selectorData[selector];
        // Load the plugin address from storage prior to running any hooks, to abide by the ERC-6900 phase rules.
        address execFunctionPlugin = selectorData.plugin;

        (FunctionReference[][] memory postHooksToRun, bytes[] memory postHookArgs) =
            _doPrePermittedCallHooksAndPreExecHooks(selectorData, permittedCallData, callBuffer);

        if (execFunctionPlugin == address(0)) {
            revert UnrecognizedFunction(selector);
        }

        bool success = _executeRaw(execFunctionPlugin, _convertRuntimeCallBufferToExecBuffer(callBuffer));
        returnData = _collectReturnData();

        if (!success) {
            assembly ("memory-safe") {
                revert(add(returnData, 32), mload(returnData))
            }
        }

        _doCachedPostHooks(postHooksToRun, postHookArgs);

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

        // Target cannot be the account itself.
        if (target == address(this)) {
            revert ExecFromPluginExternalNotPermitted(callingPlugin, target, value, data);
        }

        // Check the caller plugin's permission to make this call on the target address.
        //
        // 1. Check that the target is permitted at all, and if so check that any one of the following is true:
        //   a. Is any selector permitted?
        //   b. Is the calldata empty? (allow empty data calls by default if the target address is permitted)
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

        // Run any pre permitted call hooks specific to this caller and the `executeFromPluginExternal` selector,
        // then run any pre-exec hooks associated with the `executeFromPluginExternal` selector.
        PermittedCallData storage permittedCallData = storage_.permittedCalls[_getPermittedCallKey(
            callingPlugin, IPluginExecutor.executeFromPluginExternal.selector
        )];
        SelectorData storage selectorData =
            storage_.selectorData[IPluginExecutor.executeFromPluginExternal.selector];

        (FunctionReference[][] memory postHooksToRun, bytes[] memory postHookArgs) =
            _doPrePermittedCallHooksAndPreExecHooks(selectorData, permittedCallData, "");

        // Perform the external call
        bytes memory returnData = _exec(target, value, data);

        _doCachedPostHooks(postHooksToRun, postHookArgs);

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
        (FunctionReference[][] memory postExecHooks, bytes[] memory postHookArgs) = _preNativeFunction();
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
        (FunctionReference[][] memory postExecHooks, bytes[] memory postHookArgs) = _preNativeFunction();

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
        (FunctionReference[][] memory postExecHooks, bytes[] memory postHookArgs) = _preNativeFunction();
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
        returns (FunctionReference[][] memory postExecHooks, bytes[] memory postHookArgs)
    {
        bytes memory callBuffer = "";

        if (msg.sender != address(_ENTRY_POINT)) {
            callBuffer = _doRuntimeValidation();
        }

        (postExecHooks, postHookArgs) = _doPreExecHooks(_getAccountStorage().selectorData[msg.sig], callBuffer);
    }

    /// @dev Wraps execution of a native function with runtime validation and hooks. Used for upgradeToAndCall,
    /// execute, executeBatch, installPlugin, uninstallPlugin.
    function _postNativeFunction(FunctionReference[][] memory postExecHooks, bytes[] memory postHookArgs)
        internal
    {
        _doCachedPostHooks(postExecHooks, postHookArgs);
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
                        && (
                            (
                                msg.sig != IPluginManager.installPlugin.selector
                                    && msg.sig != UUPSUpgradeable.upgradeToAndCall.selector
                            ) || msg.sender != address(this)
                        )
                ) {
                    // Runtime calls cannot be made against functions with no
                    // validator, except in the special case of self-calls to
                    // `installPlugin` and `upgradeToAndCall`, to enable removing the plugin protecting
                    // `installPlugin` and installing a different one as part of
                    // a single batch execution, and/or to enable upgrading the account implementation.
                    revert RuntimeValidationFunctionMissing(msg.sig);
                }
                // If _RUNTIME_VALIDATION_ALWAYS_ALLOW, or we're in the
                // `installPlugin` and `upgradeToAndCall` special case,just let the function finish,
                // without the else branch.
            } else {
                _updatePluginCallBufferSelector(callBuffer, IPlugin.runtimeValidationFunction.selector);

                (address plugin, uint8 functionId) = runtimeValidationFunction.unpack();

                _updatePluginCallBufferFunctionId(callBuffer, functionId);

                _executeRuntimePluginFunction(callBuffer, plugin, RuntimeValidationFunctionReverted.selector);
            }
        }
    }

    /// @dev Executes pre-exec hooks and returns the post-exec hooks to run and their associated args.
    function _doPreExecHooks(SelectorData storage selectorData, bytes memory callBuffer)
        internal
        returns (FunctionReference[][] memory postHooksToRun, bytes[] memory postHookArgs)
    {
        FunctionReference[] memory preExecHooks;

        bool hasPreExecHooks = selectorData.hasPreExecHooks;
        bool hasPostOnlyExecHooks = selectorData.hasPostOnlyExecHooks;

        if (hasPreExecHooks) {
            preExecHooks = CastLib.toFunctionReferenceArray(selectorData.executionHooks.preHooks.getAll());
        }

        // Allocate memory for the post hooks and post hook args.
        // If we have post-only hooks, we allocate an extra FunctionReference[] for them, and one extra element
        // in the args for their empty `bytes` argument.
        uint256 postHooksToRunLength = preExecHooks.length + (hasPostOnlyExecHooks ? 1 : 0);
        postHooksToRun = new FunctionReference[][](postHooksToRunLength);
        postHookArgs = new bytes[](postHooksToRunLength);

        uint256 currentIndex = 0;

        if (hasPostOnlyExecHooks) {
            // If we have post-only hooks, we allocate an single FunctionReference[] for them, and one element
            // in the args for their empty `bytes` argument. We put this into the first element of the post
            // hooks in order to have it run last.
            postHooksToRun[0] =
                CastLib.toFunctionReferenceArray(selectorData.executionHooks.postOnlyHooks.getAll());
            unchecked {
                ++currentIndex;
            }
        }

        // If there are no pre exec hooks, this will short-circuit in the length check on `preExecHooks`.
        _cacheAssociatedPostHooks(preExecHooks, selectorData.executionHooks, postHooksToRun, currentIndex);

        // Run all pre-exec hooks and capture their outputs.
        _doPreHooks(preExecHooks, callBuffer, postHooksToRun, postHookArgs, currentIndex);
    }

    /// @dev Executes pre-permitted call hooks and pre-exec hooks, and returns the post-exec hooks to run and
    /// their associated args.
    function _doPrePermittedCallHooksAndPreExecHooks(
        SelectorData storage selectorData,
        PermittedCallData storage permittedCallData,
        bytes memory callBuffer
    ) internal returns (FunctionReference[][] memory postHooksToRun, bytes[] memory postHookArgs) {
        FunctionReference[] memory prePermittedCallHooks;
        FunctionReference[] memory preExecHooks;

        bool hasPrePermittedCallHooks = permittedCallData.hasPrePermittedCallHooks;
        bool hasPostOnlyPermittedCallHooks = permittedCallData.hasPostOnlyPermittedCallHooks;

        bool hasPreExecHooks = selectorData.hasPreExecHooks;
        bool hasPostOnlyExecHooks = selectorData.hasPostOnlyExecHooks;

        // If we have any type of pre hooks, we need to allocate memory for them to perform their call.
        if (callBuffer.length == 0 && (hasPrePermittedCallHooks || hasPreExecHooks)) {
            callBuffer = _allocateRuntimeCallBuffer(msg.data);
        }

        if (hasPrePermittedCallHooks) {
            prePermittedCallHooks =
                CastLib.toFunctionReferenceArray(permittedCallData.permittedCallHooks.preHooks.getAll());
        }

        if (hasPreExecHooks) {
            preExecHooks = CastLib.toFunctionReferenceArray(selectorData.executionHooks.preHooks.getAll());
        }

        // Allocate memory for the post hooks and post hook args.
        // If we have post-only hooks, we allocate an extra FunctionReference[] for them, and one extra element in
        // the args for their empty `bytes` argument.
        uint256 postHooksToRunLength = prePermittedCallHooks.length + preExecHooks.length
            + (hasPostOnlyPermittedCallHooks ? 1 : 0) + (hasPostOnlyExecHooks ? 1 : 0);
        postHooksToRun = new FunctionReference[][](postHooksToRunLength);
        postHookArgs = new bytes[](postHooksToRunLength);

        uint256 currentIndex = 0;

        if (hasPostOnlyPermittedCallHooks) {
            // If we have post-only hooks, we allocate an single FunctionReference[] for them, and one element in
            // the args for their empty `bytes` argument. We put this into the first element of the post hooks in
            // order to have it run last.
            postHooksToRun[currentIndex] =
                CastLib.toFunctionReferenceArray(permittedCallData.permittedCallHooks.postOnlyHooks.getAll());
            unchecked {
                ++currentIndex;
            }
        }

        if (hasPostOnlyExecHooks) {
            // If we have post-only hooks, we allocate an single FunctionReference[] for them, and one element in
            // the args for their empty `bytes` argument. We put this into the first element of the post hooks in
            // order to have it run last.
            postHooksToRun[currentIndex] =
                CastLib.toFunctionReferenceArray(selectorData.executionHooks.postOnlyHooks.getAll());
            unchecked {
                ++currentIndex;
            }
        }

        // Cache post-permitted-call hooks in memory
        _cacheAssociatedPostHooks(
            prePermittedCallHooks, permittedCallData.permittedCallHooks, postHooksToRun, currentIndex
        );

        // Cache post-exec hooks in memory
        // We use `currentIndex + prePermittedCallHooks.length` for the starting index but do not update it,
        // because its current value is useful for executing the hooks.
        uint256 preExecHookStartingIndex = currentIndex + prePermittedCallHooks.length;
        _cacheAssociatedPostHooks(
            preExecHooks, selectorData.executionHooks, postHooksToRun, preExecHookStartingIndex
        );

        // Run the permitted call hooks
        _doPreHooks(prePermittedCallHooks, callBuffer, postHooksToRun, postHookArgs, currentIndex);

        // Run the pre-exec hooks
        _doPreHooks(preExecHooks, callBuffer, postHooksToRun, postHookArgs, preExecHookStartingIndex);
    }

    /// @dev Execute all pre hooks provided, using the call buffer if provided.
    /// Outputs are captured into the `hookReturnData` array, in increasing index starting at `startingIndex`.
    /// The `postHooks` array is used to determine whether or not to capture the return data.
    /// NOTE: The caller must ensure that:
    /// - `postHooks` is allocated, and `startingIndex + preHooks.length` does not exceed the array bounds of
    /// `postHooks`.
    /// - `hookReturnData` is allocated, and `startingIndex + preHooks.length` does not exceed the array bounds of
    /// `hookReturnData`.
    function _doPreHooks(
        FunctionReference[] memory preHooks,
        bytes memory callBuffer,
        FunctionReference[][] memory postHooks, // Only used to check if any post hooks exist.
        bytes[] memory hookReturnData,
        uint256 startingIndex // Where to start writing into hookReturnData
    ) internal {
        uint256 preExecHooksLength = preHooks.length;

        // If not running anything, short-circuit before allocating more memory for the call buffers.
        if (preExecHooksLength == 0) {
            return;
        }

        if (callBuffer.length == 0) {
            // Allocate the call buffer for preExecHook. This case MUST NOT be reached by `executeFromPlugin`,
            // otherwise the call will execute with the wrong calldata. This case should only be reachable by
            // native functions with no runtime validation (i.e. being calling via a user operation).
            callBuffer = _allocateRuntimeCallBuffer(msg.data);
        }
        _updatePluginCallBufferSelector(callBuffer, IPlugin.preExecutionHook.selector);

        for (uint256 i = 0; i < preExecHooksLength;) {
            FunctionReference preExecHook = preHooks[i];

            if (preExecHook.isEmptyOrMagicValue()) {
                // The function reference must be the Always Deny magic value in this case,
                // because zero and any other magic value is unassignable here.
                revert AlwaysDenyRule();
            }

            (address plugin, uint8 functionId) = preExecHook.unpack();

            _updatePluginCallBufferFunctionId(callBuffer, functionId);

            _executeRuntimePluginFunction(callBuffer, plugin, PreExecHookReverted.selector);

            uint256 adjustedIndex;
            unchecked {
                adjustedIndex = startingIndex + i;
            }

            // Only collect the return data if there is at least one post-hook to consume it.
            if (postHooks[adjustedIndex].length > 0) {
                hookReturnData[adjustedIndex] = abi.decode(_collectReturnData(), (bytes));
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Executes all post hooks in the nested array, using the corresponding args in the nested array.
    /// Executes the elements in reverse order, so the caller should ensure the correct ordering before calling.
    function _doCachedPostHooks(FunctionReference[][] memory postHooks, bytes[] memory postHookArgs) internal {
        // Run post hooks in reverse order of their associated pre hooks.
        uint256 postHookArrsLength = postHooks.length;
        for (uint256 i = postHookArrsLength; i > 0;) {
            uint256 index;
            unchecked {
                // i starts as the length of the array and goes to 1, not zero, to avoid underflowing.
                // To use the index for array access, we need to subtract 1.
                index = i - 1;
            }
            FunctionReference[] memory postHooksToRun = postHooks[index];

            // We don't need to run each associated post-hook in reverse order, because the associativity we want
            // to maintain is reverse order of associated pre-hooks.
            uint256 postHooksToRunLength = postHooksToRun.length;
            for (uint256 j = 0; j < postHooksToRunLength;) {
                (address plugin, uint8 functionId) = postHooksToRun[j].unpack();

                // Execute the post hook with the current post hook args
                // solhint-disable-next-line no-empty-blocks
                try IPlugin(plugin).postExecutionHook(functionId, postHookArgs[index]) {}
                catch (bytes memory revertReason) {
                    revert PostExecHookReverted(plugin, functionId, revertReason);
                }

                unchecked {
                    ++j;
                }
            }

            unchecked {
                --i;
            }
        }
    }

    /// @inheritdoc UUPSUpgradeable
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override {}

    /// @dev Loads the associated post hooks for the given pre-exec hooks in the `postHooks` array, starting at
    /// `startingIndex`.
    /// NOTE: The caller must ensure that `postHooks` is allocated, and `startingIndex + preHooks.length` does not
    // exceed the array bounds of `postHooks`.
    function _cacheAssociatedPostHooks(
        FunctionReference[] memory preExecHooks,
        HookGroup storage hookGroup,
        FunctionReference[][] memory postHooks,
        uint256 startingIndex
    ) internal view {
        uint256 preExecHooksLength = preExecHooks.length;
        for (uint256 i = 0; i < preExecHooksLength;) {
            FunctionReference preExecHook = preExecHooks[i];

            // If the pre-exec hook has associated post hooks, cache them in the postHooks array.
            if (hookGroup.preHooks.flagsEnabled(CastLib.toSetValue(preExecHook), _PRE_EXEC_HOOK_HAS_POST_FLAG)) {
                // We start writing into the postHooks array starting at the `startingIndex` and counting up.
                postHooks[startingIndex + i] =
                    CastLib.toFunctionReferenceArray(hookGroup.associatedPostHooks[preExecHook].getAll());
            }
            // In no-associated-post-hooks case, we're OK returning the default value, which is an array of length
            // 0.

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Revert with an appropriate error if the calldata does not include a function selector.
    function _selectorFromCallData(bytes calldata data) internal pure returns (bytes4) {
        if (data.length < 4) {
            revert UnrecognizedFunction(bytes4(data));
        }
        return bytes4(data);
    }
}
