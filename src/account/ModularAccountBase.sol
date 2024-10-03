// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {
    Call,
    IModularAccount,
    ModuleEntity,
    ValidationConfig
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";

import {DIRECT_CALL_VALIDATION_ENTITYID} from "../helpers/Constants.sol";
import {_coalescePreValidation, _coalesceValidation} from "../helpers/ValidationResHelpers.sol";

import {ExecutionLib} from "../libraries/ExecutionLib.sol";
import {HookConfig, HookConfigLib} from "../libraries/HookConfigLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";
import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {ModuleEntityLib} from "../libraries/ModuleEntityLib.sol";
import {SparseCalldataSegmentLib} from "../libraries/SparseCalldataSegmentLib.sol";
import {ValidationConfigLib} from "../libraries/ValidationConfigLib.sol";
import {AccountStorage, getAccountStorage, toSetValue} from "./AccountStorage.sol";
import {AccountStorageInitializable} from "./AccountStorageInitializable.sol";
import {BaseAccount} from "./BaseAccount.sol";
import {ModularAccountView} from "./ModularAccountView.sol";
import {ModuleManagerInternals} from "./ModuleManagerInternals.sol";
import {TokenReceiver} from "./TokenReceiver.sol";

abstract contract ModularAccountBase is
    IModularAccount,
    ModularAccountView,
    AccountStorageInitializable,
    BaseAccount,
    IERC1271,
    IERC165,
    IAccountExecute,
    ModuleManagerInternals,
    UUPSUpgradeable,
    TokenReceiver
{
    using LinkedListSetLib for LinkedListSet;
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;
    using HookConfigLib for HookConfig;
    using SparseCalldataSegmentLib for bytes;

    struct DeferredValidationInstallData {
        ValidationConfig validationConfig;
        bytes4[] selectors;
        bytes installData;
        bytes[] hooks;
        uint256 nonce;
        uint48 deadline;
    }

    enum ValidationCheckingType {
        GLOBAL,
        SELECTOR,
        EITHER
    }

    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
    bytes32 internal constant _DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256("InstallValidation(bytes25 validationConfig,bytes4[] selectors,bytes installData,bytes[]
    // hooks,uint256 nonce,uint48 deadline)");
    bytes32 internal constant _INSTALL_VALIDATION_TYPEHASH =
        0xb5b726478a22c87521d285be8b6a8a12e8b0715e5b67a10114b963f2eac36d6c;

    // As per the EIP-165 spec, no interface should ever match 0xffffffff
    bytes4 internal constant _INTERFACE_ID_INVALID = 0xffffffff;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    uint8 internal constant _IS_GLOBAL_VALIDATION_BIT = 1;
    uint8 internal constant _IS_DEFERRED_INSTALL_VALIDATION_BIT = 2;

    event DeferredInstallNonceInvalidated(uint256 nonce);

    error PostExecHookReverted(address module, uint32 entityId, bytes revertReason);
    error PreExecHookReverted(address module, uint32 entityId, bytes revertReason);
    error PreRuntimeValidationHookFailed(address module, uint32 entityId, bytes revertReason);
    error RequireUserOperationContext();
    error RuntimeValidationFunctionReverted(address module, uint32 entityId, bytes revertReason);
    error SelfCallRecursionDepthExceeded();
    error SignatureValidationInvalid(address module, uint32 entityId);
    error UserOpValidationInvalid(address module, uint32 entityId);
    error UnexpectedAggregator(address module, uint32 entityId, address aggregator);
    error UnrecognizedFunction(bytes4 selector);
    error ValidationFunctionMissing(bytes4 selector);
    error DeferredInstallNonceInvalid();
    error DeferredInstallSignatureInvalid();
    error CreateFailed();

    // Wraps execution of a native function with runtime validation and hooks
    // Used for upgradeTo, upgradeToAndCall, execute, executeBatch, installExecution, uninstallExecution,
    // performCreate, performCreate2
    modifier wrapNativeFunction() {
        (HookConfig[] memory execHooks, bytes[] memory postExecHookData) =
            _checkPermittedCallerAndAssociatedHooks();

        _;

        _doCachedPostExecHooks(execHooks, postExecHookData);
    }

    constructor(IEntryPoint anEntryPoint) BaseAccount(anEntryPoint) {
        _disableInitializers();
    }

    // EXTERNAL FUNCTIONS

    receive() external payable {}

    /// @notice Fallback function
    /// @dev We route calls to execution functions based on incoming msg.sig
    /// @dev If there's no module associated with this function selector, revert
    fallback(bytes calldata) external payable returns (bytes memory) {
        address execModule = getAccountStorage().executionData[msg.sig].module;
        if (execModule == address(0)) {
            revert UnrecognizedFunction(msg.sig);
        }
        (HookConfig[] memory execHooks, bytes[] memory postHookDatas) = _checkPermittedCallerAndAssociatedHooks();

        // execute the function, bubbling up any reverts
        (bool execSuccess, bytes memory execReturnData) = execModule.call(msg.data);

        if (!execSuccess) {
            // Bubble up revert reasons from modules
            assembly ("memory-safe") {
                revert(add(execReturnData, 32), mload(execReturnData))
            }
        }

        _doCachedPostExecHooks(execHooks, postHookDatas);

        return execReturnData;
    }

    /// @notice Create a contract.
    /// @param value The value to send to the new contract constructor
    /// @param initCode The initCode to deploy.
    /// @return createdAddr The created contract address.
    ///
    /// @dev Assembly procedure:
    ///     1. Load the free memory pointer.
    ///     2. Get the initCode length.
    ///     3. Copy the initCode from callata to memory at the free memory pointer.
    ///     4. Create the contract.
    ///     5. If creation failed (the address returned is zero), revert with CreateFailed().
    function performCreate(uint256 value, bytes calldata initCode)
        external
        payable
        virtual
        wrapNativeFunction
        returns (address createdAddr)
    {
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            let len := initCode.length
            calldatacopy(fmp, initCode.offset, len)

            createdAddr := create(value, fmp, len)

            if iszero(createdAddr) {
                let createFailedError := 0x7e16b8cd
                mstore(0x00, createFailedError)
                revert(0x1c, 0x04)
            }
        }
    }

    /// @notice Creates a contract using create2 deterministic deployment.
    /// @param value The value to send to the new contract constructor.
    /// @param initCode The initCode to deploy.
    /// @param salt The salt to use for the create2 operation.
    /// @return createdAddr The created contract address.
    ///
    /// @dev Assembly procedure:
    ///     1. Load the free memory pointer.
    ///     2. Get the initCode length.
    ///     3. Copy the initCode from callata to memory at the free memory pointer.
    ///     4. Create the contract using Create2 with the passed salt parameter.
    ///     5. If creation failed (the address returned is zero), revert with CreateFailed().
    function performCreate2(uint256 value, bytes calldata initCode, bytes32 salt)
        external
        payable
        virtual
        wrapNativeFunction
        returns (address createdAddr)
    {
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            let len := initCode.length
            calldatacopy(fmp, initCode.offset, len)

            createdAddr := create2(value, fmp, len, salt)

            if iszero(createdAddr) {
                let createFailedError := 0x7e16b8cd
                mstore(0x00, createFailedError)
                revert(0x1c, 0x04)
            }
        }
    }

    /// @inheritdoc IAccountExecute
    /// @notice Execution function that allows UO context to be passed to execution hooks
    /// @dev This function is only callable by the EntryPoint
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external override {
        _requireFromEntryPoint();

        ModuleEntity userOpValidationFunction = ModuleEntity.wrap(bytes24(userOp.signature[:24]));

        HookConfig[] memory validationAssocExecHooks =
            MemManagementLib.loadExecHooks(getAccountStorage().validationData[userOpValidationFunction]);
        bytes[] memory postHookDatas = _doPreHooks(validationAssocExecHooks, msg.data);

        bytes memory callData = userOp.callData[4:];

        // Manually call self, without collecting return data unless there's a revert.
        ExecutionLib.callSelfBubbleOnRevert(callData);

        _doCachedPostExecHooks(validationAssocExecHooks, postHookDatas);
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        override
        wrapNativeFunction
        returns (bytes memory result)
    {
        result = ExecutionLib.exec(target, value, data);
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation function.
    function executeBatch(Call[] calldata calls)
        external
        payable
        override
        wrapNativeFunction
        returns (bytes[] memory results)
    {
        uint256 callsLength = calls.length;
        results = new bytes[](callsLength);

        for (uint256 i = 0; i < callsLength; ++i) {
            results[i] = ExecutionLib.exec(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /// @inheritdoc IModularAccount
    function executeWithRuntimeValidation(bytes calldata data, bytes calldata authorization)
        external
        payable
        returns (bytes memory)
    {
        // Revert if the provided `authorization` is less than 24 bytes long, rather than right-padding.
        ModuleEntity runtimeValidationFunction = ModuleEntity.wrap(bytes24(authorization[:24]));

        // Check if the runtime validation function is allowed to be called
        bool isGlobalValidation = uint8(authorization[24]) == 1;
        _checkIfValidationAppliesCallData(
            data,
            runtimeValidationFunction,
            isGlobalValidation ? ValidationCheckingType.GLOBAL : ValidationCheckingType.SELECTOR
        );

        _doRuntimeValidation(runtimeValidationFunction, data, authorization[25:]);

        // If runtime validation passes, run exec hooks associated with the validator
        HookConfig[] memory validationAssocExecHooks =
            MemManagementLib.loadExecHooks(getAccountStorage().validationData[runtimeValidationFunction]);
        bytes[] memory postHookData = _doPreHooks(validationAssocExecHooks, data);

        // Execute the call
        (bool success, bytes memory returnData) = address(this).call(data);

        if (!success) {
            assembly ("memory-safe") {
                revert(add(returnData, 32), mload(returnData))
            }
        }

        _doCachedPostExecHooks(validationAssocExecHooks, postHookData);

        return returnData;
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleInstallData
    ) external override wrapNativeFunction {
        _installExecution(module, manifest, moduleInstallData);
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    function uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleUninstallData
    ) external override wrapNativeFunction {
        _uninstallExecution(module, manifest, moduleUninstallData);
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    /// @dev This function can be used to update (to a certain degree) previously installed validation functions.
    ///      - preValidationHook, executionHooks, and selectors can be added later. Though they won't be deleted.
    ///      - isGlobal and isSignatureValidation can also be updated later.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external wrapNativeFunction {
        _installValidation(validationConfig, selectors, installData, hooks);
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) external wrapNativeFunction {
        _uninstallValidation(validationFunction, uninstallData, hookUninstallData);
    }

    /// @notice May be validated by a global validation
    function invalidateDeferredValidationInstallNonce(uint256 nonce) external wrapNativeFunction {
        getAccountStorage().deferredInstallNonceUsed[nonce] = true;
        emit DeferredInstallNonceInvalidated(nonce);
    }

    /// @inheritdoc IERC165
    /// @notice ERC165 introspection
    /// @dev returns true for `IERC165.interfaceId` and false for `0xFFFFFFFF`
    /// @param interfaceId interface id to check against
    /// @return bool support for specific interface
    function supportsInterface(bytes4 interfaceId) external view override returns (bool) {
        if (interfaceId == _INTERFACE_ID_INVALID) {
            return false;
        }
        if (
            interfaceId == type(IERC721Receiver).interfaceId || interfaceId == type(IERC1155Receiver).interfaceId
                || interfaceId == type(IERC165).interfaceId
        ) {
            return true;
        }

        return getAccountStorage().supportedIfaces[interfaceId] > 0;
    }

    /// @inheritdoc IModularAccount
    function accountId() external pure virtual returns (string memory) {
        return "alchemy.modular-account.0.0.1";
    }

    /// @inheritdoc UUPSUpgradeable
    /// @notice May be validated by a global validation.
    function upgradeToAndCall(address newImplementation, bytes calldata data)
        public
        payable
        override
        onlyProxy
        wrapNativeFunction
    {
        super.upgradeToAndCall(newImplementation, data);
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(_DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(this)));
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) public view returns (bytes4) {
        ModuleEntity sigValidation = ModuleEntity.wrap(bytes24(signature));
        signature = signature[24:];
        return _isValidSignature(sigValidation, hash, signature);
    }

    // INTERNAL FUNCTIONS

    // Parent function validateUserOp enforces that this call can only be made by the EntryPoint
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        override
        returns (uint256 validationData)
    {
        if (userOp.callData.length < 4) {
            revert UnrecognizedFunction(bytes4(userOp.callData));
        }

        // Revert if the provided `authorization` less than 24 bytes long, rather than right-padding.
        ModuleEntity validationFunction = ModuleEntity.wrap(bytes24(userOp.signature[:24]));

        // Decode the 25th byte into an 8-bit bitmap (6 bits of which remain unused).
        uint8 validationFlags = uint8(userOp.signature[24]);
        bool isGlobalValidation = validationFlags & _IS_GLOBAL_VALIDATION_BIT != 0;
        bool isDeferredInstallValidation = validationFlags & _IS_DEFERRED_INSTALL_VALIDATION_BIT != 0;

        // Assigned depending on whether the UO uses deferred validation installation or not.
        bytes calldata userOpSignature;

        /// The calldata layout is unique for deferred validation installation.
        /// Byte indices are [inclusive, exclusive]
        ///      [25:29] : uint32, encodedDatalength.
        ///      [29:(29 + encodedDatalength)] : bytes, abi-encoded deferred validation data.
        ///      [(29 + encodedDataLength):(33 + encodedDataLength)] : uint32, deferredInstallSigLength.
        ///      [(33 + encodedDataLength):(33 + deferredInstallSigLength + encodedDataLength)] : bytes,
        ///         deferred install sig. This is the signature passed to the outer validation decoded earlier.
        ///      [(33 + deferredInstallSigLength + encodedDataLength):] : bytes, userOpSignature. This is the
        ///         signature passed to the newly installed deferred validation.
        if (isDeferredInstallValidation) {
            // Use outer validation as a 1271 validation, then use the installed validation to validate the rest.
            // Check if the outer validation applies to `installValidation`.
            _checkIfValidationAppliesSelector(
                this.installValidation.selector,
                validationFunction, // Treated as sig val
                isGlobalValidation ? ValidationCheckingType.GLOBAL : ValidationCheckingType.SELECTOR
            );

            // Get the length of the abi-encoded `DeferredValidationInstallData` struct.
            uint256 encodedDataLength = uint32(bytes4(userOp.signature[25:29]));

            // Load the pointer to the abi-encoded data.
            bytes calldata encodedData = userOp.signature[29:29 + encodedDataLength];

            // Struct addresses stack too deep issues
            DeferredValidationInstallData memory deferredValidationInstallData;

            (
                deferredValidationInstallData.validationConfig,
                deferredValidationInstallData.selectors,
                deferredValidationInstallData.installData,
                deferredValidationInstallData.hooks,
                deferredValidationInstallData.nonce,
                deferredValidationInstallData.deadline
            ) = abi.decode(encodedData, (ValidationConfig, bytes4[], bytes, bytes[], uint256, uint48));

            // Get the deferred installation signature length.
            uint256 deferredInstallSigLength =
                uint32(bytes4(userOp.signature[29 + encodedDataLength:33 + encodedDataLength]));

            // Get the deferred installation signature, which is passed to the outer validation to install the
            // deferred validation.
            bytes calldata deferredInstallSig =
                userOp.signature[33 + encodedDataLength:33 + encodedDataLength + deferredInstallSigLength];

            //Validate the signature.
            _validateDeferredInstallDataAndSetNonce(
                validationFunction, deferredValidationInstallData, deferredInstallSig
            );

            // Use a self-call to install the deferred validation.
            this.installValidation(
                deferredValidationInstallData.validationConfig,
                deferredValidationInstallData.selectors,
                deferredValidationInstallData.installData,
                deferredValidationInstallData.hooks
            );

            // Update the outer scope functions to use the newly defer-installed validation and its isGlobal flag.
            validationFunction = deferredValidationInstallData.validationConfig.moduleEntity();
            isGlobalValidation = deferredValidationInstallData.validationConfig.isGlobal();

            // Update the UserOp signature to the remaining bytes.
            userOpSignature = userOp.signature[33 + encodedDataLength + deferredInstallSigLength:];

            validationData = uint256(deferredValidationInstallData.deadline) << 160;
        } else {
            userOpSignature = userOp.signature[25:];
        }

        _checkIfValidationAppliesCallData(
            userOp.callData,
            validationFunction,
            isGlobalValidation ? ValidationCheckingType.GLOBAL : ValidationCheckingType.SELECTOR
        );

        // Check if there are execution hooks associated with the validator, and revert if the call isn't to
        // `executeUserOp`. This check must be here because if context isn't passed, we can't tell in execution
        // which hooks should have ran.
        if (
            getAccountStorage().validationData[validationFunction].executionHookCount > 0
                && bytes4(userOp.callData[:4]) != this.executeUserOp.selector
        ) {
            revert RequireUserOperationContext();
        }
        uint256 userOpValidationRes = _doUserOpValidation(validationFunction, userOp, userOpSignature, userOpHash);

        // We only coalesce validations if the validation data from deferred installation is nonzero.
        if (validationData != 0) {
            // Parameter ordering is important here. We treat the validationData as pre-validation data because it
            // may be empty, or it may contain only the deadline from deferred installation, so
            // `_coalesceValidation()` must treat it as preValidationData.
            validationData = _coalesceValidation(validationData, userOpValidationRes);
        } else {
            validationData = userOpValidationRes;
        }
    }

    function _validateDeferredInstallDataAndSetNonce(
        ModuleEntity sigValidation,
        DeferredValidationInstallData memory installData,
        bytes calldata sig
    ) internal {
        // Check that the passed nonce isn't already invalidated.
        if (getAccountStorage().deferredInstallNonceUsed[installData.nonce]) {
            revert DeferredInstallNonceInvalid();
        }

        // Invalidate the nonce.
        getAccountStorage().deferredInstallNonceUsed[installData.nonce] = true;
        emit DeferredInstallNonceInvalidated(installData.nonce);

        // Compute the struct hash to be used to compute the replay safe hash for
        bytes32 structHash = keccak256(
            abi.encode(
                _INSTALL_VALIDATION_TYPEHASH,
                installData.validationConfig,
                installData.selectors,
                installData.installData,
                installData.hooks,
                installData.nonce,
                installData.deadline // Note that a zero deadline translates to "no deadline"
            )
        );

        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(domainSeparator(), structHash);

        if (_isValidSignature(sigValidation, typedDataHash, sig) != _1271_MAGIC_VALUE) {
            revert DeferredInstallSignatureInvalid();
        }
    }

    // To support gas estimation, we don't fail early when the failure is caused by a signature failure
    function _doUserOpValidation(
        ModuleEntity userOpValidationFunction,
        PackedUserOperation memory userOp,
        bytes calldata signature,
        bytes32 userOpHash
    ) internal returns (uint256) {
        uint256 validationRes;

        // Do preUserOpValidation hooks
        HookConfig[] memory preUserOpValidationHooks =
            MemManagementLib.loadValidationHooks(getAccountStorage().validationData[userOpValidationFunction]);

        for (uint256 i = preUserOpValidationHooks.length; i > 0; i) {
            // Decrement here, instead of in the loop body, to convert from length to an index.
            unchecked {
                --i;
            }

            (userOp.signature, signature) =
                signature.advanceSegmentIfAtIndex(uint8(preUserOpValidationHooks.length - i - 1));

            (address module, uint32 entityId) = preUserOpValidationHooks[i].moduleEntity().unpack();
            uint256 currentValidationRes =
                IValidationHookModule(module).preUserOpValidationHook(entityId, userOp, userOpHash);

            if (uint160(currentValidationRes) > 1) {
                // If the aggregator is not 0 or 1, it is an unexpected value
                revert UnexpectedAggregator(module, entityId, address(uint160(currentValidationRes)));
            }
            validationRes = _coalescePreValidation(validationRes, currentValidationRes);
        }

        // Run the user op validation function
        {
            userOp.signature = signature.getFinalSegment();

            uint256 currentValidationRes = _execUserOpValidation(userOpValidationFunction, userOp, userOpHash);

            if (preUserOpValidationHooks.length != 0) {
                // If we have other validation data we need to coalesce with
                validationRes = _coalesceValidation(validationRes, currentValidationRes);
            } else {
                validationRes = currentValidationRes;
            }
        }

        return validationRes;
    }

    function _doRuntimeValidation(
        ModuleEntity runtimeValidationFunction,
        bytes calldata callData,
        bytes calldata authorizationData
    ) internal {
        // run all preRuntimeValidation hooks
        HookConfig[] memory preRuntimeValidationHooks =
            MemManagementLib.loadValidationHooks(getAccountStorage().validationData[runtimeValidationFunction]);

        for (uint256 i = preRuntimeValidationHooks.length; i > 0;) {
            // Decrement here, instead of in the loop update step, to handle the case where the length is 0.
            unchecked {
                --i;
            }

            bytes memory currentAuthSegment;

            (currentAuthSegment, authorizationData) =
                authorizationData.advanceSegmentIfAtIndex(uint8(preRuntimeValidationHooks.length - i - 1));

            _doPreRuntimeValidationHook(preRuntimeValidationHooks[i].moduleEntity(), callData, currentAuthSegment);
        }

        authorizationData = authorizationData.getFinalSegment();

        _execRuntimeValidation(runtimeValidationFunction, callData, authorizationData);
    }

    function _doPreHooks(HookConfig[] memory hooks, bytes calldata data)
        internal
        returns (bytes[] memory postHookReturnData)
    {
        uint256 hooksLength = hooks.length;
        postHookReturnData = new bytes[](hooksLength);

        // Run the pre hooks and copy their return data to the post hooks array, if an associated post exec hook
        // exists.
        for (uint256 i = hooksLength; i > 0;) {
            // Decrement here, instead of in the loop update step, to handle the case where the length is 0.
            unchecked {
                --i;
            }

            HookConfig hookConfig = hooks[i];

            if (hookConfig.hasPreHook()) {
                bytes memory preExecHookReturnData = _runPreExecHook(hookConfig.moduleEntity(), data);

                // If there is an associated post exec hook, save the return data.
                if (hookConfig.hasPostHook()) {
                    postHookReturnData[i] = preExecHookReturnData;
                }
            }
        }
    }

    function _runPreExecHook(ModuleEntity preExecHook, bytes memory data)
        internal
        returns (bytes memory preExecHookReturnData)
    {
        (address module, uint32 entityId) = preExecHook.unpack();
        try IExecutionHookModule(module).preExecutionHook(entityId, msg.sender, msg.value, data) returns (
            bytes memory returnData
        ) {
            preExecHookReturnData = returnData;
        } catch {
            bytes memory revertReason = ExecutionLib.collectReturnData();
            revert PreExecHookReverted(module, entityId, revertReason);
        }
    }

    /// @dev Associated post hooks are run in reverse order of their pre hooks.
    function _doCachedPostExecHooks(HookConfig[] memory hooks, bytes[] memory hookData) internal {
        uint256 hooksLength = hooks.length;
        for (uint256 i = 0; i < hooksLength; ++i) {
            HookConfig hook = hooks[i];
            if (!hook.hasPostHook()) {
                // This does not have a post hook, so we skip it.
                continue;
            }

            (address module, uint32 entityId) = hook.moduleEntity().unpack();
            // solhint-disable-next-line no-empty-blocks
            try IExecutionHookModule(module).postExecutionHook(entityId, hookData[i]) {}
            catch {
                bytes memory revertReason = ExecutionLib.collectReturnData();
                revert PostExecHookReverted(module, entityId, revertReason);
            }
        }
    }

    function _doPreRuntimeValidationHook(
        ModuleEntity validationHook,
        bytes memory callData,
        bytes memory currentAuthData
    ) internal {
        (address hookModule, uint32 hookEntityId) = validationHook.unpack();
        try IValidationHookModule(hookModule).preRuntimeValidationHook(
            hookEntityId, msg.sender, msg.value, callData, currentAuthData
        )
        // forgefmt: disable-start
        // solhint-disable-next-line no-empty-blocks
        {} catch{
        // forgefmt: disable-end
            bytes memory revertReason = ExecutionLib.collectReturnData();
            revert PreRuntimeValidationHookFailed(hookModule, hookEntityId, revertReason);
        }
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override {}

    /**
     * Order of operations:
     *      1. Check if the sender is the entry point, the account itself, or the selector called is public.
     *          - Yes: Return an empty array, there are no post executionHooks.
     *          - No: Continue
     *      2. Check if the called selector (msg.sig) is included in the set of selectors the msg.sender can
     *         directly call.
     *          - Yes: Continue
     *          - No: Revert, the caller is not allowed to call this selector
     *      3. If there are runtime validation hooks associated with this caller-sig combination, run them.
     *      4. Run the pre executionHooks associated with this caller-sig combination, and return the
     *         post executionHooks to run later.
     */
    function _checkPermittedCallerAndAssociatedHooks() internal returns (HookConfig[] memory, bytes[] memory) {
        AccountStorage storage _storage = getAccountStorage();
        HookConfig[] memory execHooks;

        // We only need to handle execution hooks when the sender is not the entry point or the account itself,
        // and the selector isn't public.
        if (
            msg.sender != address(_ENTRY_POINT) && msg.sender != address(this)
                && !_storage.executionData[msg.sig].skipRuntimeValidation
        ) {
            ModuleEntity directCallValidationKey =
                ModuleEntityLib.pack(msg.sender, DIRECT_CALL_VALIDATION_ENTITYID);

            _checkIfValidationAppliesCallData(msg.data, directCallValidationKey, ValidationCheckingType.EITHER);

            // Direct call is allowed, run associated execution & validation hooks

            // Validation hooks
            HookConfig[] memory preRuntimeValidationHooks =
                MemManagementLib.loadValidationHooks(_storage.validationData[directCallValidationKey]);

            uint256 hookLen = preRuntimeValidationHooks.length;
            for (uint256 i = hookLen; i > 0;) {
                // Decrement here, instead of in the loop body, to convert from length to an index.
                unchecked {
                    --i;
                }

                _doPreRuntimeValidationHook(preRuntimeValidationHooks[i].moduleEntity(), msg.data, "");
            }

            //Load all execution hooks: both associated with the selector and the validation function.
            execHooks = MemManagementLib.loadExecHooks(
                _storage.executionData[msg.sig], _storage.validationData[directCallValidationKey]
            );
        } else {
            // If the sender is the entry point or the account itself, or the selector is public, this indicates
            // that validation was done elsewhere. We only need to run selector-associated execution hooks.
            execHooks = MemManagementLib.loadExecHooks(_storage.executionData[msg.sig]);
        }

        // Exec hooks associated with the selector
        bytes[] memory postHookDatas = _doPreHooks(execHooks, msg.data);

        return (execHooks, postHookDatas);
    }

    function _execUserOpValidation(
        ModuleEntity userOpValidationFunction,
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) internal virtual returns (uint256) {
        AccountStorage storage _storage = getAccountStorage();

        (address module, uint32 entityId) = userOpValidationFunction.unpack();

        if (!_storage.validationData[userOpValidationFunction].isUserOpValidation) {
            revert UserOpValidationInvalid(module, entityId);
        }

        return IValidationModule(module).validateUserOp(entityId, userOp, userOpHash);
    }

    function _execRuntimeValidation(
        ModuleEntity runtimeValidationFunction,
        bytes calldata callData,
        bytes calldata authorization
    ) internal virtual {
        (address module, uint32 entityId) = runtimeValidationFunction.unpack();

        try IValidationModule(module).validateRuntime(
            address(this), entityId, msg.sender, msg.value, callData, authorization
        )
        // forgefmt: disable-start
        // solhint-disable-next-line no-empty-blocks
        {} catch{
        // forgefmt: disable-end
            bytes memory revertReason = ExecutionLib.collectReturnData();
            revert RuntimeValidationFunctionReverted(module, entityId, revertReason);
        }
    }

    function _isValidSignature(ModuleEntity sigValidation, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bytes4)
    {
        HookConfig[] memory preSignatureValidationHooks =
            MemManagementLib.loadValidationHooks(getAccountStorage().validationData[sigValidation]);

        for (uint256 i = preSignatureValidationHooks.length; i > 0;) {
            // Decrement here, instead of in the loop body, to convert from length to an index.
            unchecked {
                --i;
            }

            (address hookModule, uint32 hookEntityId) = preSignatureValidationHooks[i].moduleEntity().unpack();

            bytes memory currentSignatureSegment;

            (currentSignatureSegment, signature) =
                signature.advanceSegmentIfAtIndex(uint8(preSignatureValidationHooks.length - i - 1));

            // If this reverts, bubble up revert reason.
            IValidationHookModule(hookModule).preSignatureValidationHook(
                hookEntityId, msg.sender, hash, currentSignatureSegment
            );
        }
        signature = signature.getFinalSegment();
        return _exec1271Validation(sigValidation, hash, signature);
    }

    function _exec1271Validation(ModuleEntity sigValidation, bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        returns (bytes4)
    {
        AccountStorage storage _storage = getAccountStorage();

        (address module, uint32 entityId) = sigValidation.unpack();
        if (!_storage.validationData[sigValidation].isSignatureValidation) {
            revert SignatureValidationInvalid(module, entityId);
        }

        if (
            IValidationModule(module).validateSignature(address(this), entityId, msg.sender, hash, signature)
                == _1271_MAGIC_VALUE
        ) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID;
    }

    function _globalValidationAllowed(bytes4 selector) internal view virtual returns (bool) {
        if (
            selector == this.execute.selector || selector == this.executeBatch.selector
                || selector == this.installExecution.selector || selector == this.uninstallExecution.selector
                || selector == this.installValidation.selector || selector == this.uninstallValidation.selector
                || selector == this.upgradeToAndCall.selector
                || selector == this.invalidateDeferredValidationInstallNonce.selector
                || selector == this.performCreate.selector || selector == this.performCreate2.selector
        ) {
            return true;
        }

        return getAccountStorage().executionData[selector].allowGlobalValidation;
    }

    function _isValidationGlobal(ModuleEntity validationFunction) internal view virtual returns (bool) {
        return getAccountStorage().validationData[validationFunction].isGlobal;
    }

    function _checkIfValidationAppliesCallData(
        bytes calldata callData,
        ModuleEntity validationFunction,
        ValidationCheckingType checkingType
    ) internal view {
        bytes4 outerSelector = bytes4(callData[:4]);
        if (outerSelector == this.executeUserOp.selector) {
            // If the selector is executeUserOp, pull the actual selector from the following data,
            // and trim the calldata to ensure the self-call decoding is still accurate.
            callData = callData[4:];
            outerSelector = bytes4(callData[:4]);
        }

        _checkIfValidationAppliesSelector(outerSelector, validationFunction, checkingType);

        if (outerSelector == IModularAccount.execute.selector) {
            (address target,,) = abi.decode(callData[4:], (address, uint256, bytes));

            if (target == address(this)) {
                // There is no point to call `execute` to recurse exactly once - this is equivalent to just having
                // the calldata as a top-level call.
                revert SelfCallRecursionDepthExceeded();
            }
        } else if (outerSelector == IModularAccount.executeBatch.selector) {
            // executeBatch may be used to batch account actions together, by targetting the account itself.
            // If this is done, we must ensure all of the inner calls are allowed by the provided validation
            // function.

            (Call[] memory calls) = abi.decode(callData[4:], (Call[]));

            for (uint256 i = 0; i < calls.length; ++i) {
                if (calls[i].target == address(this)) {
                    bytes4 nestedSelector = bytes4(calls[i].data);

                    if (
                        nestedSelector == IModularAccount.execute.selector
                            || nestedSelector == IModularAccount.executeBatch.selector
                    ) {
                        // To prevent arbitrarily-deep recursive checking, we limit the depth of self-calls to one
                        // for the purposes of batching.
                        // This means that all self-calls must occur at the top level of the batch.
                        // Note that modules of other contracts using `executeWithRuntimeValidation` may still
                        // independently call into this account with a different validation function, allowing
                        // composition of multiple batches.
                        revert SelfCallRecursionDepthExceeded();
                    }

                    _checkIfValidationAppliesSelector(nestedSelector, validationFunction, checkingType);
                }
            }
        }
    }

    function _checkIfValidationAppliesSelector(
        bytes4 selector,
        ModuleEntity validationFunction,
        ValidationCheckingType checkingType
    ) internal view {
        // Check that the provided validation function is applicable to the selector

        if (checkingType == ValidationCheckingType.GLOBAL) {
            if (!_globalValidationApplies(selector, validationFunction)) {
                revert ValidationFunctionMissing(selector);
            }
        } else if (checkingType == ValidationCheckingType.SELECTOR) {
            if (!_selectorValidationApplies(selector, validationFunction)) {
                revert ValidationFunctionMissing(selector);
            }
        } else {
            if (
                !_globalValidationApplies(selector, validationFunction)
                    && !_selectorValidationApplies(selector, validationFunction)
            ) {
                revert ValidationFunctionMissing(selector);
            }
        }
    }

    function _globalValidationApplies(bytes4 selector, ModuleEntity validationFunction)
        internal
        view
        returns (bool)
    {
        return _globalValidationAllowed(selector) && _isValidationGlobal(validationFunction);
    }

    function _selectorValidationApplies(bytes4 selector, ModuleEntity validationFunction)
        internal
        view
        returns (bool)
    {
        return getAccountStorage().validationData[validationFunction].selectors.contains(toSetValue(selector));
    }
}
