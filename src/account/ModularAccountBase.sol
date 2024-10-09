// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {
    Call,
    HookConfig,
    IModularAccount,
    ModuleEntity,
    ValidationConfig
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {HookConfig, HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

import {DIRECT_CALL_VALIDATION_ENTITYID} from "../helpers/Constants.sol";
import {getEmptyCalldataSlice} from "../helpers/EmptyCalldataSlice.sol";
import {_coalescePreValidation, _coalesceValidation} from "../helpers/ValidationResHelpers.sol";
import {
    DensePostHookData,
    ExecutionLib,
    PHCallBuffer,
    RTCallBuffer,
    UOCallBuffer
} from "../libraries/ExecutionLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";
import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {SparseCalldataSegmentLib} from "../libraries/SparseCalldataSegmentLib.sol";
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

    enum ValidationCheckingType {
        GLOBAL,
        SELECTOR,
        EITHER
    }

    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
    bytes32 internal constant _DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256("InstallValidation(uint256 nonce,uint48 deadline,bytes validationInstall)")
    bytes32 internal constant _INSTALL_VALIDATION_TYPEHASH =
        0x03ffe0a4f7bbcd0e07af14f95a1c08895063811809f7bedb7ac6a2cce22acd5f;

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
    error DeferredInstallSelectorInvalid();
    error DeferredInstallNonceInvalid();
    error DeferredInstallSignatureInvalid();
    error CreateFailed();

    // Wraps execution of a native function with runtime validation and hooks
    // Used for upgradeTo, upgradeToAndCall, execute, executeBatch, installExecution, uninstallExecution,
    // performCreate, performCreate2
    modifier wrapNativeFunction() {
        DensePostHookData postHookData = _checkPermittedCallerAndAssociatedHooks();

        _;

        ExecutionLib.doCachedPostHooks(postHookData);
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
        DensePostHookData postHookData = _checkPermittedCallerAndAssociatedHooks();

        // execute the function, bubbling up any reverts
        (bool execSuccess, bytes memory execReturnData) = execModule.call(msg.data);

        if (!execSuccess) {
            // Bubble up revert reasons from modules
            assembly ("memory-safe") {
                revert(add(execReturnData, 32), mload(execReturnData))
            }
        }

        ExecutionLib.doCachedPostHooks(postHookData);

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

        PHCallBuffer callBuffer;
        if (validationAssocExecHooks.length > 0) {
            callBuffer = ExecutionLib.allocatePreExecHookCallBuffer(msg.data);
        }

        DensePostHookData postHookData = ExecutionLib.doPreHooks(validationAssocExecHooks, callBuffer);

        bytes memory callData = ExecutionLib.getExecuteUOCallData(callBuffer, userOp.callData);

        // Manually call self, without collecting return data unless there's a revert.
        ExecutionLib.callSelfBubbleOnRevert(callData);

        ExecutionLib.doCachedPostHooks(postHookData);
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
        _checkIfValidationAppliesCallData(
            data,
            runtimeValidationFunction,
            // Unfortunately, have to avoid declaring a `bool isGlobalValidation` to avoid stack too deep issues.
            uint8(authorization[24]) == 1 ? ValidationCheckingType.GLOBAL : ValidationCheckingType.SELECTOR
        );

        RTCallBuffer rtCallBuffer = _doRuntimeValidation(runtimeValidationFunction, data, authorization[25:]);

        // If runtime validation passes, run exec hooks associated with the validator
        HookConfig[] memory validationAssocExecHooks =
            MemManagementLib.loadExecHooks(getAccountStorage().validationData[runtimeValidationFunction]);

        PHCallBuffer phCallBuffer;
        if (validationAssocExecHooks.length > 0) {
            phCallBuffer = ExecutionLib.convertToPreHookCallBuffer(rtCallBuffer, data);
        }
        DensePostHookData postHookData = ExecutionLib.doPreHooks(validationAssocExecHooks, phCallBuffer);

        // Execute the call, reusing the already-allocated RT call buffers, if it exists.
        // In practice, this is cheaper than attempting to coalesce the (possibly two) buffers.
        bytes memory returnData =
            ExecutionLib.exec(address(this), 0 wei, ExecutionLib.getCallData(rtCallBuffer, data));

        ExecutionLib.doCachedPostHooks(postHookData);

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

            // Get the deferred installation signature length.
            uint256 deferredInstallSigLength =
                uint32(bytes4(userOp.signature[29 + encodedDataLength:33 + encodedDataLength]));

            // Get the deferred installation signature, which is passed to the outer validation to install the
            // deferred validation.
            bytes calldata deferredInstallSig =
                userOp.signature[33 + encodedDataLength:33 + encodedDataLength + deferredInstallSigLength];

            //Validate the signature.
            uint48 deadline =
                _validateDeferredInstallDataAndSetNonce(validationFunction, encodedData, deferredInstallSig);
            // Update the validation data with the deadline.
            validationData = uint256(deadline) << 160;

            // Call `installValidation` on the account.
            ExecutionLib.callSelfBubbleOnRevertTransient(encodedData[38:]);

            // Update the UserOp signature to the remaining bytes.
            userOpSignature = userOp.signature[33 + encodedDataLength + deferredInstallSigLength:];

            // Load in the validation that was just installed.
            ValidationConfig deferredInstallValidation = ValidationConfig.wrap(bytes25(encodedData[42:67]));
            validationFunction = deferredInstallValidation.moduleEntity();
            isGlobalValidation = deferredInstallValidation.isGlobal();
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
        uint256 userOpValidationRes = _doUserOpValidation(userOp, userOpHash, validationFunction, userOpSignature);

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

    /// @return The deadline of the deferred validation.
    function _validateDeferredInstallDataAndSetNonce(
        ModuleEntity sigValidation,
        bytes calldata encodedData,
        bytes calldata sig
    ) internal returns (uint48) {
        // Decode stack vars for the deadline and nonce.
        uint256 nonce = uint256(bytes32(encodedData[:32]));
        uint48 deadline = uint48(bytes6(encodedData[32:38]));

        // Assert the function being called is `installValidation`.
        if (bytes4(encodedData[38:42]) != this.installValidation.selector) {
            revert DeferredInstallSelectorInvalid();
        }

        // Check that the passed nonce isn't already invalidated.
        if (getAccountStorage().deferredInstallNonceUsed[nonce]) {
            revert DeferredInstallNonceInvalid();
        }

        // Invalidate the nonce.
        getAccountStorage().deferredInstallNonceUsed[nonce] = true;
        emit DeferredInstallNonceInvalidated(nonce);

        // Compute the typed data hash to verify the signature over
        bytes32 typedDataHash = _computeDeferredValidationInstallTypedDataHash(
            encodedData[38:], // The encoded call without the nonce and deadline
            nonce,
            deadline
        );

        if (_isValidSignature(sigValidation, typedDataHash, sig) != _1271_MAGIC_VALUE) {
            revert DeferredInstallSignatureInvalid();
        }

        return deadline;
    }

    // To support gas estimation, we don't fail early when the failure is caused by a signature failure
    function _doUserOpValidation(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        ModuleEntity userOpValidationFunction,
        bytes calldata signature
    ) internal returns (uint256) {
        uint256 validationRes;

        // Do preUserOpValidation hooks
        HookConfig[] memory preUserOpValidationHooks =
            MemManagementLib.loadValidationHooks(getAccountStorage().validationData[userOpValidationFunction]);

        UOCallBuffer userOpCallBuffer;
        if (!_validationIsNative(userOpValidationFunction) || preUserOpValidationHooks.length > 0) {
            userOpCallBuffer = ExecutionLib.allocateUserOpValidationCallBuffer(userOp, userOpHash);
        }
        bytes calldata currentSignatureSlice;
        for (uint256 i = preUserOpValidationHooks.length; i > 0; i) {
            // Decrement here, instead of in the loop body, to convert from length to an index.
            unchecked {
                --i;
            }

            (currentSignatureSlice, signature) =
                signature.advanceSegmentIfAtIndex(uint8(preUserOpValidationHooks.length - i - 1));

            uint256 currentValidationRes = ExecutionLib.invokeUserOpCallBuffer(
                userOpCallBuffer, preUserOpValidationHooks[i].moduleEntity(), currentSignatureSlice
            );

            if (uint160(currentValidationRes) > 1) {
                // If the aggregator is not 0 or 1, it is an unexpected value
                (address module, uint32 entityId) = preUserOpValidationHooks[i].moduleEntity().unpack();
                revert UnexpectedAggregator(module, entityId, address(uint160(currentValidationRes)));
            }
            validationRes = _coalescePreValidation(validationRes, currentValidationRes);
        }

        // Run the user op validation function
        {
            currentSignatureSlice = signature.getFinalSegment();

            uint256 currentValidationRes = _execUserOpValidation(
                userOpValidationFunction, userOpHash, currentSignatureSlice, userOpCallBuffer
            );

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
    ) internal returns (RTCallBuffer) {
        // run all preRuntimeValidation hooks
        HookConfig[] memory preRuntimeValidationHooks =
            MemManagementLib.loadValidationHooks(getAccountStorage().validationData[runtimeValidationFunction]);

        RTCallBuffer callBuffer;
        if (!_validationIsNative(runtimeValidationFunction) || preRuntimeValidationHooks.length > 0) {
            callBuffer = ExecutionLib.allocateRuntimeValidationCallBuffer(callData, authorizationData);
        }

        for (uint256 i = preRuntimeValidationHooks.length; i > 0;) {
            // Decrement here, instead of in the loop update step, to handle the case where the length is 0.
            unchecked {
                --i;
            }

            bytes calldata currentAuthSegment;

            (currentAuthSegment, authorizationData) =
                authorizationData.advanceSegmentIfAtIndex(uint8(preRuntimeValidationHooks.length - i - 1));

            ExecutionLib.invokeRuntimeCallBufferPreValidationHook(
                callBuffer, preRuntimeValidationHooks[i], currentAuthSegment
            );
        }

        authorizationData = authorizationData.getFinalSegment();

        _execRuntimeValidation(runtimeValidationFunction, callBuffer, authorizationData);

        return callBuffer;
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
    function _checkPermittedCallerAndAssociatedHooks() internal returns (DensePostHookData) {
        AccountStorage storage _storage = getAccountStorage();
        HookConfig[] memory execHooks;

        RTCallBuffer rtCallBuffer;

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

            uint256 preRuntimeValidationHooksLength = preRuntimeValidationHooks.length;
            if (preRuntimeValidationHooksLength > 0) {
                rtCallBuffer = ExecutionLib.allocateRuntimeValidationCallBuffer(msg.data, getEmptyCalldataSlice());
            }

            for (uint256 i = preRuntimeValidationHooksLength; i > 0;) {
                // Decrement here, instead of in the loop body, to convert from length to an index.
                unchecked {
                    --i;
                }

                ExecutionLib.invokeRuntimeCallBufferPreValidationHook(
                    rtCallBuffer, preRuntimeValidationHooks[i], getEmptyCalldataSlice()
                );
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

        PHCallBuffer preHookCallBuffer;
        if (execHooks.length > 0) {
            preHookCallBuffer = ExecutionLib.convertToPreHookCallBuffer(rtCallBuffer, msg.data);
        }

        // Exec hooks associated with the selector
        DensePostHookData postHookData = ExecutionLib.doPreHooks(execHooks, preHookCallBuffer);

        return postHookData;
    }

    function _execUserOpValidation(
        ModuleEntity userOpValidationFunction,
        bytes32,
        bytes calldata signatureSegment,
        UOCallBuffer callBuffer
    ) internal virtual returns (uint256) {
        AccountStorage storage _storage = getAccountStorage();

        if (!_storage.validationData[userOpValidationFunction].isUserOpValidation) {
            (address module, uint32 entityId) = userOpValidationFunction.unpack();
            revert UserOpValidationInvalid(module, entityId);
        }

        ExecutionLib.convertToValidationBuffer(callBuffer);

        return ExecutionLib.invokeUserOpCallBuffer(callBuffer, userOpValidationFunction, signatureSegment);
    }

    function _execRuntimeValidation(
        ModuleEntity runtimeValidationFunction,
        RTCallBuffer callBuffer,
        bytes calldata authorization
    ) internal virtual {
        ExecutionLib.invokeRuntimeCallBufferValidation(callBuffer, runtimeValidationFunction, authorization);
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
        if (callData.length < 4) {
            revert UnrecognizedFunction(bytes4(callData));
        }

        bytes4 outerSelector = bytes4(callData);
        if (outerSelector == this.executeUserOp.selector) {
            // If the selector is executeUserOp, pull the actual selector from the following data,
            // and trim the calldata to ensure the self-call decoding is still accurate.
            callData = callData[4:];
            outerSelector = bytes4(callData[:4]);
        }

        _checkIfValidationAppliesSelector(outerSelector, validationFunction, checkingType);

        if (outerSelector == IModularAccount.execute.selector) {
            address target = MemManagementLib.getExecuteTarget(callData);

            if (target == address(this)) {
                // There is no point to call `execute` to recurse exactly once - this is equivalent to just having
                // the calldata as a top-level call.
                revert SelfCallRecursionDepthExceeded();
            }
        } else if (outerSelector == IModularAccount.executeBatch.selector) {
            // executeBatch may be used to batch account actions together, by targetting the account itself.
            // If this is done, we must ensure all of the inner calls are allowed by the provided validation
            // function.
            _checkExecuteBatchApplicability(callData[4:], validationFunction, checkingType);
        }
    }

    /// @notice Checks if the validation function is allowed to perform this call to `executeBatch`.
    /// @param callData The calldata to check, excluding the `executeBatch` selector.
    /// @param validationFunction The validation function to check against.
    /// @param checkingType The type of validation checking to perform.
    function _checkExecuteBatchApplicability(
        bytes calldata callData,
        ModuleEntity validationFunction,
        ValidationCheckingType checkingType
    ) internal view {
        // Equivalent to the following code, but without using memory.

        // (Call[] memory calls) = abi.decode(callData[4:], (Call[]));

        // for (uint256 i = 0; i < calls.length; ++i) {
        //     if (calls[i].target == address(this)) {
        //         bytes4 nestedSelector = bytes4(calls[i].data[:4]);

        //         if (
        //             nestedSelector == IModularAccount.execute.selector
        //                 || nestedSelector == IModularAccount.executeBatch.selector
        //         ) {
        //
        //             revert SelfCallRecursionDepthExceeded();
        //         }

        //         _checkIfValidationAppliesSelector(nestedSelector, validationFunction, checkingType);
        //     }
        // }

        // The following is adapted from the compiler-generated ABI decoder for the `Call[]` parameter type.
        // See test/mocks/MockDecoder.sol for more info.

        // The end of allowed calldata to read. Declared in an outer context to make available to multiple code
        // blocks.
        uint256 dataEnd;

        // The absolute offset of the start of the `Call[]` array.
        uint256 arrayPos;
        // The length of the `Call[]` array.
        uint256 callsLength;

        assembly ("memory-safe") {
            // Set up the "safe data decoding range"
            let headStart := callData.offset
            dataEnd := add(headStart, callData.length)

            // Assert it is safe to load the offset
            if slt(sub(dataEnd, headStart), 32) { revert(0, 0) }

            // Load and sanitize the offset
            let relOffset := calldataload(callData.offset)
            if gt(relOffset, 0xffffffffffffffff) { revert(0, 0) }

            // Convert from a relative offset to an absolute offset.
            let absOffset := add(headStart, relOffset)

            // Assert it is safe to load the length
            if iszero(slt(add(absOffset, 0x1f), dataEnd)) { revert(0, 0) }

            // Load and sanitize the length
            callsLength := calldataload(absOffset)
            if gt(callsLength, 0xffffffffffffffff) { revert(0, 0) }

            // Load the array position, and check that it fits within the alloted length.
            arrayPos := add(absOffset, 0x20)
            if gt(add(arrayPos, mul(callsLength, 0x20)), dataEnd) { revert(0, 0) }
        }

        // Now, we have the array length and data bounds.
        // Iterate through the array elements, checking:
        // - If the target is this account, assert that:
        //   - the selector in the data field is not `execute` or `executeBatch`.
        //   - the provided validation is allowed to call the selector.

        for (uint256 i = 0; i < callsLength; ++i) {
            address callTarget;
            uint256 structAbsOffset;

            assembly ("memory-safe") {
                // Load and sanitize the struct offset.
                // This is still safe to load, from the bounds check above.
                let structRelOffset := calldataload(add(arrayPos, mul(i, 0x20)))
                if gt(structRelOffset, 0xffffffffffffffff) { revert(0, 0) }
                // Validate struct offset. If the offset points to a location with < 3 words of space before the
                // end of data, revert.
                if iszero(slt(structRelOffset, sub(sub(dataEnd, arrayPos), sub(0x60, 1)))) { revert(0, 0) }

                structAbsOffset := add(arrayPos, structRelOffset)

                // Load the address from the struct, and sanitize its contents, to mirror the behavior of the ABI
                // decoder.
                callTarget := calldataload(structAbsOffset)
                if iszero(eq(and(callTarget, 0xffffffffffffffffffffffffffffffffffffffff), callTarget)) {
                    revert(0, 0)
                }
            }

            if (callTarget == address(this)) {
                // In this case, we must load the selector, deny if it's `execute` or `executeBatch`, and check
                // validation applicability.

                uint32 selector;

                assembly ("memory-safe") {
                    // Load and sanitize the data offset.
                    let dataRelOffset := calldataload(add(structAbsOffset, 0x40))
                    if gt(dataRelOffset, 0xffffffffffffffff) { revert(0, 0) }

                    // Validate data offset. If the offset points to a location with < 1 words of space before the
                    // end of data, revert.
                    if iszero(slt(dataRelOffset, sub(sub(dataEnd, structAbsOffset), sub(0x20, 1)))) {
                        revert(0, 0)
                    }

                    let dataAbsOffset := add(structAbsOffset, dataRelOffset)

                    // Load and sanitize the data length.
                    let dataLength := calldataload(dataAbsOffset)
                    if gt(dataLength, 0xffffffff) { revert(0, 0) }

                    // Get the data offset, and assert that the following data fits into the bounded calldata
                    // range.
                    let dataOffset := add(dataAbsOffset, 0x20)
                    if sgt(dataOffset, sub(dataEnd, mul(dataLength, 0x01))) { revert(0, 0) }

                    // Finally, load the selector being called. This will be the first 4 bytes of the data.
                    // If the data length is less than 4, revert.
                    if slt(dataLength, 4) { revert(0, 0) }
                    selector := shr(224, calldataload(dataOffset))
                }

                if (selector == uint32(this.execute.selector) || selector == uint32(this.executeBatch.selector)) {
                    // To prevent arbitrarily-deep recursive checking, we limit the depth of self-calls to one
                    // for the purposes of batching.
                    // This means that all self-calls must occur at the top level of the batch.
                    // Note that modules of other contracts using `executeWithRuntimeValidation` may still
                    // independently call into this account with a different validation function, allowing
                    // composition of multiple batches.

                    revert SelfCallRecursionDepthExceeded();
                }

                _checkIfValidationAppliesSelector(bytes4(selector), validationFunction, checkingType);
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

    function _computeDeferredValidationInstallTypedDataHash(
        bytes calldata encodedInstallCall,
        uint256 nonce,
        uint48 deadline
    ) internal view returns (bytes32) {
        // bytes32 result;

        // Compute the hash without permanently allocating memory for each step.
        // The following is equivalent to:
        // keccak256(
        //     abi.encode(
        //         _INSTALL_VALIDATION_TYPEHASH,
        //         nonce,
        //         deadline,
        //         keccak256(encodedInstallCall)
        //     )
        // )

        // Note that a zero deadline translates to "no deadline"

        bytes32 structHash;

        assembly ("memory-safe") {
            // Get the hash of the dynamic-length encoded install call
            let fmp := mload(0x40)
            calldatacopy(fmp, encodedInstallCall.offset, encodedInstallCall.length)
            let installCallHash := keccak256(fmp, encodedInstallCall.length)

            // Compute the struct hash
            let ptr := fmp
            mstore(ptr, _INSTALL_VALIDATION_TYPEHASH)
            ptr := add(ptr, 0x20)
            mstore(ptr, nonce)
            ptr := add(ptr, 0x20)
            // Clear the upper bits of the deadline, in case the caller didn't.
            mstore(ptr, and(deadline, 0xffffffff))
            ptr := add(ptr, 0x20)
            mstore(ptr, installCallHash)

            // Compute the struct hash
            structHash := keccak256(fmp, 0x80)
        }

        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(_domainSeparator(), structHash);

        return typedDataHash;
    }

    function _domainSeparator() internal view returns (bytes32) {
        bytes32 result;

        // Compute the hash without permanently allocating memory
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            mstore(fmp, _DOMAIN_SEPARATOR_TYPEHASH)
            mstore(add(fmp, 0x20), chainid())
            mstore(add(fmp, 0x40), address())
            result := keccak256(fmp, 0x60)
        }

        return result;
    }

    // A virtual function to detect if a validation function is natively implemented. Used for determining call
    // buffer allocation.
    function _validationIsNative(ModuleEntity) internal pure virtual returns (bool) {
        return false;
    }
}
