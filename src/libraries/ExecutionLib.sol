// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {HookConfig} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntity} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

// The following types alias a `bytes memory`, to protect the user from doing anything unexpected with it. We can't
// actually alias a `bytes memory` type, so we use a `bytes32` type instead, and cast it to `bytes memory` within
// this library.
type UOCallBuffer is bytes32;

type RTCallBuffer is bytes32;

type PHCallBuffer is bytes32;

type SigCallBuffer is bytes32;

type DensePostHookData is bytes32;

using HookConfigLib for HookConfig;

/// @title Execution Library
/// @author Alchemy
/// @notice A library for performing external calls. This library is used for the external calls of `execute` and
/// `executeBatch`, for any account self-calls, and for any call to a module function.
/// @dev This library uses "call buffers", or reusable memory buffers that hold the abi-encoded data to be sent to
/// a module function. These buffers are used to avoid the overhead of encoding the same data multiple times.
library ExecutionLib {
    // solhint-disable ordering
    // Functions are more readable in original order.

    error PostExecHookReverted(ModuleEntity moduleFunction, bytes revertReason);
    error PreExecHookReverted(ModuleEntity moduleFunction, bytes revertReason);
    error PreRuntimeValidationHookReverted(ModuleEntity moduleFunction, bytes revertReason);
    error PreSignatureValidationHookReverted(ModuleEntity moduleFunction, bytes revertReason);
    error PreUserOpValidationHookReverted(ModuleEntity moduleFunction, bytes revertReason);
    error RuntimeValidationFunctionReverted(ModuleEntity moduleFunction, bytes revertReason);
    error SignatureValidationFunctionReverted(ModuleEntity moduleFunction, bytes revertReason);
    error UserOpValidationFunctionReverted(ModuleEntity moduleFunction, bytes revertReason);

    /// @notice Perform the following call, without capturing any return data.
    /// If the call reverts, the revert message will be directly bubbled up.
    /// @param target The address to call.
    /// @param value The value to send with the call.
    /// @param callData The data to send with the call.
    function callBubbleOnRevert(address target, uint256 value, bytes memory callData) internal {
        // Manually call, without collecting return data unless there's a revert.
        assembly ("memory-safe") {
            let success :=
                call(
                    gas(),
                    target,
                    /*value*/
                    value,
                    /*argOffset*/
                    add(callData, 0x20),
                    /*argSize*/
                    mload(callData),
                    /*retOffset*/
                    codesize(),
                    /*retSize*/
                    0
                )

            // directly bubble up revert messages, if any.
            if iszero(success) {
                // For memory safety, copy this revert data to scratch space past the end of used memory. Because
                // we immediately revert, we can omit storing the length as we normally would for a `bytes memory`
                // type, as well as omit finalizing the allocation by updating the free memory pointer.
                let revertDataLocation := mload(0x40)
                returndatacopy(revertDataLocation, 0, returndatasize())
                revert(revertDataLocation, returndatasize())
            }
        }
    }

    /// @notice Transiently copy the call data to a memory, and perform a self-call.
    /// If the call reverts, the revert message will be directly bubbled up.
    /// @param target The address to call.
    /// @param value The value to send with the call.
    /// @param callData The data to send with the call.
    function callBubbleOnRevertTransient(address target, uint256 value, bytes calldata callData) internal {
        bytes memory encodedCall;

        assembly ("memory-safe") {
            // Store the length of the call
            encodedCall := mload(0x40)
            mstore(encodedCall, callData.length)
            // Copy in the calldata
            calldatacopy(add(encodedCall, 0x20), callData.offset, callData.length)
        }

        callBubbleOnRevert(target, value, encodedCall);
        // Memory is discarded afterwards
    }

    // Transiently copy the call data to a memory, and perform a self-call.
    function delegatecallBubbleOnRevertTransient(address target) internal {
        assembly ("memory-safe") {
            // Store the length of the call
            let fmp := mload(0x40)

            // Copy in the entire calldata
            calldatacopy(fmp, 0, calldatasize())

            let success :=
                delegatecall(
                    gas(),
                    target,
                    /*argOffset*/
                    fmp,
                    /*argSize*/
                    calldatasize(),
                    /*retOffset*/
                    codesize(),
                    /*retSize*/
                    0
                )

            // directly bubble up revert messages, if any.
            if iszero(success) {
                // For memory safety, copy this revert data to scratch space past the end of used memory. Because
                // we immediately revert, we can omit storing the length as we normally would for a `bytes memory`
                // type, as well as omit finalizing the allocation by updating the free memory pointer.
                let revertDataLocation := mload(0x40)
                returndatacopy(revertDataLocation, 0, returndatasize())
                revert(revertDataLocation, returndatasize())
            }
        }
        // Memory is discarded afterwards
    }

    /// @notice Manually collect and store the return data from the most recent external call into a `bytes
    /// memory`.
    /// @return returnData The return data from the most recent external call.
    function collectReturnData() internal pure returns (bytes memory returnData) {
        assembly ("memory-safe") {
            // Allocate a buffer of that size, advancing the memory pointer to the nearest word
            returnData := mload(0x40)
            mstore(returnData, returndatasize())
            mstore(0x40, and(add(add(returnData, returndatasize()), 0x3f), not(0x1f)))

            // Copy over the return data
            returndatacopy(add(returnData, 0x20), 0, returndatasize())
        }
    }

    // Allocate a buffer to call user op validation and validation hook functions. Both of these take the form of
    // - bytes4 selector
    // - uint32 entityId
    // - PackedUserOperation userOp
    // - bytes32 userOpHash
    // The buffer starts with the selector for `preUserOpValidationHook`, and can be updated later to
    // `validateUserOp`. When perfomring the actual function calls later, update the entityId field and selector,
    // as as needed.
    function allocateUserOpValidationCallBuffer(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        pure
        returns (UOCallBuffer result)
    {
        bytes memory buffer =
            abi.encodeCall(IValidationHookModule.preUserOpValidationHook, (uint32(0), userOp, userOpHash));

        assembly ("memory-safe") {
            result := buffer
        }

        // Buffer contents:
        // 0xAAAAAAAA // selector
        // 0x000: 0x________________________________________________________BBBBBBBB // entityId
        // 0x020: 0x______________________________________________________________60 // userOp offset
        // 0x040: 0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC // userOp hash
        // 0x060: 0x________________________DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD // userOp sender
        // 0x080: 0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE // userOp nonce
        // 0x0a0: 0x_____________________________________________________________FFF // userOp initCode offset
        // 0x0c0: 0x_____________________________________________________________GGG // userOp callData offset
        // 0x0e0: 0xHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH // userOp accountGasLimits
        // 0x100: 0xIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII // userOp preVerificationGas
        // 0x120: 0xJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ // userOp gasFees
        // 0x140: 0x_____________________________________________________________KKK // userOp pmData offset
        // 0x160: 0x_____________________________________________________________LLL // userOp signature offset
        // 0x180...                                                                  // dynamic fields
    }

    // Converts a user op call buffer from pre user op validation hooks to user op validation.
    // Performs this by writing over the selector stored in the buffer.
    function convertToValidationBuffer(UOCallBuffer buffer) internal pure {
        // Selector is treated as a uint32 to be right-aligned in the word.
        uint32 selector = uint32(IValidationModule.validateUserOp.selector);

        assembly ("memory-safe") {
            // We want to write in the selector without writing over anything else in the buffer, so we save the
            // length, write over a portion of the length, and restore it.
            let bufferLength := mload(buffer)
            mstore(add(buffer, 4), selector)
            mstore(buffer, bufferLength)
        }
    }

    // Invokes either a user op validation hook, or validation function.
    function invokeUserOpCallBuffer(
        UOCallBuffer buffer,
        ModuleEntity moduleEntity,
        bytes calldata signatureSegment
    ) internal returns (uint256 validationData) {
        bool success;
        address moduleAddress;
        uint32 entityId;

        assembly ("memory-safe") {
            // Load the module address and entity Id
            entityId := and(shr(64, moduleEntity), 0xffffffff)
            moduleAddress := shr(96, moduleEntity)

            // Update the buffer with the entity Id
            mstore(add(buffer, 0x24), entityId)

            // Get the offset of the user op signature in the buffer.
            // The PackedUserOperation starts at the 5th word in the buffer (0x20 * 4 = 0x80).
            // It is the 9th element in PackedUserOp (so add 0x20 * 8 = 0x100 to the buffer start).
            // So we start at 0x184, to include the selector length.
            // Then, to convert from a relative to an absolute offset, we need to add the buffer start, selector,
            // and to skip over the entityId, offset, and hash.
            let userOpSigRelativeOffset := mload(add(buffer, 0x184))
            let userOpSigAbsOffset := add(add(buffer, userOpSigRelativeOffset), 0x84)

            // Copy in the signature segment
            // Since the buffer's copy of the signature exceeds the length of any sub-segments, we can safely write
            // over it.
            mstore(userOpSigAbsOffset, signatureSegment.length)
            // If there is a nonzero signature segment length, copy in the data.
            if signatureSegment.length {
                // Because we will be sending the data with word-aligned padding ("strict ABI encoding"), we need
                // to zero out the last word of the buffer to prevent sending garbage data.
                let roundedDownSignatureLength := and(signatureSegment.length, not(0x1f))
                mstore(add(userOpSigAbsOffset, add(roundedDownSignatureLength, 0x20)), 0)
                calldatacopy(add(userOpSigAbsOffset, 0x20), signatureSegment.offset, signatureSegment.length)
            }

            // The data amount we actually want to call with is:
            // buffer length - word-align(oldSignature length) + word-align(newSignature length)
            // Which is equivalent to:
            // 4 (selector length) + 0x80 (entityId, user op offset, user op hash, signature length field)
            // + userOpSigRelativeOffset + word-align(newSignature length)

            let actualCallLength := add(userOpSigRelativeOffset, 0x84)

            // Add in the new signature length, with word alignment. This is safe to do because the signature
            // segment length is guaranteed to be less than the size of the previous entire signature length.
            actualCallLength := add(actualCallLength, and(add(signatureSegment.length, 0x1f), not(0x1f)))

            // Perform the call, reverting on failure or insufficient return data.

            success :=
                and(
                    // Yul evaluates expressions from right to left, so `returndatasize` will evaluate after `call`.
                    gt(returndatasize(), 0x1f),
                    call(
                        // If gas is the leftmost item before the call, it *should* be placed immediately before the
                        // call opcode and be allowed in validation.
                        gas(),
                        moduleAddress,
                        /*value*/
                        0,
                        /*argOffset*/
                        add(buffer, 0x20), // jump over 32 bytes for length
                        /*argSize*/
                        actualCallLength,
                        /*retOffset*/
                        0,
                        /*retSize*/
                        0x20
                    )
                )
        }

        if (success) {
            assembly ("memory-safe") {
                // If the call was successful, we return the first word of the return data as the validation data.
                validationData := mload(0)
            }
        } else {
            // Revert with the appropriate error type for the selector used.

            uint32 selectorUsed;
            uint32 errorSelector;

            assembly ("memory-safe") {
                selectorUsed := and(mload(add(buffer, 0x4)), 0xffffffff)
            }

            if (selectorUsed == uint32(IValidationHookModule.preUserOpValidationHook.selector)) {
                errorSelector = uint32(PreUserOpValidationHookReverted.selector);
            } else {
                errorSelector = uint32(UserOpValidationFunctionReverted.selector);
            }

            _revertModuleFunction(errorSelector, moduleAddress, entityId);
        }
    }

    function allocateRuntimeValidationCallBuffer(bytes calldata callData, bytes calldata authorization)
        internal
        returns (RTCallBuffer result)
    {
        // Allocate a call to regular runtime validation. Pre runtime validation hooks lack the `account` field, so
        // they won't touch the selector portion of this buffer.
        bytes memory buffer = abi.encodeCall(
            IValidationModule.validateRuntime,
            (address(0), uint32(0), msg.sender, msg.value, callData, authorization)
        );

        assembly ("memory-safe") {
            result := buffer
        }

        // Buffer contents, before update:
        // 0xAAAAAAAA // selector
        // 0x000: 0x________________________BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB // account
        // 0x020: 0x________________________________________________________CCCCCCCC // entityId
        // 0x040: 0x________________________DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD // msg.sender
        // 0x060: 0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE // msg.value
        // 0x080: 0x______________________________________________________________c0 // callData offset
        // 0x0a0: 0x_____________________________________________________________FFF // authorization offset
        // 0x0c0...                                                                  // dynamic fields

        // Prepare the buffer for pre-runtime validation hooks.
        _prepareRuntimeCallBufferPreValidationHooks(result);
    }

    function invokeRuntimeCallBufferPreValidationHook(
        RTCallBuffer buffer,
        HookConfig hookEntity,
        bytes calldata authorizationSegment
    ) internal {
        bool success;
        address moduleAddress;
        uint32 entityId;
        assembly ("memory-safe") {
            // Load the module address and entity Id
            entityId := and(shr(64, hookEntity), 0xffffffff)
            moduleAddress := shr(96, hookEntity)

            // Update the buffer with the entity Id
            mstore(add(buffer, 0x44), entityId)

            // Get the offset of the authorization in the buffer.
            // The authorization offset is the 6th word in the buffer (0x20 * 5 = 0xa0).
            // We need to add the buffer length and selector length (0x24) to get the start of the authorization.
            let authorizationRelativeOffset := mload(add(buffer, 0xc4))

            // Convert to an absolute offset
            // Add the lengths of the selector, buffer length field, and the authorization length field.
            let authorizationAbsOffset := add(add(buffer, authorizationRelativeOffset), 0x44)

            // Copy in the authorization segment
            // Since the buffer's copy of the authorization exceeds the length of any sub-segments, we can safely
            // write over it.
            mstore(authorizationAbsOffset, authorizationSegment.length)
            // If there is a nonzero authorization segment length, copy in the data.
            if authorizationSegment.length {
                // Because we will be sending the data with word-aligned padding ("strict ABI encoding"), we need
                // to zero out the last word of the buffer to prevent sending garbage data.
                let roundedDownAuthorizationLength := and(authorizationSegment.length, not(0x1f))
                mstore(add(authorizationAbsOffset, add(roundedDownAuthorizationLength, 0x20)), 0)
                // Copy the authorization segment from calldata into the correct location in the buffer.
                calldatacopy(
                    add(authorizationAbsOffset, 0x20), authorizationSegment.offset, authorizationSegment.length
                )
            }

            // The data amount we actually want to call with is:
            // buffer length - word-align(oldAuthorization length) + word-align(newAuthorization length) - 0x20 (to
            // skip `account`),
            // This is equivalent to:
            // 4 (selector length) + 0x20 (authorization length field) + authorizationRelativeOffset +
            // word-align(newAuthorization length)

            let actualCallLength := add(authorizationRelativeOffset, 0x24)

            // Add in the new authorization length, with word alignment. This is safe to do because the
            // authorization segment length is guaranteed to be less than the size of the previous entire
            // authorization length.
            actualCallLength := add(actualCallLength, and(add(authorizationSegment.length, 0x1f), not(0x1f)))

            // Perform the call
            success :=
                call(
                    gas(),
                    moduleAddress,
                    /*value*/
                    0,
                    /*argOffset*/
                    add(buffer, 0x40), // jump over 32 bytes for length, and another 32 bytes for the account
                    /*argSize*/
                    actualCallLength,
                    /*retOffset*/
                    codesize(),
                    /*retSize*/
                    0
                )
        }

        if (!success) {
            _revertModuleFunction(uint32(PreRuntimeValidationHookReverted.selector), moduleAddress, entityId);
        }
    }

    // Note: we need to add an extra check for codesize > 0 on the module, otherwise EOAs added as runtime
    // validation would authorize all calls.
    function invokeRuntimeCallBufferValidation(
        RTCallBuffer buffer,
        ModuleEntity moduleEntity,
        bytes calldata authorizationSegment
    ) internal {
        bool success;
        address moduleAddress;
        uint32 entityId;

        assembly ("memory-safe") {
            // Load the module address and entity Id
            entityId := and(shr(64, moduleEntity), 0xffffffff)
            moduleAddress := shr(96, moduleEntity)

            // Store the account in the `account` field.
            mstore(add(buffer, 0x24), address())

            // Update the buffer with the entity Id
            mstore(add(buffer, 0x44), entityId)

            // Fix the calldata offsets of `callData` and `authorization`, due to including the `account` field for
            // runtime validation.

            // The offset of calldata should be reset back to 0x0c0. For pre-validation hooks, it was set to 0x0a0.
            mstore(add(buffer, 0xa4), 0xc0)

            // Get the offset of the authorization in the buffer.
            // The authorization offset is the 6th word in the buffer (0x20 * 5 = 0xa0).
            let authorizationOffsetPtr := add(buffer, 0xc4)
            // Get the stored value. This will be the edited value for preRuntimeValidationHooks.
            let authorizationRelativeOffset := mload(authorizationOffsetPtr)
            // Fix the stored offset value by adding 0x20.
            authorizationRelativeOffset := add(authorizationRelativeOffset, 0x20)
            // Correct the authorization relative offset
            mstore(authorizationOffsetPtr, authorizationRelativeOffset)

            // Convert to an absolute offset
            // Add the lengths of the selector and buffer length field.
            let authorizationAbsOffset := add(add(buffer, authorizationRelativeOffset), 0x24)

            // Copy in the authorization segment
            // Since the buffer's copy of the authorization exceeds the length of any sub-segments, we can safely
            // write over it.
            mstore(authorizationAbsOffset, authorizationSegment.length)
            // If there is a nonzero authorization segment length, copy in the data.
            if authorizationSegment.length {
                // Because we will be sending the data with word-aligned padding ("strict ABI encoding"), we need
                // to zero out the last word of the buffer to prevent sending garbage data.
                let roundedDownAuthorizationLength := and(authorizationSegment.length, not(0x1f))
                mstore(add(authorizationAbsOffset, add(roundedDownAuthorizationLength, 0x20)), 0)
                // Copy the authorization segment from calldata into the correct location in the buffer.
                calldatacopy(
                    add(authorizationAbsOffset, 0x20), authorizationSegment.offset, authorizationSegment.length
                )
            }

            // The data amount we actually want to call with is:
            // buffer length - word-align(oldAuthorization length) + word-align(newAuthorization length) - 0x20 (to
            // skip `account`),
            // This is equivalent to:
            // 4 (selector length) + 0x20 (authorization length field) + authorizationRelativeOffset +
            // word-align(newAuthorization length)

            let actualCallLength := add(authorizationRelativeOffset, 0x24)

            // Add in the new authorization length, with word alignment.
            // This is safe to do because the authorization segment length is guaranteed to be less than the size
            // of the previous entire authorization length.
            actualCallLength := add(actualCallLength, and(add(authorizationSegment.length, 0x1f), not(0x1f)))

            // Before performing the call, we need to check that the module has code.
            // IValidationModule.validateRuntime has no return value, so an EOA added as a validation (perhaps for
            // direct call validation) would authorize all calls, which is unsafe. Solidity inserts this check by
            // default, but when we're making calls manually via call buffers, we need to do the check ourselves.
            if iszero(extcodesize(moduleAddress)) { revert(0, 0) }

            // Perform the call
            success :=
                call(
                    gas(),
                    moduleAddress,
                    /*value*/
                    0,
                    /*argOffset*/
                    add(buffer, 0x20), // jump over 32 bytes for length
                    /*argSize*/
                    actualCallLength,
                    /*retOffset*/
                    codesize(),
                    /*retSize*/
                    0
                )
        }

        if (!success) {
            _revertModuleFunction(uint32(RuntimeValidationFunctionReverted.selector), moduleAddress, entityId);
        }
    }

    function executeRuntimeSelfCall(RTCallBuffer buffer, bytes calldata data) internal {
        bool bufferExists;

        assembly ("memory-safe") {
            bufferExists := iszero(iszero(buffer))
        }

        if (bufferExists) {
            // We don’t know whether the RTCallBuffer was called only with pre-hooks (skipping RT validation
            // updates because of SMA), or if it was called with a buffer after a module based RT validation, which
            // would cause the relative offset of calldata to change. So, when loading the callData for self-exec,
            // we must not load the relative calldata offset, and must instead use an absolute offset from the
            // start of the buffer. Using an absolute offset is safe because the abi encoder will only generate
            // “strict encoding mode” encodings, so it is guaranteed to be in that location.

            bytes memory callData;

            assembly ("memory-safe") {
                // Get the memory address of the length of callData in the buffer.
                // Because we don't know whether this will be invoked with the RTCallBuffer still as a
                callData := add(buffer, 0xe4)
            }

            // Perform the call, bubbling up revert data on failure.
            callBubbleOnRevert(address(this), msg.value, callData);
        } else {
            // No buffer exists yet, just copy the data to memory transiently and execute it.
            callBubbleOnRevertTransient(address(this), msg.value, data);
        }
    }

    // Convert a RTCallBuffer to a pre hook call buffer, if the RTCallBuffer exists. If not, allocate a new one.
    function convertToPreHookCallBuffer(RTCallBuffer buffer, bytes calldata data)
        internal
        view
        returns (PHCallBuffer result)
    {
        bool bufferExists;

        assembly ("memory-safe") {
            bufferExists := iszero(iszero(buffer))
        }

        if (bufferExists) {
            // The buffer already has most of what we need, but we need to update the pointer, length, and data
            // offset.

            // Buffer transformation:
            // 0xAAAAAAAA // selector
            // 0x000: 0x________________________BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB account -> discarded
            // 0x020: 0x________________________________________________________CCCCCCCC entityId -> selector
            // 0x040: 0x________________________DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD msg.sender -> entityId
            // 0x060: 0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE msg.value -> sender
            // 0x080: 0x______________________________________________________________c0 callData offset -> value
            // 0x0a0: 0x_____________________________________________________________FFF auth offset -> cd offset
            // 0x0c0: 0x_____________________________________________________________GGG callData length -> stays

            // This new buffer will be a subset of the existing buffer.
            PHCallBuffer newBuffer;

            // Right-align the selector
            uint32 selector = uint32(IExecutionHookModule.preExecutionHook.selector);

            assembly ("memory-safe") {
                // We don’t know whether the RTCallBuffer was called only with pre-hooks (skipping RT validation
                // updates because of SMA), or if it was called with a buffer after a module based RT validation,
                // which would cause the relative offset of calldata to change. So, when converting to a pre hook
                // buffer, we must not load the relative calldata offset, and must instead use an absolute offset
                // from the start of the buffer. Using an absolute offset is safe because the abi encoder will only
                // generate “strict encoding mode” encodings, so it is guaranteed to be in that location.

                let callDataAbsOffset := add(buffer, 0xe4)

                let callDataSize := mload(callDataAbsOffset)

                // We must squash existing elements, because the stored offset of authorization causes the other
                // fields to not be aligned.
                // We need to copy in the selector, entityId, sender, value, and relative callData offset.

                // Step back 5 words, to start pasting in the new data.
                let workingPtr := add(buffer, 0x44)
                // Paste in the selector
                mstore(workingPtr, selector)
                // skip pasting in the entity ID, the caller will squash this later
                workingPtr := add(workingPtr, 0x40)
                // Paste in msg.sender
                mstore(workingPtr, caller())
                workingPtr := add(workingPtr, 0x20)
                // Paste in msg.value
                mstore(workingPtr, callvalue())
                workingPtr := add(workingPtr, 0x20)
                // Paste in the relative callData offset. This is now 0xa0, to show that it is after the entityId,
                // sender, value, and offset fields.
                mstore(workingPtr, 0x80)

                // Now store the buffer length. This will be directly before the selector, and the returned pointer
                // will point to this word in memory.
                newBuffer := add(buffer, 0x40)
                // word-align the callDataSize
                callDataSize := and(add(callDataSize, 0x1f), not(0x1f))
                mstore(newBuffer, add(callDataSize, 0xa4))
                // See `allocateRuntimeCallBuffer` for the buffer layout.
            }

            return newBuffer;
        } else {
            // We need to allocate and return a new buffer.
            return allocatePreExecHookCallBuffer(data);
        }
    }

    // Allocate a buffer to call a pre-execution hook.
    function allocatePreExecHookCallBuffer(bytes calldata data) internal view returns (PHCallBuffer) {
        bytes memory newBuffer =
            abi.encodeCall(IExecutionHookModule.preExecutionHook, (uint32(0), msg.sender, msg.value, data));

        PHCallBuffer result;

        assembly ("memory-safe") {
            result := newBuffer
        }

        return result;

        // Buffer contents:
        // 0xAAAAAAAA // selector
        // 0x000: 0x________________________________________________________BBBBBBBB // entityId
        // 0x020: 0x________________________CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC // sender
        // 0x040: 0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD // value
        // 0x060: 0x______________________________________________________________80 // callData offset
        // 0x080...                                                                  // dynamic fields
    }

    function invokePreExecHook(PHCallBuffer buffer, HookConfig hookEntity)
        internal
        returns (uint256 returnedBytesSize)
    {
        bool success;
        address moduleAddress;
        uint32 entityId;

        assembly ("memory-safe") {
            // Load the module address and entity Id
            entityId := and(shr(64, hookEntity), 0xffffffff)
            moduleAddress := shr(96, hookEntity)

            // Update the buffer with the entity Id
            mstore(add(buffer, 0x24), entityId)

            // Perform the call, storing the first two words of return data into scratch space.
            success :=
                call(
                    gas(),
                    moduleAddress,
                    /*value*/
                    0,
                    /*argOffset*/
                    add(buffer, 0x20), // jump over 32 bytes for length
                    /*argSize*/
                    mload(buffer),
                    /*retOffset*/
                    0,
                    /*retSize*/
                    0x40
                )

            // Need at least 64 bytes of return data to be considered successful.
            success := and(success, gt(returndatasize(), 0x3f))
            // Only accept return data of "strict encoding" form, where the relative offset is exactly 0x20.
            success := and(success, eq(mload(0), 0x20))
            // Ensure that the reported length of return data does not exceed the actual length.
            // aka the stored length <= retundatasize() - 0x40 (for the first two values)
            // No opcode for lte, so the expression equals:
            // stored length < retundatasize() - 0x3f
            // Underflow doesn't matter, because success is false anyways if length < 0x40.
            returnedBytesSize := mload(0x20)
            success := and(success, lt(returnedBytesSize, sub(returndatasize(), 0x3f)))
        }

        if (!success) {
            _revertModuleFunction(uint32(PreExecHookReverted.selector), moduleAddress, entityId);
        }
    }

    // Converts a PreHookCallBuffer to a `bytes memory`, to use for a self-call in `executeUserOp`.
    // Handles skipping ahead an extra 4 bytes to omit the `executeUserOp` selector, and updates the stored length
    // to do so. This will edit the buffer.
    function getExecuteUOCallData(PHCallBuffer buffer, bytes calldata callData)
        internal
        pure
        returns (bytes memory)
    {
        bool bufferExists;

        assembly ("memory-safe") {
            bufferExists := iszero(iszero(buffer))
        }

        if (bufferExists) {
            // At this point, the buffer contains the encoded call to the pre-exec hook, but the data being sent is
            // `msg.data`, not `userOp.callData`. Re-decoding the user op struct's callData is error-prone, so
            // instead we just copy-in the provided userOp.callData, squashing the buffer. This is fine because the
            // buffer will not be reused after this operation.

            bytes memory result;

            assembly ("memory-safe") {
                // Safe to do unchecked because there must have been at least 4 bytes of callData for the
                // EntryPoint to call `executeUserOp`.
                let actualCallDataLength := sub(callData.length, 4)

                // Write over the existing buffer
                result := buffer

                // Store the new length
                mstore(result, actualCallDataLength)

                if actualCallDataLength {
                    // We don't need to write a zero word because this data will not be word-aligned before sending
                    // Copy in the callData
                    calldatacopy(add(result, 0x20), add(callData.offset, 4), actualCallDataLength)
                }
            }

            return result;
        } else {
            // No buffer exists yet, just copy the data to memory and return it.
            // Skip the first 4 bytes in this function to save the computation on the buffer reuse case.
            return callData[4:];
        }
    }

    // DensePostHookData layout
    // Very tricky to navigate, because we must do so backwards.

    // type ~= struct[] but in reverse, the caller must advance through it backwards

    // N instances of:
    // - post hook address (will be squashed with the selector later, during invocation)
    // - post hood entity Id
    // - fixed preExecHookData offset (always 0x40)
    // - preExecHookData length
    // - var-length data (right-padded with zeros to be word aligned)
    // - segment (struct) length (not counting this word, to traverse backwards)
    // 1 count of post hooks to run. The returned memory pointer will point to this value.

    function doPreHooks(HookConfig[] memory hooks, PHCallBuffer callBuffer)
        internal
        returns (DensePostHookData result)
    {
        uint256 hooksLength = hooks.length;

        // How many "post hooks to run" there are.
        uint256 resultCount;
        // Where in memory to start writing the next "post hook to run".
        bytes32 workingMemPtr;

        // Start allocating the dense buffer. From this point out, avoid any high-level memory allocations,
        // otherwise the data-in-flight may be corrupted.
        assembly ("memory-safe") {
            workingMemPtr := mload(0x40)
        }

        // Run the pre hooks and copy their return data to the dense post hooks data buffer array, if an associated
        // post exec hook exists.
        for (uint256 i = hooksLength; i > 0;) {
            // Decrement here, instead of in the loop update step, to handle the case where the length is 0.
            unchecked {
                --i;
            }

            HookConfig hookConfig = hooks[i];

            if (hookConfig.hasPreHook()) {
                uint256 returnedBytesSize = ExecutionLib.invokePreExecHook(callBuffer, hookConfig);

                // If there is an associated post exec hook, save the return data.
                if (hookConfig.hasPostHook()) {
                    // Case: both pre and post exec hook, need to save hook info, and pre hook return data

                    workingMemPtr = _appendPostHookToRun(workingMemPtr, hookConfig, returnedBytesSize);

                    ++resultCount;
                }
            } else if (hookConfig.hasPostHook()) {
                // If there is no pre hook, but there is a post hook, we still need to save a placeholder for the
                // post hook return data.

                // Case: only post exec hook, need to save hook info, and no pre hook return data
                // Call the append function with legnth 0 to put no pre hook return data.

                workingMemPtr = _appendPostHookToRun(workingMemPtr, hookConfig, 0);

                ++resultCount;
            }
        }

        // Save the length, return a pointer to the length, and update the FMP
        assembly ("memory-safe") {
            mstore(workingMemPtr, resultCount)
            result := workingMemPtr

            workingMemPtr := add(workingMemPtr, 0x20)
            mstore(0x40, workingMemPtr)
        }
    }

    function doCachedPostHooks(DensePostHookData postHookData) internal {
        uint256 postHookCount;
        uint256 workingMemPtr;

        assembly ("memory-safe") {
            postHookCount := mload(postHookData)
            workingMemPtr := sub(postHookData, 0x20)
        }

        uint32 selector = uint32(IExecutionHookModule.postExecutionHook.selector);

        // Run the post hooks.
        // This is tricky, unlike normal, we must traverse the data backwards, because the post exec hooks should
        // be executed in reverse order of the pre exec hooks.
        for (uint256 i = 0; i < postHookCount; i++) {
            bool success;

            address moduleAddress;
            uint32 entityId;

            assembly ("memory-safe") {
                // The last word of each segment is the segment length
                let segmentLength := mload(workingMemPtr)

                // Step the working memory pointer back to the start of the segment, and preserve a copy to
                // continue the loop
                workingMemPtr := sub(workingMemPtr, segmentLength)
                let segmentStart := workingMemPtr

                // Load the post hook address
                moduleAddress := mload(workingMemPtr)
                // Load the entity id, just for the revert message
                entityId := mload(add(workingMemPtr, 0x20))

                // Squash the post hook address field with the selector
                mstore(workingMemPtr, selector)

                // Advance the working mem pointer to just before the selector, to prepare to make the call.
                workingMemPtr := add(workingMemPtr, 0x1c)

                // Compute the total call length, including the selector
                // This will be seggment length - 0x1c (28), to take out the space not used in the selector
                let callLength := sub(segmentLength, 0x1c)

                // Perform the call
                success :=
                    call(
                        gas(),
                        moduleAddress,
                        /*value*/
                        0,
                        /*argOffset*/
                        workingMemPtr,
                        /*argSize*/
                        callLength,
                        /*retOffset*/
                        codesize(),
                        /*retSize*/
                        0
                    )

                // Step the working mem pointer back to the previous segment
                workingMemPtr := sub(segmentStart, 0x20)
            }

            if (!success) {
                _revertModuleFunction(uint32(PostExecHookReverted.selector), moduleAddress, entityId);
            }
        }
    }

    function allocateSigCallBuffer(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (SigCallBuffer result)
    {
        bytes memory buffer = abi.encodeCall(
            IValidationModule.validateSignature, (address(0), uint32(0), msg.sender, hash, signature)
        );

        assembly ("memory-safe") {
            result := buffer
        }

        // Buffer contents, before update:
        // 0xAAAAAAAA // selector
        // 0x000: 0x________________________BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB // account
        // 0x020: 0x________________________________________________________CCCCCCCC // entityId
        // 0x040: 0x________________________DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD // msg.sender
        // 0x060: 0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE // hash
        // 0x080: 0x______________________________________________________________a0 // signature offset
        // 0x0a0...                                                                  // dynamic fields

        // Prepare the buffer for pre-signature validation hooks.
        _prepareSigValidationCallBufferPreSigValidationHooks(result);
    }

    function invokePreSignatureValidationHook(
        SigCallBuffer buffer,
        HookConfig hookEntity,
        bytes calldata signatureSegment
    ) internal view {
        bool success;
        address moduleAddress;
        uint32 entityId;

        assembly ("memory-safe") {
            // Load the module address and entity id
            entityId := and(shr(64, hookEntity), 0xffffffff)
            moduleAddress := shr(96, hookEntity)

            // Update the buffer with the entity Id
            mstore(add(buffer, 0x44), entityId)

            // Copy in the signature segment
            // Since the buffer's copy of the signature exceeds the length of any sub-segments, we can safely write
            // over it.
            mstore(add(buffer, 0xc4), signatureSegment.length)

            // If there is a nonzero signature segment length, copy in the data.
            if signatureSegment.length {
                // Because we will be sending the data with word-aligned padding ("strict ABI encoding"), we need
                // to zero out the last word of the buffer to prevent sending garbage data.
                let roundedDownSignatureLength := and(signatureSegment.length, not(0x1f))
                mstore(add(add(buffer, 0xe4), roundedDownSignatureLength), 0)
                // Copy in the data
                calldatacopy(add(buffer, 0xe4), signatureSegment.offset, signatureSegment.length)
            }

            // The data amount we actually want to call with is:
            // 0xa4 (4 byte selector + 5 words of data: entity id, sender, hash, signature offset, signature
            // length) + word-align(signature length)
            let actualCallLength := add(0xa4, and(add(signatureSegment.length, 0x1f), not(0x1f)))

            // Perform the call
            success :=
                staticcall(
                    gas(),
                    moduleAddress,
                    /*argOffset*/
                    add(buffer, 0x40), // jump over 32 bytes for length, and another 32 bytes for the account
                    /*argSize*/
                    actualCallLength,
                    /*retOffset*/
                    0,
                    /*retSize*/
                    0x20
                )
        }

        if (!success) {
            _revertModuleFunction(uint32(PreSignatureValidationHookReverted.selector), moduleAddress, entityId);
        }
    }

    function invokeSignatureValidation(
        SigCallBuffer buffer,
        ModuleEntity validationFunction,
        bytes calldata signatureSegment
    ) internal view returns (bytes4 result) {
        bool success;
        address moduleAddress;
        uint32 entityId;

        assembly ("memory-safe") {
            // Load the module address and entity id
            entityId := and(shr(64, validationFunction), 0xffffffff)
            moduleAddress := shr(96, validationFunction)

            // Store the account in the `account` field.
            mstore(add(buffer, 0x24), address())

            // Update the buffer with the entity Id
            mstore(add(buffer, 0x44), entityId)

            // Fix the calldata offsets of `signature`, due to including the `account` field for signature
            // validation.
            mstore(add(buffer, 0xa4), 0xa0)

            // Copy in the signature segment
            // Since the buffer's copy of the signature exceeds the length of any sub-segments, we can safely write
            // over it.
            mstore(add(buffer, 0xc4), signatureSegment.length)

            // If there is a nonzero signature segment length, copy in the data.
            if signatureSegment.length {
                // Because we will be sending the data with word-aligned padding ("strict ABI encoding"), we need
                // to zero out the last word of the buffer to prevent sending garbage data.
                let roundedDownSignatureLength := and(signatureSegment.length, not(0x1f))
                mstore(add(add(buffer, 0xe4), roundedDownSignatureLength), 0)
                // Copy in the data
                calldatacopy(add(buffer, 0xe4), signatureSegment.offset, signatureSegment.length)
            }

            // The data amount we actually want to call with is:
            // 0xc4 (4 byte selector + 6 words of data: account, entity id, sender, hash, signature offset,
            // signature length) + word-align(signature length)
            let actualCallLength := add(0xc4, and(add(signatureSegment.length, 0x1f), not(0x1f)))

            // Perform the call
            success :=
                and(
                    // Yul evaluates expressions from right to left, so `returndatasize` will evaluate after
                    // `staticcall`.
                    gt(returndatasize(), 0x1f),
                    staticcall(
                        gas(),
                        moduleAddress,
                        /*argOffset*/
                        add(buffer, 0x20), // jump over 32 bytes for length, and another 32 bytes for the account
                        /*argSize*/
                        actualCallLength,
                        /*retOffset*/
                        0,
                        /*retSize*/
                        0x20
                    )
                )
        }

        if (success) {
            assembly ("memory-safe") {
                // Otherwise, we return the first word of the return data as the signature validation result
                result := mload(0)

                // If any of the lower 28 bytes are nonzero, it would be an abi decoding failure.
                if shl(32, result) { revert(0, 0) }
            }
        } else {
            _revertModuleFunction(uint32(SignatureValidationFunctionReverted.selector), moduleAddress, entityId);
        }
    }

    /// @notice Appends a post hook to run to the dense post hook data buffer.
    /// @param workingMemPtr The current working memory pointer
    /// @param hookConfig The hook configuration
    /// @param returnedBytesSize The size of the returned bytes from the pre hook
    /// @return The new working memory pointer
    function _appendPostHookToRun(bytes32 workingMemPtr, HookConfig hookConfig, uint256 returnedBytesSize)
        private
        pure
        returns (bytes32)
    {
        // Each segment starts out at a length of 4 words:
        // - post hook address
        // - post hook entity Id
        // - fixed preExecHookData offset (always 0x40)
        // - preHookReturnData length
        // Add to this the word-aligned length of the pre hook return data.
        uint256 segmentLength = 0x80;

        assembly ("memory-safe") {
            // Load the module address and entity Id
            let entityId := and(shr(64, hookConfig), 0xffffffff)
            let moduleAddress := shr(96, hookConfig)

            // Get the word-aligned data to copy length
            let alignedDataLength := and(add(returnedBytesSize, 0x1f), not(0x1f))

            segmentLength := add(segmentLength, alignedDataLength)

            // Start writing to memory:

            // Store the post hook address
            mstore(workingMemPtr, moduleAddress)
            workingMemPtr := add(workingMemPtr, 0x20)

            // Store the post hook entity Id
            mstore(workingMemPtr, entityId)
            workingMemPtr := add(workingMemPtr, 0x20)

            // Store the fixed preExecHookData offset
            mstore(workingMemPtr, 0x40)
            workingMemPtr := add(workingMemPtr, 0x20)

            // Store the preHookReturnData length
            mstore(workingMemPtr, returnedBytesSize)
            workingMemPtr := add(workingMemPtr, 0x20)

            // Copy in the pre hook return data, if any exists
            if returnedBytesSize {
                // Zero out the last memory word to encode in strict ABI mode
                let roundedDownDataLength := and(returnedBytesSize, not(0x1f))
                mstore(add(workingMemPtr, roundedDownDataLength), 0)

                // Copy in the data
                returndatacopy(workingMemPtr, 0x40, returnedBytesSize)
                workingMemPtr := add(workingMemPtr, alignedDataLength)
            }

            // Store the overall segment length at the end
            mstore(workingMemPtr, segmentLength)
            workingMemPtr := add(workingMemPtr, 0x20)
        }

        return workingMemPtr;
    }

    function _revertModuleFunction(uint32 errorSelector, address moduleAddress, uint32 entityId) private pure {
        // All of the module function reverts have the same parameter layout:
        // - module address
        // - entity Id
        // - revert data

        assembly ("memory-safe") {
            let m := mload(0x40)
            // Write in order of entityId -> address -> selector, to avoid masking or shifts.
            mstore(add(m, 0x18), entityId)
            mstore(add(m, 0x14), moduleAddress)
            mstore(m, errorSelector)
            mstore(add(m, 0x40), 0x40) // fixed offset for the revert data
            mstore(add(m, 0x60), returndatasize())

            if returndatasize() {
                // Store a zero in the last word of the revert data, to do strict ABI-encoding for the error.
                let roundedDownDataLength := and(returndatasize(), not(0x1f))
                mstore(add(m, add(0x80, roundedDownDataLength)), 0)
                returndatacopy(add(m, 0x80), 0, returndatasize())
            }

            let roundedUpDataLength := and(add(returndatasize(), 0x1f), not(0x1f))

            // 4 bytes for the selector, and 0x60 for the 3 words of fixed-size data.
            let totalRevertDataLength := add(0x64, roundedUpDataLength)

            revert(add(m, 0x1c), totalRevertDataLength)
        }
    }

    function _prepareRuntimeCallBufferPreValidationHooks(RTCallBuffer buffer) private pure {
        uint32 selector = uint32(IValidationHookModule.preRuntimeValidationHook.selector);
        assembly ("memory-safe") {
            // Update the buffer with the selector. This will squash a portion of the `account` param for runtime
            // validation, but that will be restored before calling.
            mstore(add(buffer, 0x24), selector)

            // Fix the calldata offsets of `callData` and `authorization`, due to excluding the `account` field.

            // The offset of calldata starts out as 0x0c0, but for pre-validation hooks, it should be 0x0a0.
            mstore(add(buffer, 0xa4), 0xa0)

            // The offset of authorization should be decremented by one word.
            let authorizationOffsetPtr := add(buffer, 0xc4)
            // Get the stored value. This will be wrong for preRuntimeValidationHooks, because the buffer size is
            // smaller by 1 word.
            let authorizationOffset := mload(authorizationOffsetPtr)
            // Fix the stored offset value
            mstore(authorizationOffsetPtr, sub(authorizationOffset, 0x20))
        }
    }

    function _prepareSigValidationCallBufferPreSigValidationHooks(SigCallBuffer buffer) private pure {
        uint32 selector = uint32(IValidationHookModule.preSignatureValidationHook.selector);
        assembly ("memory-safe") {
            // Update the buffer with the selector. This will squash a portion of the `account` param for signature
            // validation, but that will be restored before calling.
            mstore(add(buffer, 0x24), selector)

            // Fix the calldata offset of `signature`, due to excluding the `account` field.

            // The offset of the signature starts out as 0xa0, but for pre-validation hooks, it should be 0x80.
            mstore(add(buffer, 0xa4), 0x80)
        }
    }
}
