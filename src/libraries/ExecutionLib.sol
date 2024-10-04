// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {HookConfig} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {ModuleEntity} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

// Type-aliasing a `bytes memory`, to protect the caller from doing anything unexpected with it.
// We can't actually alias a `bytes memory` type, so we use a `bytes32` type instead, and cast it to `bytes memory`
// within this library.
type UOCallBuffer is bytes32;

type RTCallBuffer is bytes32;

// Functions are more readable in original order
// solhint-disable ordering
library ExecutionLib {
    // Duplicate definition to make it easier to revert in the library.
    error PreRuntimeValidationHookFailed(address module, uint32 entityId, bytes revertReason);
    error RuntimeValidationFunctionReverted(address module, uint32 entityId, bytes revertReason);

    /// @param target The address of the contract to call.
    /// @param value The value to send with the call.
    /// @param data The call data.
    /// @return result The return data of the call, or the error message from the call if call reverts.
    function exec(address target, uint256 value, bytes memory data) internal returns (bytes memory result) {
        // Manually call, collecting return data.
        assembly ("memory-safe") {
            let success := call(gas(), target, value, add(data, 0x20), mload(data), codesize(), 0)

            // Allocate space for the return data, advancing the memory pointer to the nearest word
            result := mload(0x40)
            mstore(0x40, and(add(add(result, returndatasize()), 0x3f), not(0x1f)))

            // Copy the returned data to the allocated space.
            mstore(result, returndatasize())
            returndatacopy(add(result, 0x20), 0, returndatasize())

            // Revert if the call was not successful.
            if iszero(success) { revert(add(result, 0x20), returndatasize()) }
        }
    }

    // Call the following function to address(this), without capturing any return data.
    // If the call reverts, the revert message will be directly bubbled up.
    function callSelfBubbleOnRevert(bytes memory callData) internal {
        // Manually call, without collecting return data unless there's a revert.
        assembly ("memory-safe") {
            let success :=
                call(
                    gas(),
                    address(),
                    /*value*/
                    0,
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

    // Manually collect and store the return data from the most recent external call into a `bytes memory`.
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
        assembly ("memory-safe") {
            // Load the module address and entity Id
            let entityId := and(shr(64, moduleEntity), 0xffffffff)
            let moduleAddress := shr(96, moduleEntity)

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
            switch and(
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
            case 0 {
                // Bubble up the revert if the call reverts.
                let m := mload(0x40)
                returndatacopy(m, 0, returndatasize())
                revert(m, returndatasize())
            }
            default {
                // Otherwise, we return the first word of the return data as the validation data
                validationData := mload(0)
            }
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

        // Prepare the buffer for pre-runtime validation hooks.
        _prepareRuntimeCallBufferPreValidationHooks(result);

        // Buffer contents:
        // 0xAAAAAAAA // selector
        // 0x000: 0x________________________BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB // account
        // 0x020: 0x________________________________________________________CCCCCCCC // entityId
        // 0x040: 0x________________________DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD // msg.sender
        // 0x060: 0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE // msg.value
        // 0x080: 0x______________________________________________________________c0 // callData offset
        // 0x0a0: 0x_____________________________________________________________FFF // authorization offset
        // 0x0c0...                                                                  // dynamic fields
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
            revert PreRuntimeValidationHookFailed(moduleAddress, entityId, collectReturnData());
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
            revert RuntimeValidationFunctionReverted(moduleAddress, entityId, collectReturnData());
        }
    }

    function getCallData(RTCallBuffer buffer, bytes calldata data) internal pure returns (bytes memory) {
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

            return callData;
        } else {
            // No buffer exists yet, just copy the data to memory and return it.
            return data;
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
}
