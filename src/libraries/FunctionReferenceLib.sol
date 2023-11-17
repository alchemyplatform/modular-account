// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

type FunctionReference is bytes21;

using {eq as ==, notEq as !=} for FunctionReference global;
using FunctionReferenceLib for FunctionReference global;

/// @title Function Reference Lib
/// @author Alchemy
library FunctionReferenceLib {
    // Empty or unset function reference.
    FunctionReference internal constant _EMPTY_FUNCTION_REFERENCE = FunctionReference.wrap(bytes21(0));
    // Magic value for runtime validation functions that always allow access.
    FunctionReference internal constant _RUNTIME_VALIDATION_ALWAYS_ALLOW =
        FunctionReference.wrap(bytes21(uint168(1)));
    // Magic value for hooks that should always revert.
    FunctionReference internal constant _PRE_HOOK_ALWAYS_DENY = FunctionReference.wrap(bytes21(uint168(2)));

    function pack(address addr, uint8 functionId) internal pure returns (FunctionReference) {
        return FunctionReference.wrap(bytes21(bytes20(addr)) | bytes21(uint168(functionId)));
    }

    function unpack(FunctionReference fr) internal pure returns (address addr, uint8 functionId) {
        bytes21 underlying = FunctionReference.unwrap(fr);
        addr = address(bytes20(underlying));
        functionId = uint8(bytes1(underlying << 160));
    }

    function isEmptyOrMagicValue(FunctionReference fr) internal pure returns (bool) {
        return FunctionReference.unwrap(fr) <= bytes21(uint168(2));
    }
}

function eq(FunctionReference a, FunctionReference b) pure returns (bool) {
    return FunctionReference.unwrap(a) == FunctionReference.unwrap(b);
}

function notEq(FunctionReference a, FunctionReference b) pure returns (bool) {
    return FunctionReference.unwrap(a) != FunctionReference.unwrap(b);
}
