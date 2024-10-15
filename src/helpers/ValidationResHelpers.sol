// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

// solhint-disable-next-line private-vars-leading-underscore
function _coalescePreValidation(uint256 validationRes1, uint256 validationRes2)
    pure
    returns (uint256 resValidationData)
{
    resValidationData = _coalesceValidationRes(validationRes1, validationRes2);

    // Once we know that the authorizer field is 0 or 1, we can safely bubble up SIG_FAIL with bitwise OR
    resValidationData |= uint160(validationRes1) | uint160(validationRes2);
}

// solhint-disable-next-line private-vars-leading-underscore
function _coalesceValidation(uint256 preValidationData, uint256 validationRes)
    pure
    returns (uint256 resValidationData)
{
    resValidationData = _coalesceValidationRes(preValidationData, validationRes);

    // If prevalidation failed, bubble up failure
    resValidationData |= uint160(preValidationData) == 1 ? 1 : uint160(validationRes);
}

function _coalesceValidationRes(uint256 validationRes1, uint256 validationRes2)
    pure
    returns (uint256 resValidationData)
{
    uint48 validUntil1 = uint48(validationRes1 >> 160);
    if (validUntil1 == 0) {
        validUntil1 = type(uint48).max;
    }
    uint48 validUntil2 = uint48(validationRes2 >> 160);
    if (validUntil2 == 0) {
        validUntil2 = type(uint48).max;
    }
    resValidationData = ((validUntil1 > validUntil2) ? uint256(validUntil2) << 160 : uint256(validUntil1) << 160);

    uint48 validAfter1 = uint48(validationRes1 >> 208);
    uint48 validAfter2 = uint48(validationRes2 >> 208);

    resValidationData |= ((validAfter1 < validAfter2) ? uint256(validAfter2) << 208 : uint256(validAfter1) << 208);
}
