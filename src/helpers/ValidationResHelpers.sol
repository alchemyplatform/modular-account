// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

// solhint-disable-next-line private-vars-leading-underscore
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

    // If one res with sig fail, we set authorizer field to fail (1), otherwise, either 0 or authorizer value
    resValidationData |= (uint160(validationRes1) == 1 || uint160(validationRes2) == 1)
        ? 1
        : (uint160(validationRes1) | uint160(validationRes2));
}
