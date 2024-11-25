// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.26;

// solhint-disable-next-line private-vars-leading-underscore
function _coalescePreValidation(uint256 validationRes1, uint256 validationRes2)
    pure
    returns (uint256 resValidationData)
{
    resValidationData = _coalesceValidationResTime(validationRes1, validationRes2);

    // Once we know that the authorizer field is 0 or 1, we can safely bubble up SIG_FAIL with bitwise OR
    resValidationData |= uint160(validationRes1) | uint160(validationRes2);
}

// solhint-disable-next-line private-vars-leading-underscore
function _coalesceValidation(uint256 preValidationData, uint256 validationRes)
    pure
    returns (uint256 resValidationData)
{
    resValidationData = _coalesceValidationResTime(preValidationData, validationRes);

    // If prevalidation failed, bubble up failure, and ignore authorizer
    resValidationData |= uint160(preValidationData) == 1 ? 1 : uint160(validationRes);
}

// solhint-disable-next-line private-vars-leading-underscore
function _coalesceValidationResTime(uint256 validationRes1, uint256 validationRes2)
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
