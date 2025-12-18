// This file is part of Modular Account.
//
// Copyright 2025 Alchemy Insights, Inc.
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

import {SignatureType} from "../helpers/SignatureType.sol";

library SignatureTypeLib {
    function isReplayProtected(
        SignatureType sigType
    ) internal pure returns (bool) {
        return (uint8(sigType) & 2) == 0;
    }

    function getBaseSignatureType(
        SignatureType sigType
    ) internal pure returns (SignatureType) {
        return SignatureType(uint8(sigType) & 1);
    }
}
