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

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {ValidationLookupKey} from "../libraries/ValidationLocatorLib.sol";

// Magic value for the ModuleEntity of the fallback validation for SemiModularAccount.
ModuleEntity constant FALLBACK_VALIDATION = ModuleEntity.wrap(bytes24(0));

// Magic value for the validation entity id of the fallback validation for SemiModularAccount.
uint32 constant FALLBACK_VALIDATION_ID = uint32(0);

// Magic value for the ValidationLookupKey of the fallback validation for SemiModularAccount.
ValidationLookupKey constant FALLBACK_VALIDATION_LOOKUP_KEY = ValidationLookupKey.wrap(uint168(0));
