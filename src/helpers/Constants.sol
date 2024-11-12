// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {ValidationLookupKey} from "../libraries/ValidationLocatorLib.sol";

// Magic value for the ModuleEntity of the fallback validation for SemiModularAccount.
ModuleEntity constant FALLBACK_VALIDATION = ModuleEntity.wrap(bytes24(0));

// Magic value for the ValidationLookupKey of the fallback validation for SemiModularAccount.
ValidationLookupKey constant FALLBACK_VALIDATION_LOOKUP = ValidationLookupKey.wrap(uint168(0));
