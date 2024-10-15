// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

// Magic value for the ModuleEntity of the fallback validation for SemiModularAccount.
ModuleEntity constant FALLBACK_VALIDATION = ModuleEntity.wrap(bytes24(0));
