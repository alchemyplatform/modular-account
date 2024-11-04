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

import {Vm} from "forge-std/Vm.sol";
// solhint-disable no-console
import {console} from "forge-std/console.sol";

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {_ACCOUNT_STORAGE_SLOT} from "../../src/account/AccountStorage.sol";

library StorageAccesses {
    // solhint-disable const-name-snakecase
    // solhint-disable-next-line private-vars-leading-underscore
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct PredictedSlotNames {
        bytes32[] slots;
        string[] names;
    }

    function printRawStorageAccesses(address target) internal {
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(target);

        console.log("Storage reads:");
        for (uint256 j = 0; j < reads.length; j++) {
            console.logBytes32(reads[j]);
        }

        console.log("Storage writes:");
        for (uint256 j = 0; j < writes.length; j++) {
            console.logBytes32(writes[j]);
        }
    }

    function printFormattedStorageAccesses(
        address target,
        ModuleEntity validationFunction,
        bytes4 executionSelector
    ) internal {
        PredictedSlotNames memory slotNames =
            getPredictedValidationSlotNames(validationFunction, executionSelector);

        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(target);

        console.log("Storage reads: %s", reads.length);
        for (uint256 j = 0; j < reads.length; j++) {
            console.log(string.concat(formatSlot(reads[j], slotNames)));
        }

        console.log("Storage writes: %s", writes.length);
        for (uint256 j = 0; j < writes.length; j++) {
            console.log(string.concat(formatSlot(writes[j], slotNames)));
        }
    }

    function formatSlot(bytes32 slot, PredictedSlotNames memory slotNames) internal pure returns (string memory) {
        for (uint256 j = 0; j < slotNames.slots.length; j++) {
            if (slotNames.slots[j] == slot) {
                return slotNames.names[j];
            }
        }

        return vm.toString(slot);
    }

    function printPredictedValidationSlots(ModuleEntity validation, bytes4 executionSelector) internal pure {
        PredictedSlotNames memory slotNames = getPredictedValidationSlotNames(validation, executionSelector);

        console.log("Predicted validation slots:");
        for (uint256 j = 0; j < slotNames.slots.length; j++) {
            console.log(string.concat(slotNames.names[j], ": %x"), uint256(slotNames.slots[j]));
        }
    }

    function getPredictedValidationSlotNames(ModuleEntity validation, bytes4 executionSelector)
        internal
        pure
        returns (PredictedSlotNames memory)
    {
        bytes32[] memory slots = new bytes32[](8);
        string[] memory names = new string[](8);

        uint256 root = uint256(_ACCOUNT_STORAGE_SLOT);

        uint256 validationStorageMappingSlot = root + 2;
        uint256 validationStorageSlot =
            getMappingEntrySlot(validationStorageMappingSlot, uint256(bytes32(ModuleEntity.unwrap(validation))));

        slots[0] = bytes32(validationStorageSlot);
        names[0] = "Validation data slot (contains flags)";

        uint256 preValidationHooksLengthSlot = validationStorageSlot + 1;
        slots[1] = bytes32(preValidationHooksLengthSlot);
        names[1] = "Pre-validation hooks length slot";

        uint256 preValidationHooksContentSlot = getArrayContentsSlot(preValidationHooksLengthSlot);
        slots[2] = bytes32(preValidationHooksContentSlot);
        names[2] = "Pre-validation hooks content slot";

        uint256 executionHooksMappingSlot = validationStorageSlot + 2;
        uint256 executionHooksFirstElementSlot = getMappingEntrySlot(executionHooksMappingSlot, uint256(1));
        slots[3] = bytes32(executionHooksFirstElementSlot);
        names[3] = "Execution hooks first element slot";

        uint256 selectorsMappingSlot = validationStorageSlot + 3;
        uint256 selectorsFirstElementSlot = getMappingEntrySlot(selectorsMappingSlot, uint256(1));
        slots[4] = bytes32(selectorsFirstElementSlot);
        names[4] = "Selectors first element slot";

        slots[5] = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        names[5] = "ERC-1967 proxy implementation slot";

        uint256 executionStorageMappingSlot = root + 1;
        uint256 executionStorageSlot =
            getMappingEntrySlot(executionStorageMappingSlot, uint256(bytes32(executionSelector)));

        slots[6] = bytes32(executionStorageSlot);
        names[6] = "Execution data slot (contains module address and flags)";

        uint256 selectorExecutionHooksMappingSlot = executionStorageSlot + 1;
        uint256 selectorExecutionHooksFirstElementSlot =
            getMappingEntrySlot(selectorExecutionHooksMappingSlot, uint256(1));
        slots[7] = bytes32(selectorExecutionHooksFirstElementSlot);
        names[7] = "Selector execution hooks first element slot";

        return PredictedSlotNames(slots, names);
    }

    function getArrayContentsSlot(uint256 arraySlot) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(arraySlot)));
    }

    function getMappingEntrySlot(uint256 mappingSlot, uint256 key) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(key, mappingSlot)));
    }
}
