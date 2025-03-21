// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ValidationFlags} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    IModularAccountView,
    ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";

contract EntityIdReader {
    constructor(IModularAccountView account, uint32 startEntityId) {
        uint32 entityId = startEntityId;
        while (true) {
            ValidationDataView memory data = account.getValidationData(ModuleEntityLib.pack(address(0), entityId));
            // if global validation is empty and selector validation is empty, we treat the key as unused
            if (uint8(ValidationFlags.unwrap(data.validationFlags)) == 0 && data.selectors.length == 0) {
                assembly ("memory-safe") {
                    mstore(0, entityId)
                    return(28, 4)
                }
            }
            entityId++;
        }
    }
}
