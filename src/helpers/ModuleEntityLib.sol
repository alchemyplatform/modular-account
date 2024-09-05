// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ModuleEntity} from "@erc-6900/reference-implementation/interfaces/IModularAccount.sol";

library ModuleEntityLib {
    // Magic value for hooks that should always revert.
    ModuleEntity internal constant _PRE_HOOK_ALWAYS_DENY = ModuleEntity.wrap(bytes24(uint192(2)));

    function pack(address addr, uint32 entityId) internal pure returns (ModuleEntity) {
        return ModuleEntity.wrap(bytes24(bytes20(addr)) | bytes24(uint192(entityId)));
    }

    function unpack(ModuleEntity fr) internal pure returns (address addr, uint32 entityId) {
        bytes24 underlying = ModuleEntity.unwrap(fr);
        addr = address(bytes20(underlying));
        entityId = uint32(bytes4(underlying << 160));
    }

    function isEmpty(ModuleEntity fr) internal pure returns (bool) {
        return ModuleEntity.unwrap(fr) == bytes24(0);
    }

    function notEmpty(ModuleEntity fr) internal pure returns (bool) {
        return ModuleEntity.unwrap(fr) != bytes24(0);
    }

    function eq(ModuleEntity a, ModuleEntity b) internal pure returns (bool) {
        return ModuleEntity.unwrap(a) == ModuleEntity.unwrap(b);
    }

    function notEq(ModuleEntity a, ModuleEntity b) internal pure returns (bool) {
        return ModuleEntity.unwrap(a) != ModuleEntity.unwrap(b);
    }
}
