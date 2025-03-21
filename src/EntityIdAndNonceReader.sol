// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ValidationFlags} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {
    IModularAccountView,
    ValidationDataView
} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

// This contract finds the first uninstalled entity id in a MA v2 account, reads the EP nonce given the parallel
// nonce and validation options, and returns the full nonce.
// This allows a client to obtain the entity id and nonce in a single eth_call.
contract EntityIdAndNonceReader {
    /**
     * constructor
     * @param account account address
     * @param ep entrypoint address
     * @param nonce uint192 nonce. First 152 bits = parallel nonce, next 32 is empty, last 8 are val options
     */
    constructor(IModularAccountView account, IEntryPoint ep, uint192 nonce) {
        uint32 startEntityId = uint32(nonce >> 8);
        uint32 entityId = startEntityId > 0 ? startEntityId : 1;

        if (address(account).code.length > 0) {
            while (true) {
                ValidationDataView memory data =
                    account.getValidationData(ModuleEntityLib.pack(address(0), entityId));
                // if global validation is empty and selector validation is empty, we treat the key as unused
                if (uint8(ValidationFlags.unwrap(data.validationFlags)) == 0 && data.selectors.length == 0) {
                    break;
                }
                entityId++;
            }
        }

        // full nonce = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBB_CC_DDDDDDDDDDDDDDDD
        // where A = nonce key, B = entity id, C = val options, D = response from EP
        uint256 fullNonce =
            ep.getNonce(address(account), nonce & ~uint192(0xFFFFFFFF00) | (uint192(entityId) << 8));
        assembly ("memory-safe") {
            mstore(0, fullNonce)
            return(0, 32)
        }
    }
}
