// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {NonceAndEntityIdReader} from "../../src/NonceAndEntityIdReader.sol";
import {AccountTestBase} from "./AccountTestBase.sol";
import {DIRECT_CALL_VALIDATION_ENTITY_ID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {
    ValidationConfig,
    ValidationConfigLib
} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {console} from "forge-std/console.sol";

contract NonceAndEntityIdReaderTest is AccountTestBase {
    function testRead(uint152 parallelNonce, uint8 validationOptions, uint8 endEntityId) public {
        vm.assume(endEntityId != 0);
        vm.assume(endEntityId != 1);

        vm.startPrank(owner1);
        for (uint32 entityId = 1; entityId < uint32(endEntityId); entityId++) {
            account1.executeWithRuntimeValidation(
                abi.encodeCall(
                    account1.installValidation,
                    (
                        ValidationConfigLib.pack(address(this), entityId, true, false, false),
                        new bytes4[](0),
                        "",
                        new bytes[](0)
                    )
                ),
                _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
            );
        }

        address readerFromStart = address(
            new NonceAndEntityIdReader(account1, 1, entryPoint, parallelNonce << 40 | 1 << 8 | validationOptions)
        );
        address readerFromEnd = address(
            new NonceAndEntityIdReader(
                account1, 1, entryPoint, parallelNonce << 40 | endEntityId << 8 | validationOptions
            )
        );

        uint256 actualNonce = entryPoint.getNonce(
            address(account1), parallelNonce << 40 | uint152(endEntityId) << 8 | uint152(validationOptions)
        );

        assertEq(readerFromStart.code.length, 32);
        assertEq(readerFromEnd.code.length, 32);

        assertEq(uint256(bytes32(readerFromStart.code)), actualNonce);
        assertEq(uint256(bytes32(readerFromEnd.code)), actualNonce);
    }
}
