// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModuleEntity} from "../../src/libraries/ModuleEntityLib.sol";
import {ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";

import {ContractOwnerValidationModule} from "../../src/modules/validation/ContractOwnerValidationModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ECDSAOwnerValidationModule is AccountTestBase {
    address public recipient = address(1);
    address payable public bundler = payable(address(2));
    ExecutionManifest internal _m;
    ModuleEntity public validationFunction;
    uint32 public entityId = 2;
    bytes4 internal constant _ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _ERC1271_BAD_VALUE = 0xffffffff;

    ModularAccount public acct;
    ContractOwnerValidationModule public valModule = new ContractOwnerValidationModule();

    function setUp() public {
        // Set up a validator with hooks from the erc20 spend limit module attached
        acct = factory.createAccount(address(this), 0, 0);

        vm.prank(address(acct));
        acct.installValidation(
            ValidationConfigLib.pack(address(valModule), entityId, true, true, true),
            new bytes4[](0),
            abi.encode(entityId, address(this)), // this contract is the owner
            new bytes[](0)
        );

        validationFunction = ModuleEntityLib.pack(address(valModule), entityId);
    }

    function test_contractOwner_validation() public view {
        bytes memory sig = _encode1271Signature(validationFunction, "");

        // event to check that the contract owner was called
        bytes4 val = acct.isValidSignature(keccak256(abi.encode("test")), sig);

        assertEq(val, _ERC1271_MAGIC_VALUE);
    }

    // This test contract is the contract owner of the account
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return _ERC1271_MAGIC_VALUE;
    }
}
