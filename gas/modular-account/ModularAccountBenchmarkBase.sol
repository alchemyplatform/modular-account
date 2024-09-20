// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {AccountFactory} from "../../src/account/AccountFactory.sol";
import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccount} from "../../src/account/SemiModularAccount.sol";

import {ModuleEntity, ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {ModuleSignatureUtils} from "../../test/utils/ModuleSignatureUtils.sol";
import {BenchmarkBase} from "..//BenchmarkBase.sol";

abstract contract ModularAccountBenchmarkBase is BenchmarkBase, ModuleSignatureUtils {
    AccountFactory public factory;
    ModularAccount public accountImpl;
    SemiModularAccount public semiModularImpl;
    SingleSignerValidationModule public singleSignerValidationModule;

    ModularAccount public account1;

    ModuleEntity public signerValidation;

    constructor(string memory accountImplName) BenchmarkBase(accountImplName) {
        accountImpl = _deployModularAccount(IEntryPoint(entryPoint));
        semiModularImpl = _deploySemiModularAccount(IEntryPoint(entryPoint));
        singleSignerValidationModule = _deploySingleSignerValidationModule();

        factory = new AccountFactory(
            entryPoint, accountImpl, semiModularImpl, address(singleSignerValidationModule), address(this)
        );
    }

    function _deployAccount1() internal {
        account1 = factory.createAccount(owner1, 0, 0);
        signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), 0);
    }
}
