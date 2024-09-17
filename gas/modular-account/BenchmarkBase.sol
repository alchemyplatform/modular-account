// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {GasSnapshot} from "forge-gas-snapshot/GasSnapshot.sol";

import {AccountFactory} from "../../src/account/AccountFactory.sol";
import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccount} from "../../src/account/SemiModularAccount.sol";

import {ModuleEntity, ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {MockERC20} from "../../test/mocks/MockERC20.sol";

import {ModuleSignatureUtils} from "../../test/utils/ModuleSignatureUtils.sol";
import {OptimizedTest} from "../../test/utils/OptimizedTest.sol";

abstract contract ModularAccountBenchmarkBase is GasSnapshot, OptimizedTest, ModuleSignatureUtils {
    EntryPoint public entryPoint;

    AccountFactory public factory;
    ModularAccount public accountImpl;
    SemiModularAccount public semiModularImpl;
    SingleSignerValidationModule public singleSignerValidationModule;

    ModularAccount public account1;

    address public owner1;
    uint256 public owner1Key;

    address public recipient;
    MockERC20 public mockErc20;

    ModuleEntity public signerValidation;

    constructor() {
        (owner1, owner1Key) = makeAddrAndKey("owner1");

        recipient = makeAddr("recipient");
        vm.deal(recipient, 1 wei);

        entryPoint = _deployEntryPoint070();
        accountImpl = _deployModularAccount(IEntryPoint(entryPoint));
        semiModularImpl = _deploySemiModularAccount(IEntryPoint(entryPoint));
        singleSignerValidationModule = _deploySingleSignerValidationModule();
        mockErc20 = new MockERC20();

        factory = new AccountFactory(
            entryPoint, accountImpl, semiModularImpl, address(singleSignerValidationModule), address(this)
        );
    }

    function _deployAccount1() internal {
        account1 = factory.createAccount(owner1, 0, 0);
        signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), 0);
    }
}
