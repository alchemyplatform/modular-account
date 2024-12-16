// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {StakeFactoryScript} from "../../script/StakeFactory.s.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";
import {ExecutionInstallDelegate} from "../../src/helpers/ExecutionInstallDelegate.sol";
import {WebAuthnValidationModule} from "../../src/modules/validation/WebAuthnValidationModule.sol";

import {OptimizedTest} from "../utils/OptimizedTest.sol";

contract StakeFactoryTest is OptimizedTest {
    StakeFactoryScript internal _stakeFactoryScript;

    EntryPoint internal _entryPoint;

    AccountFactory internal _accountFactory;

    uint256 internal constant _REQUIRED_STAKE_AMOUNT_WEI = 100_000_000_000_000_000;
    uint32 internal constant _UNSTAKE_DELAY_SEC = 86_400;

    function setUp() public {
        _stakeFactoryScript = new StakeFactoryScript();

        _entryPoint = _deployEntryPoint070();

        ExecutionInstallDelegate executionInstallDelegate = _deployExecutionInstallDelegate();

        _accountFactory = new AccountFactory(
            _entryPoint,
            _deployModularAccount(_entryPoint, executionInstallDelegate),
            _deploySemiModularAccountBytecode(_entryPoint, executionInstallDelegate),
            address(_deploySingleSignerValidationModule()),
            address(new WebAuthnValidationModule()),
            DEFAULT_SENDER
        );

        vm.setEnv("REQUIRED_STAKE_AMOUNT_WEI", vm.toString(_REQUIRED_STAKE_AMOUNT_WEI));
        vm.setEnv("UNSTAKE_DELAY_SEC", vm.toString(_UNSTAKE_DELAY_SEC));
        vm.setEnv("ACCOUNT_FACTORY_TO_STAKE", vm.toString(address(_accountFactory)));
    }

    function test_stakeFactoryScript_fromZero() public {
        IEntryPoint.DepositInfo memory factoryDepositInfo = _entryPoint.getDepositInfo(address(_accountFactory));

        assertFalse(factoryDepositInfo.staked, "Factory should not be staked");
        assertEq(factoryDepositInfo.stake, 0, "Factory Stake should be 0");
        assertEq(factoryDepositInfo.unstakeDelaySec, 0, "Factory Unstake Delay should be 0");

        _stakeFactoryScript.setUp();

        _stakeFactoryScript.run();

        factoryDepositInfo = _entryPoint.getDepositInfo(address(_accountFactory));

        assertTrue(factoryDepositInfo.staked, "Factory should be staked");
        assertEq(factoryDepositInfo.stake, _REQUIRED_STAKE_AMOUNT_WEI, "Factory Stake should be 1000");
        assertEq(factoryDepositInfo.unstakeDelaySec, _UNSTAKE_DELAY_SEC, "Factory Unstake Delay should be 86_400");
    }

    function test_stakeFactoryScript_fromNonZero() public {
        vm.prank(DEFAULT_SENDER);
        _accountFactory.addStake{value: _REQUIRED_STAKE_AMOUNT_WEI / 2}(uint32(_UNSTAKE_DELAY_SEC / 2));

        IEntryPoint.DepositInfo memory factoryDepositInfo = _entryPoint.getDepositInfo(address(_accountFactory));

        assertTrue(factoryDepositInfo.staked, "Factory should be staked");
        assertEq(factoryDepositInfo.stake, _REQUIRED_STAKE_AMOUNT_WEI / 2, "Factory Stake should be 500");
        assertEq(
            factoryDepositInfo.unstakeDelaySec, _UNSTAKE_DELAY_SEC / 2, "Factory Unstake Delay should be 43_200"
        );

        _stakeFactoryScript.setUp();

        _stakeFactoryScript.run();

        factoryDepositInfo = _entryPoint.getDepositInfo(address(_accountFactory));

        assertTrue(factoryDepositInfo.staked, "Factory should be staked");
        assertEq(factoryDepositInfo.stake, _REQUIRED_STAKE_AMOUNT_WEI, "Factory Stake should be 1000");
        assertEq(factoryDepositInfo.unstakeDelaySec, _UNSTAKE_DELAY_SEC, "Factory Unstake Delay should be 86_400");
    }
}
