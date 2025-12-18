// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {IStakeManager} from "@eth-infinitism/account-abstraction/interfaces/IStakeManager.sol";
import {console} from "forge-std/console.sol";

import {WebAuthnFactory} from "../src/factory/WebAuthnFactory.sol";

import {ScriptBase} from "./ScriptBase.sol";

contract StakeWebAuthnFactoryScript is ScriptBase {
    WebAuthnFactory internal _accountFactory;

    IEntryPoint internal _entryPoint;

    function setUp() public {
        _entryPoint = _getEntryPoint();

        // Has to use a different env var name to avoid conflicts with the one in DeployFactoryScript, because
        // vm.setEnv in tests doesn't isolate and it would result in a race condition.
        _accountFactory = WebAuthnFactory(vm.envOr("WEBAUTHN_ACCOUNT_FACTORY_TO_STAKE", address(0)));
    }

    function run() public {
        console.log("******** Staking Account Factory *********");

        if (address(_accountFactory) == address(0)) {
            console.log("WebAuthn Account Factory not found or invalid");
            revert();
        }

        console.log("Using WebAuthn AccountFactory at address: ", address(_accountFactory));

        (uint256 stakeAmountWei, uint256 unstakeDelay) = _getStakeParams();

        uint256 stakeNeeded = _checkCurrentStake(stakeAmountWei);

        vm.startBroadcast();

        _accountFactory.addStake{value: stakeNeeded}(uint32(unstakeDelay));

        vm.stopBroadcast();

        console.log("******** Done Staking WebAuthn Account Factory *********");
    }

    function _getStakeParams() internal view returns (uint256 stakeAmountWei, uint256 unstakeDelaySec) {
        stakeAmountWei = vm.envOr("REQUIRED_STAKE_AMOUNT_WEI", uint256(0));

        if (stakeAmountWei == 0) {
            console.log("Env Variable 'REQUIRED_STAKE_AMOUNT_WEI' not found or invalid.");
            revert();
        }

        console.log("Using user-defined stake amount: ", stakeAmountWei);

        unstakeDelaySec = vm.envOr("UNSTAKE_DELAY_SEC", uint256(0));

        if (unstakeDelaySec == 0) {
            console.log("Env Variable 'UNSTAKE_DELAY_SEC' not found or invalid.");
            revert();
        }

        console.log("Using user-defined unstake delay: ", unstakeDelaySec);
    }

    function _checkCurrentStake(uint256 requiredStakeAmountWei) internal view returns (uint256 stakeNeeded) {
        IStakeManager.DepositInfo memory factoryDepositInfo = _entryPoint.getDepositInfo(address(_accountFactory));

        uint256 currentStake = factoryDepositInfo.stake;

        if (currentStake > requiredStakeAmountWei) {
            console.log("WebAuthn Factory already has enough stake: ", currentStake);
            stakeNeeded = 0;
        } else {
            stakeNeeded = requiredStakeAmountWei - currentStake;
            console.log("Adding stake to webauthn factory: ", stakeNeeded);
        }

        return stakeNeeded;
    }
}
