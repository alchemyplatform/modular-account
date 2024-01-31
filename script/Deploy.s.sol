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

pragma solidity ^0.8.22;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/Test.sol";

import {IEntryPoint as I4337EntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../src/interfaces/erc4337/IEntryPoint.sol";
import {BasePlugin} from "../src/plugins/BasePlugin.sol";
import {MultiOwnerPlugin} from "../src/plugins/owner/MultiOwnerPlugin.sol";
import {SessionKeyPlugin} from "../src/plugins/session/SessionKeyPlugin.sol";

contract Deploy is Script {
    // Load entrypoint from env
    address public entryPointAddr = vm.envAddress("ENTRYPOINT");
    IEntryPoint public entryPoint = IEntryPoint(payable(entryPointAddr));

    // Load factory owner from env
    address public owner = vm.envAddress("OWNER");

    // Load core contract, if not in env, deploy new contract
    address public maImpl = vm.envOr("MA_IMPL", address(0));
    address public ownerFactoryAddr = vm.envOr("OWNER_FACTORY", address(0));
    MultiOwnerModularAccountFactory ownerFactory;

    // Load plugins contract, if not in env, deploy new contract
    address public multiOwnerPlugin = vm.envOr("OWNER_PLUGIN", address(0));
    bytes32 public multiOwnerPluginManifestHash;
    address public sessionKeyPlugin = vm.envOr("SESSION_KEY_PLUGIN", address(0));

    function run() public {
        console.log("******** Deploying *********");
        console.log("Chain: ", block.chainid);
        console.log("EP: ", entryPointAddr);
        console.log("Factory owner: ", owner);

        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy ma impl
        if (maImpl == address(0)) {
            UpgradeableModularAccount ma = new UpgradeableModularAccount(entryPoint);
            maImpl = address(ma);
            console.log("New MA impl: ", maImpl);
        } else {
            console.log("Exist MA impl: ", maImpl);
        }

        // Deploy multi owner plugin, and set plugin hash
        if (multiOwnerPlugin == address(0)) {
            MultiOwnerPlugin mop = new MultiOwnerPlugin();
            multiOwnerPlugin = address(mop);
            console.log("New MultiOwnerPlugin: ", multiOwnerPlugin);
        } else {
            console.log("Exist MultiOwnerPlugin: ", multiOwnerPlugin);
        }
        multiOwnerPluginManifestHash = keccak256(abi.encode(BasePlugin(multiOwnerPlugin).pluginManifest()));

        // Deploy MultiOwnerModularAccountFactory, and add stake with EP

        if (ownerFactoryAddr == address(0)) {
            ownerFactory = new MultiOwnerModularAccountFactory(
                owner, multiOwnerPlugin, maImpl, multiOwnerPluginManifestHash, entryPoint
            );

            ownerFactoryAddr = address(ownerFactory);
            console.log("New MultiOwnerModularAccountFactory: ", ownerFactoryAddr);
        } else {
            console.log("Exist MultiOwnerModularAccountFactory: ", ownerFactoryAddr);
        }
        _addStakeForFactory(ownerFactoryAddr, entryPoint);

        // Deploy SessionKeyPlugin impl
        if (sessionKeyPlugin == address(0)) {
            SessionKeyPlugin skp = new SessionKeyPlugin();
            sessionKeyPlugin = address(skp);
            console.log("New SessionKeyPlugin: ", sessionKeyPlugin);
        } else {
            console.log("Exist SessionKeyPlugin: ", sessionKeyPlugin);
        }

        console.log("******** Deploy Done! *********");
        vm.stopBroadcast();
    }

    function _addStakeForFactory(address factoryAddr, IEntryPoint anEntryPoint) internal {
        uint32 unstakeDelaySec = uint32(vm.envOr("UNSTAKE_DELAY_SEC", uint32(60)));
        uint256 requiredStakeAmount = vm.envUint("REQUIRED_STAKE_AMOUNT") * 1 ether;
        uint256 currentStakedAmount = I4337EntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).stake;
        uint256 stakeAmount = requiredStakeAmount - currentStakedAmount;
        // since all factory share the same addStake method, it does not matter which contract we use to cast the
        // address
        MultiOwnerModularAccountFactory(payable(factoryAddr)).addStake{value: stakeAmount}(
            unstakeDelaySec, stakeAmount
        );
        console.log("******** Add Stake Verify *********");
        console.log("Staked factory: ", factoryAddr);
        console.log("Stake amount: ", I4337EntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).stake);
        console.log(
            "Unstake delay: ", I4337EntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).unstakeDelaySec
        );
        console.log("******** Stake Verify Done *********");
    }
}
