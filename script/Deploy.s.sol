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

import {console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {IEntryPoint as IMSCAEntryPoint} from "../src/interfaces/erc4337/IEntryPoint.sol";

import {UpgradeableModularAccount} from "../src/account/UpgradeableModularAccount.sol";

import {MultiOwnerMSCAFactory} from "../src/factory/MultiOwnerMSCAFactory.sol";
import {MultiOwnerTokenReceiverMSCAFactory} from "../src/factory/MultiOwnerTokenReceiverMSCAFactory.sol";

import {BasePlugin} from "../src/plugins/BasePlugin.sol";
import {MultiOwnerPlugin} from "../src/plugins/owner/MultiOwnerPlugin.sol";
import {TokenReceiverPlugin} from "../src/plugins/TokenReceiverPlugin.sol";
import {SessionKeyPlugin} from "../src/plugins/session/SessionKeyPlugin.sol";

contract Deploy is Script {
    // Load entrypoint from env
    address public entryPointAddr = vm.envAddress("ENTRYPOINT");
    IMSCAEntryPoint public entryPoint = IMSCAEntryPoint(payable(entryPointAddr));

    // Load factory owner from env
    address public owner = vm.envAddress("OWNER");

    // Load core contract, if not in env, deploy new contract
    address public mscaImpl = vm.envOr("MSCA_IMPL", address(0));
    address public ownerFactoryAddr = vm.envOr("OWNER_FACTORY", address(0));
    address public ownerAndTokenReceiverFactoryAddr = vm.envOr("OWNER_TOKEN_RECEIVER_FACTORY", address(0));
    MultiOwnerMSCAFactory ownerFactory;
    MultiOwnerTokenReceiverMSCAFactory ownerAndTokenReceiverFactory;

    // Load plugins contract, if not in env, deploy new contract
    address public multiOwnerPlugin = vm.envOr("OWNER_PLUGIN", address(0));
    bytes32 public multiOwnerPluginManifestHash;
    address public tokenReceiverPlugin = vm.envOr("TOKEN_RECEIVER_PLUGIN", address(0));
    bytes32 public tokenReceiverPluginManifestHash;
    address public sessionKeyPlugin = vm.envOr("SESSION_KEY_PLUGIN", address(0));

    function run() public {
        console.log("******** Deploying *********");
        console.log("Chain: ", block.chainid);
        console.log("EP: ", entryPointAddr);
        console.log("Factory owner: ", owner);

        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy msca impl
        if (mscaImpl == address(0)) {
            UpgradeableModularAccount msca = new UpgradeableModularAccount(entryPoint);
            mscaImpl = address(msca);
            console.log("New MSCA impl: ", mscaImpl);
        } else {
            console.log("Exist MSCA impl: ", mscaImpl);
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

        // Deploy multi owner plugin, and set plugin hash
        if (tokenReceiverPlugin == address(0)) {
            TokenReceiverPlugin trp = new TokenReceiverPlugin();
            tokenReceiverPlugin = address(trp);
            console.log("New TokenReceiverPlugin: ", tokenReceiverPlugin);
        } else {
            console.log("Exist TokenReceiverPlugin: ", tokenReceiverPlugin);
        }
        tokenReceiverPluginManifestHash = keccak256(abi.encode(BasePlugin(tokenReceiverPlugin).pluginManifest()));

        // Deploy MultiOwnerMSCAFactory, and add stake with EP
        {
            if (ownerFactoryAddr == address(0)) {
                ownerFactory = new MultiOwnerMSCAFactory(
                    owner, multiOwnerPlugin, mscaImpl, multiOwnerPluginManifestHash, entryPoint
                );

                ownerFactoryAddr = address(ownerFactory);
                console.log("New MultiOwnerMSCAFactory: ", ownerFactoryAddr);
            } else {
                console.log("Exist MultiOwnerMSCAFactory: ", ownerFactoryAddr);
            }
            _addStakeForFactory(ownerFactoryAddr, entryPoint);
        }

        // Deploy MultiOwnerTokenReceiverMSCAFactory, and add stake with EP
        if (ownerAndTokenReceiverFactoryAddr == address(0)) {
            ownerAndTokenReceiverFactory = new MultiOwnerTokenReceiverMSCAFactory(
                owner,
                multiOwnerPlugin,
                tokenReceiverPlugin,
                mscaImpl,
                multiOwnerPluginManifestHash,
                tokenReceiverPluginManifestHash,
                entryPoint
            );

            ownerAndTokenReceiverFactoryAddr = address(ownerAndTokenReceiverFactory);
            console.log("New MultiOwnerTokenReceiverMSCAFactory: ", ownerAndTokenReceiverFactoryAddr);
        } else {
            console.log("Exist MultiOwnerTokenReceiverMSCAFactory: ", ownerAndTokenReceiverFactoryAddr);
        }
        _addStakeForFactory(ownerAndTokenReceiverFactoryAddr, entryPoint);

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

    function _addStakeForFactory(address factoryAddr, IMSCAEntryPoint anEntryPoint) internal {
        uint32 unstakeDelaySec = uint32(vm.envOr("UNSTAKE_DELAY_SEC", uint32(60)));
        uint256 requiredStakeAmount = vm.envUint("REQUIRED_STAKE_AMOUNT") * 1 ether;
        uint256 currentStakedAmount = IEntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).stake;
        uint256 stakeAmount = requiredStakeAmount - currentStakedAmount;
        // since all factory share the same addStake method, it does not matter which contract we use to cast the
        // address
        MultiOwnerMSCAFactory(payable(factoryAddr)).addStake{value: stakeAmount}(unstakeDelaySec, stakeAmount);
        console.log("******** Add Stake Verify *********");
        console.log("Staked factory: ", factoryAddr);
        console.log("Stake amount: ", IEntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).stake);
        console.log(
            "Unstake delay: ", IEntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).unstakeDelaySec
        );
        console.log("******** Stake Verify Done *********");
    }
}
