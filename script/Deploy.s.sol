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
import "forge-std/StdJson.sol";
import {IEntryPoint as I4337EntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerModularAccountFactory} from "../src/factory/MultiOwnerModularAccountFactory.sol";
import {IEntryPoint} from "../src/interfaces/erc4337/IEntryPoint.sol";
import {BasePlugin} from "../src/plugins/BasePlugin.sol";
import {MultiOwnerPlugin} from "../src/plugins/owner/MultiOwnerPlugin.sol";
import {SessionKeyPlugin} from "../src/plugins/session/SessionKeyPlugin.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

contract Deploy is Script {
    using stdJson for string;

    address public entryPointAddr;
    IEntryPoint public entryPoint;
    address public owner;
    bytes32 public multiOwnerPluginManifestHash;
    uint256 public maImplSalt;
    uint256 public factorySalt;
    uint256 public multiOwnerPluginSalt;
    uint256 public sessionKeyPluginSalt;
    address public expectedMaImpl;
    address public expectedFactory;
    address public expectedMultiOwnerPlugin;
    address public expectedSessionKeyPlugin;

    function readInputsFromPath() internal {
        string memory json = vm.readFile("input.json");
        entryPointAddr = json.readAddress("$.entryPoint");
        entryPoint = IEntryPoint(payable(entryPointAddr));
        owner = json.readAddress("$.owner");
        maImplSalt = json.readUint("$.maImplSalt");
        factorySalt = json.readUint("$.factorySalt");
        multiOwnerPluginSalt = json.readUint("$.multiOwnerPluginSalt");
        sessionKeyPluginSalt = json.readUint("$.sessionKeyPluginSalt");
        expectedMaImpl = json.readAddress("$.maImpl");
        expectedFactory = json.readAddress("$.factory");
        expectedMultiOwnerPlugin = json.readAddress("$.multiOwnerPlugin");
        expectedSessionKeyPlugin = json.readAddress("$.sessionKeyPlugin");
    }

    function run() public {
        readInputsFromPath();
        console.log("******** Deploying *********");
        console.log("Chain: ", block.chainid);
        console.log("EP: ", entryPointAddr);
        console.log("Factory owner: ", owner);

        vm.startBroadcast();
        UpgradeableModularAccount maImpl = deployMA(bytes32(maImplSalt), expectedMaImpl, entryPoint);
        MultiOwnerPlugin multiOwnerPlugin = deployMAP(bytes32(multiOwnerPluginSalt), expectedMultiOwnerPlugin);
        multiOwnerPluginManifestHash = keccak256(abi.encode(BasePlugin(multiOwnerPlugin).pluginManifest()));
        deployMAFactory(bytes32(factorySalt), expectedFactory, entryPoint, address(multiOwnerPlugin), address(maImpl), owner, multiOwnerPluginManifestHash);
        deploySK(bytes32(sessionKeyPluginSalt), expectedSessionKeyPlugin);

        console.log("******** Deploy Done! *********");
        vm.stopBroadcast();
    }

    function deployMAFactory(bytes32 saltBytes, address expected, IEntryPoint ep, address mop, address uma, address own, bytes32 maHash) private returns (MultiOwnerModularAccountFactory) {
        address addr = Create2.computeAddress(
            saltBytes, keccak256(abi.encodePacked(type(MultiOwnerModularAccountFactory).creationCode, abi.encode(own, mop, uma, maHash, ep))), CREATE2_FACTORY
        );

        console.logAddress(addr);
        require(addr == expected, "Expected address is not the same as computed for ma factory");
        if (addr.code.length > 0) {
            console.log("ModularAccountFactory impl already deployed. Skipping");
            return MultiOwnerModularAccountFactory(payable(addr));
        }

        MultiOwnerModularAccountFactory impl = new MultiOwnerModularAccountFactory{salt: saltBytes}(own, mop, uma, maHash, ep);
        require(address(impl) == addr, "Impl address did not match predicted");
        return impl;
    }

    function deployMA(bytes32 saltBytes, address expected, IEntryPoint ep) private returns (UpgradeableModularAccount) {
        address addr = Create2.computeAddress(
            saltBytes, keccak256(abi.encodePacked(type(UpgradeableModularAccount).creationCode, abi.encode(ep))), CREATE2_FACTORY
        );

        console.logAddress(addr);
        require(addr == expected, "Expected address is not the same as computed for ma");
        if (addr.code.length > 0) {
            console.log("ModularAccount impl already deployed. Skipping");
            return UpgradeableModularAccount(payable(addr));
        }

        UpgradeableModularAccount impl = new UpgradeableModularAccount{salt: saltBytes}(ep);
        require(address(impl) == addr, "Impl address did not match predicted");
        return impl;
    }

    function deploySK(bytes32 saltBytes, address expected) private returns (SessionKeyPlugin) {
        address addr = Create2.computeAddress(
            saltBytes, keccak256(abi.encodePacked(type(SessionKeyPlugin).creationCode)), CREATE2_FACTORY
        );

        console.logAddress(addr);
        require(addr == expected, "Expected address is not the same as computed for sk plugin");
        if (addr.code.length > 0) {
            console.log("SessionKey impl already deployed. Skipping");
            return SessionKeyPlugin(payable(addr));
        }

        SessionKeyPlugin impl = new SessionKeyPlugin{salt: saltBytes}();
        require(address(impl) == addr, "Impl address did not match predicted");
        return impl;
    }

    function deployMAP(bytes32 saltBytes, address expected) private returns (MultiOwnerPlugin) {
        address addr = Create2.computeAddress(
            saltBytes, keccak256(abi.encodePacked(type(MultiOwnerPlugin).creationCode)), CREATE2_FACTORY
        );

        console.logAddress(addr);
        require(addr == expected, "Expected address is not the same as computed for mo plugin");
        if (addr.code.length > 0) {
            console.log("MultiOwnerPlugin impl already deployed. Skipping");
            return MultiOwnerPlugin(payable(addr));
        }

        MultiOwnerPlugin impl = new MultiOwnerPlugin{salt: saltBytes}();
        require(address(impl) == addr, "Impl address did not match predicted");
        return impl;
    }

    // function _addStakeForFactory(address factoryAddr, IEntryPoint anEntryPoint) internal {
    //     uint32 unstakeDelaySec = uint32(vm.envOr("UNSTAKE_DELAY_SEC", uint32(86400)));
    //     uint256 requiredStakeAmount = vm.envUint("REQUIRED_STAKE_AMOUNT");
    //     uint256 currentStakedAmount = I4337EntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).stake;
    //     uint256 stakeAmount = requiredStakeAmount - currentStakedAmount;
    //     // since all factory share the same addStake method, it does not matter which contract we use to cast the
    //     // address
    //     MultiOwnerModularAccountFactory(payable(factoryAddr)).addStake{value: stakeAmount}(
    //         unstakeDelaySec, stakeAmount
    //     );
    //     console.log("******** Add Stake Verify *********");
    //     console.log("Staked factory: ", factoryAddr);
    //     console.log("Stake amount: ", I4337EntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).stake);
    //     console.log(
    //         "Unstake delay: ", I4337EntryPoint(address(anEntryPoint)).getDepositInfo(factoryAddr).unstakeDelaySec
    //     );
    //     console.log("******** Stake Verify Done *********");
    // }
}
