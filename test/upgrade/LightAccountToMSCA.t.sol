// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {LightAccount} from "@alchemy/light-account/src/LightAccount.sol";
import {LightAccountFactory} from "@alchemy/light-account/src/LightAccountFactory.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {IEntryPoint as IMSCAEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";

import {MockERC20} from "../mocks/tokens/MockERC20.sol";

contract LightAccountToMSCATest is Test {
    IEntryPoint public entryPoint;
    IMSCAEntryPoint public mscaEntryPoint;

    MockERC20 public token1;

    address public owner;
    address[] public owners;
    LightAccount public lightAccount;

    MultiOwnerPlugin public multiOwnerPlugin;
    address public mscaImpl;

    event ModularAccountInitialized(IMSCAEntryPoint indexed entryPoint);

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        mscaEntryPoint = IMSCAEntryPoint(address(entryPoint));
        (owner,) = makeAddrAndKey("owner");

        // set up light account
        LightAccountFactory lightAccountFactory = new LightAccountFactory(entryPoint);
        lightAccount = lightAccountFactory.createAccount(owner, 1);
        vm.deal(address(lightAccount), 2 ether);

        // setup mock tokens
        token1 = new MockERC20("T1");
        token1.mint(address(lightAccount), 1 ether);

        // setup MSCA
        multiOwnerPlugin = new MultiOwnerPlugin();
        mscaImpl = address(new UpgradeableModularAccount(mscaEntryPoint));
    }

    function test_verifySetup() public {
        assertEq(token1.balanceOf(address(lightAccount)), 1 ether);
        assertEq(token1.balanceOf(owner), 0 ether);

        address[] memory returnedOwners = multiOwnerPlugin.ownersOf(address(lightAccount));
        assertEq(returnedOwners, new address[](0));
        assertEq(payable(lightAccount).balance, 2 ether);
        assertEq(payable(owner).balance, 0);
    }

    function test_upgrade() public {
        // setup data for msca upgrade
        owners = new address[](1);
        owners[0] = owner;
        address[] memory plugins = new address[](1);
        plugins[0] = address(multiOwnerPlugin);
        bytes32[] memory manifestHashes = new bytes32[](1);
        manifestHashes[0] = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));
        bytes[] memory pluginInitBytes = new bytes[](1);
        pluginInitBytes[0] = abi.encode(owners);

        // upgrade to msca
        vm.startPrank(owner);
        vm.expectEmit(true, true, true, true);
        emit ModularAccountInitialized(mscaEntryPoint);
        lightAccount.upgradeToAndCall(
            mscaImpl,
            abi.encodeCall(
                UpgradeableModularAccount.initialize, (plugins, abi.encode(manifestHashes, pluginInitBytes))
            )
        );

        // verify upgrade success
        address[] memory returnedOwners = multiOwnerPlugin.ownersOf(address(lightAccount));
        assertEq(returnedOwners, owners);
        assertEq(token1.balanceOf(address(lightAccount)), 1 ether);

        // verify can do basic transaction
        lightAccount.execute(owner, 1 ether, "");
        assertEq(payable(lightAccount).balance, 1 ether);
        assertEq(payable(owner).balance, 1 ether);
    }
}
