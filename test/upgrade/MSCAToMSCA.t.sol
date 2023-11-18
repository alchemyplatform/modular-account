// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MultiOwnerTokenReceiverMSCAFactory} from "../../src/factory/MultiOwnerTokenReceiverMSCAFactory.sol";
import {MultiOwnerPlugin} from "../../src/plugins/owner/MultiOwnerPlugin.sol";
import {TokenReceiverPlugin} from "../../src/plugins/TokenReceiverPlugin.sol";
import {IEntryPoint} from "../../src/interfaces/erc4337/IEntryPoint.sol";

import {Utils} from "../Utils.sol";
import {MockERC20} from "../mocks/tokens/MockERC20.sol";

contract MSCAToMSCATest is Test {
    IEntryPoint public entryPoint;

    MockERC20 public token1;

    address[] public owners;
    UpgradeableModularAccount public msca;

    MultiOwnerPlugin public multiOwnerPlugin;
    TokenReceiverPlugin public tokenReceiverPlugin;
    address public mscaImpl1;
    address public mscaImpl2;

    event Upgraded(address indexed implementation);

    function setUp() public {
        owners.push(makeAddr("owner1"));
        owners.push(makeAddr("owner2"));
        entryPoint = IEntryPoint(address(new EntryPoint()));
        mscaImpl1 = address(new UpgradeableModularAccount(entryPoint));
        mscaImpl2 = address(new UpgradeableModularAccount(entryPoint));
        multiOwnerPlugin = new MultiOwnerPlugin();
        tokenReceiverPlugin = new TokenReceiverPlugin();
        bytes32 ownerManifestHash = keccak256(abi.encode(multiOwnerPlugin.pluginManifest()));
        bytes32 tokenReceiverManifestHash = keccak256(abi.encode(tokenReceiverPlugin.pluginManifest()));
        MultiOwnerTokenReceiverMSCAFactory factory = new MultiOwnerTokenReceiverMSCAFactory(
            address(this),
            address(multiOwnerPlugin), 
            address(tokenReceiverPlugin),
            mscaImpl1, 
            ownerManifestHash, 
            tokenReceiverManifestHash,
            entryPoint
        );
        msca = UpgradeableModularAccount(payable(factory.createAccount(0, owners)));
        vm.deal(address(msca), 2 ether);

        // setup mock tokens
        token1 = new MockERC20("T1");
        token1.mint(address(msca), 1 ether);
    }

    function test_sameStorageSlot_upgradeToAndCall() public {
        vm.startPrank(owners[0]);

        // upgrade to mscaImpl2
        vm.expectEmit(true, true, true, true);
        emit Upgraded(mscaImpl2);
        msca.upgradeToAndCall(mscaImpl2, "");

        // verify account storage is the same
        (, bytes memory returnData) = address(msca).call(abi.encodeWithSelector(MultiOwnerPlugin.owners.selector));
        address[] memory returnedOwners = abi.decode(returnData, (address[]));
        assertEq(Utils.reverseAddressArray(returnedOwners), owners);
        assertEq(token1.balanceOf(address(msca)), 1 ether);

        // verify can do basic transaction
        msca.execute(owners[0], 1 ether, "");
        assertEq(payable(msca).balance, 1 ether);
        assertEq(payable(owners[0]).balance, 1 ether);

        vm.stopPrank();
    }
}
