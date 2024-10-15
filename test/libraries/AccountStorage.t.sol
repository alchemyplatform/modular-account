// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Test} from "forge-std/src/Test.sol";

import {_ACCOUNT_STORAGE_SLOT} from "../../src/account/AccountStorage.sol";
import {AccountStorageInitializable} from "../../src/account/AccountStorageInitializable.sol";
import {MockDiamondStorageContract} from "../mocks/MockDiamondStorageContract.sol";

// Test implementation of AccountStorageInitializable which is contained in ReferenceModularAccount
contract AccountStorageTest is Test {
    MockDiamondStorageContract public impl;
    address public proxy;

    function setUp() external {
        impl = new MockDiamondStorageContract();
        proxy = address(new ERC1967Proxy(address(impl), ""));
    }

    function test_storageSlotImpl() external {
        // disable initializers sets value to uint8(max)
        assertEq(uint256(vm.load(address(impl), _ACCOUNT_STORAGE_SLOT)), type(uint8).max);

        // should revert if we try to initialize again
        vm.expectRevert(AccountStorageInitializable.InvalidInitialization.selector);
        impl.initialize();
    }

    function test_storageSlotProxy() external {
        // before init, proxy's slot should be empty
        assertEq(uint256(vm.load(proxy, _ACCOUNT_STORAGE_SLOT)), uint256(0));

        MockDiamondStorageContract(proxy).initialize();
        // post init slot should contains: packed(uint8 initialized = 1, bool initializing = 0)
        assertEq(uint256(vm.load(proxy, _ACCOUNT_STORAGE_SLOT)), uint256(1));
    }

    function test_accountStorage_revertOnBadDisableInitializers() public {
        vm.expectRevert(AccountStorageInitializable.InvalidInitialization.selector);
        MockDiamondStorageContract(proxy).badDisableInitializers();
    }
}
