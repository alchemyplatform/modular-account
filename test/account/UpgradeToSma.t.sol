// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {AccountStorageInitializable} from "../../src/account/AccountStorageInitializable.sol";
import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {SemiModularAccountBase} from "../../src/account/SemiModularAccountBase.sol";
import {SemiModularAccountStorage} from "../../src/account/SemiModularAccountStorage.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {LightAccount} from "@alchemy/light-account/src/LightAccount.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract UpgradeToSmaTest is AccountTestBase {
    address public smaStorageImpl;
    address public owner2;
    uint256 public owner2Key;

    function setUp() external {
        smaStorageImpl = address(new SemiModularAccountStorage(entryPoint));
        (owner2, owner2Key) = makeAddrAndKey("owner2");
    }

    function test_fail_upgradeToAndCall_initializedMaToSmaStorage() external {
        if (vm.envOr("SMA_TEST", false)) {
            // This should only fail if the contract is initialized, and SMABytecode does not have an initializer,
            // so we skip this case.
            return;
        }

        vm.expectRevert(AccountStorageInitializable.InvalidInitialization.selector);

        vm.prank(address(entryPoint));
        account1.upgradeToAndCall(smaStorageImpl, abi.encodeCall(SemiModularAccountStorage.initialize, owner2));
    }

    // Positives

    function test_upgradeToAndCall_MaToSmaStorage() external {
        vm.prank(address(entryPoint));
        // We call `updateFallbackSigner()` to upgrade from an MA to an SMA-S, because we are already initialized.
        account1.upgradeToAndCall(
            smaStorageImpl, abi.encodeCall(SemiModularAccountBase.updateFallbackSigner, owner2)
        );

        bytes memory expectedRevertdata =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error");

        _userOpTransfer(address(account1), owner1Key, expectedRevertdata);

        _userOpTransfer(address(account1), owner2Key, "");
    }

    function test_upgradeToAndCall_LaToSmaStorage() external {
        address lightAccountImpl = address(new LightAccount(entryPoint));

        // We use deploy rather than create because we want to revert if the account is already deployed, if it
        // does revert the error is `DeploymentFailed()`.
        address payable newAccount = payable(LibClone.deployDeterministicERC1967(lightAccountImpl, 0x00));
        LightAccount(newAccount).initialize(owner1);

        vm.prank(address(entryPoint));
        ModularAccount(newAccount).upgradeToAndCall(
            smaStorageImpl, abi.encodeCall(SemiModularAccountStorage.initialize, owner2)
        );

        bytes memory expectedRevertdata =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error");

        _userOpTransfer(address(newAccount), owner1Key, expectedRevertdata);

        _userOpTransfer(newAccount, owner2Key, "");
    }

    function _userOpTransfer(address account, uint256 ownerKey, bytes memory expectedRevertData) internal {
        deal(account, 1 ether);

        address target = makeAddr("4546b");
        assertEq(target.balance, 0, "Target has balance when it shouldn't");

        bytes memory encodedCall = abi.encodeCall(ModularAccountBase.execute, (target, 0.1 ether, ""));

        _runUserOpFrom(account, ownerKey, encodedCall, expectedRevertData);

        if (expectedRevertData.length == 0) {
            assertEq(target.balance, 0.1 ether, "Target missing balance from UO transfer");
        }
    }
}
