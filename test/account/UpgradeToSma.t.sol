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
        // This should only fail if the contract is initialized, and SMABytecode does not have an initializer,
        // so we skip this case by checking the env variable.
        if (vm.envOr("SMA_TEST", false)) {
            return;
        }

        // The call should revert with invalid initialization.
        vm.expectRevert(AccountStorageInitializable.InvalidInitialization.selector);

        // Attempt an upgrade and re-initialization.
        vm.prank(address(entryPoint));
        account1.upgradeToAndCall(smaStorageImpl, abi.encodeCall(SemiModularAccountStorage.initialize, owner2));
    }

    // Positives

    function test_upgradeToAndCall_MaToSmaStorage() external {
        // We call `updateFallbackSigner()` to upgrade from an MA to an SMA-S, because we are already initialized.
        vm.prank(address(entryPoint));
        account1.upgradeToAndCall(
            smaStorageImpl, abi.encodeCall(SemiModularAccountBase.updateFallbackSigner, owner2)
        );

        // Build expected revert data for a UO with the original signer.
        bytes memory expectedRevertdata =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error");

        // Attempt to execute a UO with the original signer, anticipating a revert.
        _userOpTransfer(address(account1), owner1Key, expectedRevertdata);

        // Attempt to successfully execute a UO with the new signer, which is the fallback signer.
        _userOpTransfer(address(account1), owner2Key, "");
    }

    function test_upgradeToAndCall_LaToSmaStorage() external {
        address lightAccountImpl = address(new LightAccount(entryPoint));

        // We use deploy rather than create because we want to revert if the light account is already deployed, if
        // it does revert the error is `DeploymentFailed()`.
        address payable newAccount = payable(LibClone.deployDeterministicERC1967(lightAccountImpl, 0x00));

        // Initialize the LightAccount (which has its own storage namespacing) with the original signer.
        LightAccount(newAccount).initialize(owner1);

        // Upgrade the LightAccount to an SMA-Storage and call the initializer.
        vm.prank(address(entryPoint));
        ModularAccount(newAccount).upgradeToAndCall(
            smaStorageImpl, abi.encodeCall(SemiModularAccountStorage.initialize, owner2)
        );

        // Build expected revert data for a UO with the original signer.
        bytes memory expectedRevertdata =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error");

        // Attempt to execute a UO with the original signer, anticipating a revert.
        _userOpTransfer(address(newAccount), owner1Key, expectedRevertdata);

        // Attempt to successfully execute a UO with the new signer, which is the fallback signer.
        _userOpTransfer(newAccount, owner2Key, "");
    }

    function _userOpTransfer(address account, uint256 ownerKey, bytes memory expectedRevertData) internal {
        // Pre-fund the account.
        deal(account, 1 ether);

        // Generate a target and ensure it has no balance.
        address target = makeAddr("4546b");
        assertEq(target.balance, 0, "Target has balance when it shouldn't");

        // Encode a transfer to the target.
        bytes memory encodedCall = abi.encodeCall(ModularAccountBase.execute, (target, 0.1 ether, ""));

        // Run a UO with the encoded call.
        _runUserOpFrom(account, ownerKey, encodedCall, expectedRevertData);

        // If the call was not supposed to revert, ensure the transfer succeeded.
        if (expectedRevertData.length == 0) {
            assertEq(target.balance, 0.1 ether, "Target missing balance from UO transfer");
        }
    }
}
