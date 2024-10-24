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

pragma solidity ^0.8.26;

import {LightAccount} from "@alchemy/light-account/src/LightAccount.sol";

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {AccountStorageInitializable} from "../../src/account/AccountStorageInitializable.sol";
import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {SemiModularAccountBase} from "../../src/account/SemiModularAccountBase.sol";
import {SemiModularAccountStorageOnly} from "../../src/account/SemiModularAccountStorageOnly.sol";
import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {CODELESS_ADDRESS} from "../utils/TestConstants.sol";

contract UpgradeToSmaTest is AccountTestBase {
    using ModuleEntityLib for ModuleEntity;
    using MessageHashUtils for bytes32;

    address public smaStorageImpl;
    address public owner2;
    uint256 public owner2Key;
    uint256 public transferAmount;

    function setUp() public override {
        _revertSnapshot = vm.snapshotState();
        smaStorageImpl = address(new SemiModularAccountStorageOnly(entryPoint));
        (owner2, owner2Key) = makeAddrAndKey("owner2");
        transferAmount = 0.1 ether;
    }

    // This test should only run with an MA, using withSMATest would result in the SMABytecode not being
    // initialized and the initialize call not reverting.
    function test_fail_upgradeToAndCall_initializedMaToSmaStorage() external {
        // The call should revert with invalid initialization.
        vm.expectRevert(AccountStorageInitializable.InvalidInitialization.selector);

        // Attempt an upgrade and re-initialization.
        vm.prank(address(entryPoint));
        account1.upgradeToAndCall(smaStorageImpl, abi.encodeCall(SemiModularAccountStorageOnly.initialize, owner2));
    }

    // Positives

    function test_upgradeToAndCall_MaToSmaStorage() external {
        // We call `updateFallbackSigner()` to upgrade from an MA to an SMA-S, because we are already initialized.
        vm.prank(address(entryPoint));
        account1.upgradeToAndCall(
            smaStorageImpl, abi.encodeCall(SemiModularAccountBase.updateFallbackSignerData, (owner2, false))
        );

        // The previous owner1 validation is still installed, so this should not revert.
        _userOpTransfer(address(account1), owner1Key, "", 0, false);

        vm.prank(owner2);
        account1.uninstallValidation(_signerValidation, "", new bytes[](0));

        // Build expected revert data for a UO with the original signer.
        bytes memory expectedRevertdata = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(
                ModularAccountBase.ValidationFunctionMissing.selector, ModularAccountBase.execute.selector
            )
        );

        // Execute a UO with the original signer and the now uninstalled validation, anticipating a revert.
        _userOpTransfer(address(account1), owner1Key, expectedRevertdata, transferAmount, false);

        expectedRevertdata = abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error");
        // Execute a UO with the original signer and the fallback validation, anticipating a revert.
        _userOpTransfer(address(account1), owner1Key, expectedRevertdata, transferAmount, true);

        // Execute a UO with the new signer, which is the fallback signer.
        _userOpTransfer(address(account1), owner2Key, "", transferAmount, true);
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
            smaStorageImpl, abi.encodeCall(SemiModularAccountStorageOnly.initialize, owner2)
        );

        // Build expected revert data for a UO with the original signer.
        bytes memory expectedRevertdata =
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error");

        // Attempt to execute a UO with the original signer, anticipating a revert.
        _userOpTransfer(address(newAccount), owner1Key, expectedRevertdata, 0, true);

        // Attempt to successfully execute a UO with the new signer, which is the fallback signer.
        _userOpTransfer(newAccount, owner2Key, "", 0, true);
    }

    // Internal helpers

    function _userOpTransfer(
        address account,
        uint256 ownerKey,
        bytes memory expectedRevertData,
        uint256 initialBalance,
        bool withFallbackValidation
    ) internal {
        // Pre-fund the account.
        deal(account, 1 ether);

        // Generate a target and ensure it has no balance.
        address target = CODELESS_ADDRESS;
        assertEq(target.balance, initialBalance, "Target has balance when it shouldn't");

        // Encode a transfer to the target.
        bytes memory encodedCall = abi.encodeCall(ModularAccountBase.execute, (target, transferAmount, ""));

        // Run a UO with the encoded call.
        if (withFallbackValidation) {
            _runUserOpWithFallbackValidation(account, ownerKey, encodedCall, expectedRevertData);
        } else {
            _runUserOpFrom(account, ownerKey, encodedCall, expectedRevertData);
        }

        // If the call was not supposed to revert, ensure the transfer succeeded.
        if (expectedRevertData.length == 0) {
            assertEq(target.balance, transferAmount + initialBalance, "Target missing balance from UO transfer");
        }
    }

    function _runUserOpWithFallbackValidation(
        address account,
        uint256 ownerKey,
        bytes memory encodedCall,
        bytes memory expectedRevertData
    ) internal {
        uint256 nonce = entryPoint.getNonce(account, 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: nonce,
            initCode: hex"",
            callData: encodedCall,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash.toEthSignedMessageHash());

        userOp.signature =
            _encodeSignature(FALLBACK_VALIDATION, GLOBAL_VALIDATION, abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        if (expectedRevertData.length > 0) {
            vm.expectRevert(expectedRevertData);
        }
        entryPoint.handleOps(userOps, beneficiary);
    }
}
