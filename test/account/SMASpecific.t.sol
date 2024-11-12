// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";

import {MockCountModule} from "../mocks/modules/MockCountModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {CODELESS_ADDRESS} from "../utils/TestConstants.sol";

contract SMASpecificTest is AccountTestBase {
    using ModuleEntityLib for ModuleEntity;
    using MessageHashUtils for bytes32;

    address public mockCountModule;
    uint256 public transferAmount;

    function setUp() public override {
        // smaStorageImpl = address(new SemiModularAccountStorageOnly(entryPoint));
        // (owner2, owner2Key) = makeAddrAndKey("owner2");
        _switchToSMA();
        transferAmount = 0.1 ether;
        mockCountModule = address(new MockCountModule());
    }

    function testFuzz_fallbackValidation_hooksFlow(
        uint32 validationHookCount,
        uint32 valAssocExecHookCount,
        bool[254] calldata execHooksHavePost
    ) public {
        validationHookCount = uint32(bound(validationHookCount, 0, 254));
        valAssocExecHookCount = uint32(bound(valAssocExecHookCount, 0, 254));

        _installPreValidationHooks(validationHookCount);

        uint256 totalPostHooks = _installValidationAssociatedExecHooks(valAssocExecHookCount, execHooksHavePost);

        _runtimeTransfer(0);
        _userOpTransfer(transferAmount);

        // Post run validation, ensuring hooks have run
        assertEq(MockCountModule(mockCountModule).runtimeValidationHookRunCount(), validationHookCount);
        assertEq(MockCountModule(mockCountModule).userOpValidationHookRunCount(), validationHookCount);
        assertEq(MockCountModule(mockCountModule).preExecutionHookRunCount(), valAssocExecHookCount * 2);
        assertEq(MockCountModule(mockCountModule).postExecutionHookRunCount(), totalPostHooks * 2);

        bytes[] memory hookUninstallDatas = new bytes[](validationHookCount + valAssocExecHookCount);
        if (hookUninstallDatas.length > 0) {
            hookUninstallDatas[0] = "a"; // mock nonzero length data to call `onUninstall()` once.
        }
        vm.prank(address(entryPoint));
        account1.uninstallValidation(_signerValidation, "", hookUninstallDatas);

        // Ensure the fallback validation works after uninstalling the hooks.
        _runtimeTransfer(transferAmount * 2);
        _userOpTransfer(transferAmount * 3);

        // After uninstallation, the hooks should not have run at all.
        assertEq(MockCountModule(mockCountModule).runtimeValidationHookRunCount(), 0);
        assertEq(MockCountModule(mockCountModule).userOpValidationHookRunCount(), 0);
        assertEq(MockCountModule(mockCountModule).preExecutionHookRunCount(), 0);
        assertEq(MockCountModule(mockCountModule).postExecutionHookRunCount(), 0);
    }

    // Internal helpers

    function _runtimeTransfer(uint256 initialBalance) internal {
        deal(address(account1), 1 ether);
        address target = CODELESS_ADDRESS;
        vm.prank(owner1);
        account1.executeWithRuntimeValidation(
            abi.encodeCall(ModularAccountBase.execute, (target, transferAmount, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
        assertEq(target.balance, transferAmount + initialBalance, "Target missing balance from runtime transfer");
    }

    function _userOpTransfer(uint256 initialBalance) internal {
        // Pre-fund the account, arbitrarily high amount to cover arbitrarily high gas.
        deal(address(account1), type(uint128).max);

        // Generate a target and ensure it has no balance.
        address target = CODELESS_ADDRESS;
        assertEq(target.balance, initialBalance, "Target has balance when it shouldn't");

        // Encode a transfer to the target.
        // bytes memory encodedCall = abi.encodeCall(ModularAccountBase.execute, (target, transferAmount, ""));
        bytes memory encodedCall = abi.encodePacked(
            ModularAccountBase.executeUserOp.selector,
            abi.encodeCall(ModularAccountBase.execute, (target, transferAmount, ""))
        );

        // Run a UO with the encoded call.
        _runUserOpWithFallbackValidation(encodedCall);

        assertEq(target.balance, transferAmount + initialBalance, "Target missing balance from UO transfer");
    }

    function _runUserOpWithFallbackValidation(bytes memory encodedCall) internal {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: _encodeNextNonce(address(account1), FALLBACK_VALIDATION, true),
            initCode: hex"",
            callData: encodedCall,
            accountGasLimits: _encodeGas(type(uint24).max, type(uint24).max),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        userOp.signature = _encodeSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function _installPreValidationHooks(uint32 count) internal {
        bytes[] memory hooks = new bytes[](count);

        for (uint32 i = 0; i < count; ++i) {
            hooks[i] = abi.encodePacked(HookConfigLib.packValidationHook(mockCountModule, i), "");
        }

        vm.prank(address(entryPoint));

        account1.installValidation(
            ValidationConfigLib.pack(_signerValidation, true, true, true), new bytes4[](0), "", hooks
        );
    }

    function _installValidationAssociatedExecHooks(uint32 count, bool[254] memory execHooksHavePost)
        internal
        returns (uint256)
    {
        bytes[] memory hooks = new bytes[](count);
        uint256 totalPostHookCount = 0;

        for (uint32 i = 0; i < count; ++i) {
            bool hasPost = execHooksHavePost[i];
            if (hasPost) {
                ++totalPostHookCount;
            }
            hooks[i] =
                abi.encodePacked(HookConfigLib.packExecHook(mockCountModule, i, true, execHooksHavePost[i]), "");
        }

        vm.prank(address(entryPoint));

        account1.installValidation(
            ValidationConfigLib.pack(_signerValidation, true, true, true), new bytes4[](0), "", hooks
        );
        return totalPostHookCount;
    }
}
