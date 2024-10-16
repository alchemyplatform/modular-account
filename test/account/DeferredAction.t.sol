// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {
    ExecutionManifest,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";

import {MockERC20} from "../mocks/MockERC20.sol";
import {MockTokenPaymaster} from "../mocks/MockTokenPaymaster.sol";
import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract DeferredActionTest is AccountTestBase {
    // Need a non-deployed account.
    ModularAccount public account2;

    MockERC20 public erc20;

    MockTokenPaymaster public paymaster;

    MockModule public mockModule;

    function setUp() public override {
        _revertSnapshot = vm.snapshot();
        erc20 = new MockERC20();
        paymaster = new MockTokenPaymaster(erc20, entryPoint);

        ExecutionManifest memory m; // Empty manifest
        mockModule = new MockModule(m);

        // prefund
        vm.deal(address(paymaster), 100 ether);
        paymaster.deposit();
    }

    function test_deferredAction_approveERC20InInitcode() public withSMATest {
        uint256 salt = 1;
        bytes memory initCode;

        if (_isSMATest) {
            account2 = ModularAccount(payable(factory.getAddressSemiModular(owner1, salt)));
            initCode = abi.encodePacked(
                address(factory), abi.encodeCall(factory.createSemiModularAccount, (owner1, salt))
            );
        } else {
            account2 = ModularAccount(payable(factory.getAddress(owner1, salt, TEST_DEFAULT_VALIDATION_ENTITY_ID)));
            initCode = abi.encodePacked(
                address(factory),
                abi.encodeCall(factory.createAccount, (owner1, salt, TEST_DEFAULT_VALIDATION_ENTITY_ID))
            );
        }

        erc20.mint(address(account2), 100 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: initCode,
            callData: abi.encodeCall(IModularAccount.execute, (address(0), 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: abi.encodePacked(
                address(paymaster), _encodeGas(VERIFICATION_GAS_LIMIT, VERIFICATION_GAS_LIMIT)
            ),
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 0;

        bytes memory deferredAction = abi.encodeCall(
            IModularAccount.execute,
            (address(erc20), 0 wei, abi.encodeCall(erc20.approve, (address(paymaster), 10 ether)))
        );

        userOp.signature = _buildFullDeferredInstallSig(
            deferredInstallNonce,
            deferredInstallDeadline,
            deferredAction,
            // Use the same validation for the deferred action and the user op
            ValidationConfigLib.pack(_signerValidation, true, false, false),
            account2,
            owner1Key,
            uoSig
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.prank(beneficiary);
        entryPoint.handleOps(userOps, beneficiary);

        assertEq(10 ether, erc20.balanceOf(address(paymaster)));
    }

    // Install a new execution function that the validation does not have the privilege to call.
    // Assert that user op validation reverts if the deferred action tries to call it.
    function test_deferredAction_noPrivilegeEscalation() public {
        bytes4 newFunctionSelector = bytes4(0xabcdabcd);

        ExecutionManifest memory m;
        m.executionFunctions = new ManifestExecutionFunction[](1);
        m.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: newFunctionSelector,
            skipRuntimeValidation: false,
            allowGlobalValidation: false
        });

        vm.prank(address(account1));
        account1.installExecution(address(mockModule), m, "");

        // Attempt to call it via a deferred action in a user op
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(IModularAccount.execute, (address(0), 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        bytes memory uoSig = _packFinalSignature(abi.encodePacked(EOA_TYPE_SIGNATURE, r, s, v));

        uint256 deferredInstallNonce = 0;
        uint48 deferredInstallDeadline = 0;

        bytes memory deferredAction = abi.encodeWithSelector(newFunctionSelector);

        userOp.signature = _buildFullDeferredInstallSig(
            deferredInstallNonce,
            deferredInstallDeadline,
            deferredAction,
            // Use the same validation for the deferred action and the user op
            ValidationConfigLib.pack(_signerValidation, true, false, false),
            account1,
            owner1Key,
            uoSig
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.prank(beneficiary);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(ModularAccountBase.ValidationFunctionMissing.selector, bytes4(0xabcdabcd))
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }
}
