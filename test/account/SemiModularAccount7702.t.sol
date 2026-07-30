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

import {DIRECT_CALL_VALIDATION_ENTITY_ID} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModularAccount, ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {HookConfig, HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {SemiModularAccount7702} from "../../src/account/SemiModularAccount7702.sol";
import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";
import {SignatureType} from "../../src/helpers/SignatureType.sol";
import {ValidationLocator, ValidationLocatorLib} from "../../src/libraries/ValidationLocatorLib.sol";

import {MockAccessControlHookModule} from "../mocks/modules/MockAccessControlHookModule.sol";
import {MockCountModule} from "../mocks/modules/MockCountModule.sol";
import {MockModule} from "../mocks/modules/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

/// @dev Mirrors the signature check in Permit2's `SignatureVerification` library, which is immutable and
/// therefore cannot be updated to understand delegated EOAs. Because a delegated account has code, the ERC-1271
/// branch is the only one it can reach.
contract MockPermit2SignatureVerification {
    error InvalidContractSignature();

    function verify(bytes32 hash, bytes calldata signature, address claimedSigner) external view {
        if (claimedSigner.code.length == 0) {
            revert("claimedSigner has no code; test setup is wrong");
        }

        if (IERC1271(claimedSigner).isValidSignature(hash, signature) != bytes4(0x1626ba7e)) {
            revert InvalidContractSignature();
        }
    }
}

contract MockERC1271ContractSigner is IERC1271 {
    address internal immutable _SIGNER;

    constructor(address signer) {
        _SIGNER = signer;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        return err == ECDSA.RecoverError.NoError && recovered == _SIGNER ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

/// @dev Tests for `SemiModularAccount7702`, focused on ERC-1271 validation of bare ECDSA signatures produced by
/// the delegating EOA.
contract SemiModularAccount7702Test is AccountTestBase {
    using MessageHashUtils for bytes32;

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    // secp256k1 group order, used to construct malleable signatures.
    uint256 internal constant _SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    address internal _eoa;
    uint256 internal _eoaKey;
    SemiModularAccount7702 internal _account;

    MockPermit2SignatureVerification internal _permit2;

    function setUp() public override {
        (_eoa, _eoaKey) = makeAddrAndKey("sma7702Eoa");

        // Simulate an EIP-7702 delegation by placing the implementation's runtime code at the EOA's address.
        // `address(this)` inside the account then resolves to the EOA, which is what makes the EOA the account's
        // default fallback signer.
        SemiModularAccount7702 implementation = _deploySemiModularAccount7702(entryPoint, executionInstallDelegate);
        vm.etch(_eoa, address(implementation).code);

        _account = SemiModularAccount7702(payable(_eoa));
        vm.deal(_eoa, 100 ether);

        _permit2 = new MockPermit2SignatureVerification();

        // Point the shared helpers in `AccountTestBase` at the delegated account.
        account1 = ModularAccount(payable(_eoa));
        _signerValidation = FALLBACK_VALIDATION;
        _isSMATest = true;
    }

    function test_accountId() public view {
        assertEq(_account.accountId(), "alchemy.sma-7702.1.1.0");
    }

    // Bare ECDSA signatures from the delegating EOA.

    function test_isValidSignature_bareSignature() public view {
        bytes32 hash = keccak256("hello world");
        bytes memory signature = _signBare(hash);

        assertEq(signature.length, 65);
        assertEq(_account.isValidSignature(hash, signature), _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_bareSignature_compact() public view {
        bytes32 hash = keccak256("hello world");
        bytes memory signature = _signBareCompact(hash);

        assertEq(signature.length, 64);
        assertEq(_account.isValidSignature(hash, signature), _1271_MAGIC_VALUE);
    }

    function testFuzz_isValidSignature_bareSignature(bytes32 hash) public view {
        assertEq(_account.isValidSignature(hash, _signBare(hash)), _1271_MAGIC_VALUE);
        assertEq(_account.isValidSignature(hash, _signBareCompact(hash)), _1271_MAGIC_VALUE);
    }

    /// @dev The reported failure: Permit2 sees that the delegated account has code, routes the check through
    /// ERC-1271, and hands over the bare signature the external wallet produced.
    function test_isValidSignature_permit2Compatibility() public view {
        bytes32 hash = keccak256("permit2 digest");

        _permit2.verify(hash, _signBare(hash), _eoa);
        _permit2.verify(hash, _signBareCompact(hash), _eoa);
    }

    /// @dev The same check as reached through OpenZeppelin's `SignatureChecker`, which many contracts use in
    /// place of hand-rolling the code-length branch.
    function test_isValidSignature_signatureCheckerCompatibility() public view {
        bytes32 hash = keccak256("hello world");

        assertTrue(SignatureChecker.isValidERC1271SignatureNow(_eoa, hash, _signBare(hash)));
        assertTrue(SignatureChecker.isValidERC1271SignatureNow(_eoa, hash, _signBareCompact(hash)));
    }

    // For this compatibility path, rejected bare signatures return the failure value rather than reverting. Gas
    // estimation in dApps depends on that behavior: the original report surfaced as an unrelated estimation
    // failure because validation reverted while decoding the signature.

    function test_isValidSignature_bareSignature_wrongSigner() public view {
        bytes32 hash = keccak256("hello world");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, hash);

        assertEq(_account.isValidSignature(hash, abi.encodePacked(r, s, v)), _1271_INVALID);
    }

    function test_isValidSignature_bareSignature_wrongHash() public view {
        bytes memory signature = _signBare(keccak256("hello world"));

        assertEq(_account.isValidSignature(keccak256("goodbye world"), signature), _1271_INVALID);
    }

    function test_isValidSignature_bareSignature_zeroed() public view {
        bytes32 hash = keccak256("hello world");

        assertEq(_account.isValidSignature(hash, new bytes(65)), _1271_INVALID);
        assertEq(_account.isValidSignature(hash, new bytes(64)), _1271_INVALID);
    }

    /// @dev Before bare signatures were handled, the leading byte was decoded as validation options. Here it has
    /// the direct-call bit set, which is what previously routed validation to an uninstalled validation function
    /// and reverted.
    function test_isValidSignature_bareSignature_directCallBitSet() public view {
        bytes32 hash = keccak256("hello world");

        bytes memory signature = _signBare(hash);
        signature[0] = 0xe5;

        assertEq(_account.isValidSignature(hash, signature), _1271_INVALID);
    }

    function test_isValidSignature_bareSignature_malleable() public view {
        bytes32 hash = keccak256("hello world");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_eoaKey, hash);

        // Flip the signature to its malleable counterpart, which recovers the same signer but must be rejected.
        bytes32 flippedS = bytes32(_SECP256K1_N - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;

        assertEq(_account.isValidSignature(hash, abi.encodePacked(r, flippedS, flippedV)), _1271_INVALID);
    }

    function test_isValidSignature_bareSignature_invalidV() public view {
        bytes32 hash = keccak256("hello world");
        (, bytes32 r, bytes32 s) = vm.sign(_eoaKey, hash);

        assertEq(_account.isValidSignature(hash, abi.encodePacked(r, s, uint8(0))), _1271_INVALID);
        assertEq(_account.isValidSignature(hash, abi.encodePacked(r, s, uint8(1))), _1271_INVALID);
        assertEq(_account.isValidSignature(hash, abi.encodePacked(r, s, uint8(26))), _1271_INVALID);
        assertEq(_account.isValidSignature(hash, abi.encodePacked(r, s, uint8(29))), _1271_INVALID);
        assertEq(_account.isValidSignature(hash, abi.encodePacked(r, s, type(uint8).max)), _1271_INVALID);
    }

    function test_isValidSignature_bareSignature_compactHighS() public view {
        bytes32 hash = keccak256("hello world");
        (, bytes32 r,) = vm.sign(_eoaKey, hash);
        uint256 highS = (_SECP256K1_N / 2) + 1;

        assertEq(_account.isValidSignature(hash, abi.encodePacked(r, bytes32(highS))), _1271_INVALID);
        assertEq(
            _account.isValidSignature(hash, abi.encodePacked(r, bytes32(highS | (uint256(1) << 255)))),
            _1271_INVALID
        );
    }

    function testFuzz_isValidSignature_bareSignature_arbitraryDoesNotRevert(
        bytes32 hash,
        bytes32 r,
        bytes32 sOrVs,
        uint8 v
    ) public view {
        bytes4 compactResult = _account.isValidSignature(hash, abi.encodePacked(r, sOrVs));
        bytes4 standardResult = _account.isValidSignature(hash, abi.encodePacked(r, sOrVs, v));

        (address compactRecovered, ECDSA.RecoverError compactError,) = ECDSA.tryRecover(hash, r, sOrVs);
        (address standardRecovered, ECDSA.RecoverError standardError,) = ECDSA.tryRecover(hash, v, r, sOrVs);

        assertEq(
            compactResult,
            compactError == ECDSA.RecoverError.NoError && compactRecovered == _eoa
                ? _1271_MAGIC_VALUE
                : _1271_INVALID
        );
        assertEq(
            standardResult,
            standardError == ECDSA.RecoverError.NoError && standardRecovered == _eoa
                ? _1271_MAGIC_VALUE
                : _1271_INVALID
        );
    }

    /// @dev The bare path checks the digest exactly as given. A signature over the account's replay-safe
    /// wrapping of that digest must not validate against the unwrapped digest.
    function test_isValidSignature_bareSignature_overReplaySafeHash() public view {
        bytes32 hash = keccak256("hello world");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_eoaKey, _getSMAReplaySafeHash(_eoa, hash));

        assertEq(_account.isValidSignature(hash, abi.encodePacked(r, s, v)), _1271_INVALID);
    }

    // Configuration gates. The EOA is honored only while it is still the account's active fallback signer, so
    // the bare path accepts a subset of the signers that fallback validation accepts.

    function test_isValidSignature_bareSignature_fallbackSignerDisabled() public {
        vm.prank(_eoa);
        _account.updateFallbackSignerData(address(0), true);

        bytes32 hash = keccak256("hello world");
        _assertDoesNotValidate(address(_account), hash, _signBare(hash));
        _assertDoesNotValidate(address(_account), hash, _signBareCompact(hash));

        bytes memory standardSignature =
            _encode1271Signature(FALLBACK_VALIDATION, _signRawHash(vm, _eoaKey, _getSMAReplaySafeHash(_eoa, hash)));
        _assertDoesNotValidate(address(_account), hash, standardSignature);
    }

    function test_isValidSignature_bareSignature_fallbackSignerRotated() public {
        vm.prank(_eoa);
        _account.updateFallbackSignerData(owner1, false);

        bytes32 hash = keccak256("hello world");
        _assertDoesNotValidate(address(_account), hash, _signBare(hash));
        _assertDoesNotValidate(address(_account), hash, _signBareCompact(hash));

        // The rotated-to signer still validates through the standard encoding.
        bytes memory signature = _encode1271Signature(
            FALLBACK_VALIDATION, _signRawHash(vm, owner1Key, _getSMAReplaySafeHash(_eoa, hash))
        );
        assertEq(_account.isValidSignature(hash, signature), _1271_MAGIC_VALUE);
    }

    /// @dev The zero storage value resolves to the delegated EOA, while storing the EOA explicitly has the same
    /// effect. Raw mode requires every activation predicate; none of signer state, the disabled flag, or the
    /// fallback validation hook state can override another.
    function test_isValidSignature_bareSignature_fallbackStateMatrix() public {
        uint256 cleanState = vm.snapshotState();
        bytes32 hash = keccak256("fallback state matrix");
        for (uint8 storedSignerState = 0; storedSignerState < 3; ++storedSignerState) {
            for (uint8 disabledState = 0; disabledState < 2; ++disabledState) {
                for (uint8 hookState = 0; hookState < 2; ++hookState) {
                    bool validationHookInstalled = hookState == 1;
                    if (validationHookInstalled) {
                        _installNoOpFallbackValidationHook(new MockCountModule());
                    }

                    address storedSigner =
                        storedSignerState == 0 ? address(0) : storedSignerState == 1 ? _eoa : owner1;
                    bool fallbackDisabled = disabledState == 1;
                    vm.prank(_eoa);
                    _account.updateFallbackSignerData(storedSigner, fallbackDisabled);

                    bool rawModeExpected = !fallbackDisabled
                        && (storedSigner == address(0) || storedSigner == _eoa) && !validationHookInstalled;
                    if (rawModeExpected) {
                        assertEq(_account.isValidSignature(hash, _signBare(hash)), _1271_MAGIC_VALUE);
                        assertEq(_account.isValidSignature(hash, _signBareCompact(hash)), _1271_MAGIC_VALUE);
                    } else {
                        _assertDoesNotValidate(address(_account), hash, _signBare(hash));
                        _assertDoesNotValidate(address(_account), hash, _signBareCompact(hash));
                    }

                    assertTrue(vm.revertToState(cleanState));
                }
            }
        }
    }

    /// @dev A bare signature cannot carry the per-hook data used by the standard encoding. It must not bypass a
    /// fallback validation hook that imposes an additional signature policy.
    function test_isValidSignature_bareSignature_fallbackValidationHookInstalled() public {
        MockAccessControlHookModule hookModule = new MockAccessControlHookModule();
        HookConfig hookConfig =
            HookConfigLib.packValidationHook({_module: address(hookModule), _entityId: uint32(1)});
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(hookConfig, abi.encode(uint32(1), address(0)));

        vm.prank(_eoa);
        _account.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: FALLBACK_VALIDATION,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hooks
        );

        bytes memory hookProof = "hook proof";
        bytes32 hash = keccak256(hookProof);
        _assertDoesNotValidate(address(_account), hash, _signBare(hash));
        _assertDoesNotValidate(address(_account), hash, _signBareCompact(hash));

        PreValidationHookData[] memory hookData = new PreValidationHookData[](1);
        hookData[0] = PreValidationHookData({index: 0, validationData: hookProof});
        bytes memory standardSignature = _encode1271Signature(
            FALLBACK_VALIDATION, hookData, _signRawHash(vm, _eoaKey, _getSMAReplaySafeHash(_eoa, hash))
        );
        assertEq(_account.isValidSignature(hash, standardSignature), _1271_MAGIC_VALUE);
    }

    /// @dev Only pre-validation hooks attached to the reserved fallback validation are raw-mode opt-outs.
    /// Validation flags, an execution-only hook, and validation hooks stored under the fallback direct-call key
    /// or another validation do not affect raw ERC-1271. Removing the fallback configuration clears its hook types
    /// but reactivates raw mode only after the other predicates are also restored; reinstalling the validation
    /// hook opts out again.
    function test_isValidSignature_bareSignature_fallbackHookTypeAndOptOutLifecycle() public {
        MockCountModule executionHookModule = new MockCountModule();
        HookConfig executionHookConfig = HookConfigLib.packExecHook({
            _module: address(executionHookModule),
            _entityId: uint32(1),
            _hasPre: true,
            _hasPost: false
        });
        bytes[] memory executionHooks = new bytes[](1);
        executionHooks[0] = abi.encodePacked(executionHookConfig, hex"00");

        vm.prank(_eoa);
        _account.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: FALLBACK_VALIDATION,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            executionHooks
        );

        bytes32 hash = keccak256("hello world");
        assertEq(_account.isValidSignature(hash, _signBare(hash)), _1271_MAGIC_VALUE);
        assertEq(_account.isValidSignature(hash, _signBareCompact(hash)), _1271_MAGIC_VALUE);

        {
            MockCountModule directCallHookModule = new MockCountModule();
            HookConfig directCallHookConfig =
                HookConfigLib.packValidationHook({_module: address(directCallHookModule), _entityId: uint32(1)});
            bytes[] memory directCallHooks = new bytes[](1);
            directCallHooks[0] = abi.encodePacked(directCallHookConfig, hex"00");
            ModuleEntity fallbackDirectCallValidation =
                ModuleEntityLib.pack(_eoa, DIRECT_CALL_VALIDATION_ENTITY_ID);

            vm.prank(_eoa);
            _account.installValidation(
                ValidationConfigLib.pack({
                    _validationFunction: fallbackDirectCallValidation,
                    _isGlobal: false,
                    _isSignatureValidation: false,
                    _isUserOpValidation: false
                }),
                new bytes4[](0),
                "",
                directCallHooks
            );
        }
        assertEq(_account.isValidSignature(hash, _signBare(hash)), _1271_MAGIC_VALUE);
        assertEq(_account.isValidSignature(hash, _signBareCompact(hash)), _1271_MAGIC_VALUE);

        {
            ExecutionManifest memory manifest;
            MockModule unrelatedValidationModule = new MockModule(manifest);
            MockCountModule unrelatedHookModule = new MockCountModule();
            HookConfig unrelatedHookConfig =
                HookConfigLib.packValidationHook({_module: address(unrelatedHookModule), _entityId: uint32(1)});
            bytes[] memory unrelatedHooks = new bytes[](1);
            unrelatedHooks[0] = abi.encodePacked(unrelatedHookConfig, hex"00");

            vm.prank(_eoa);
            _account.installValidation(
                ValidationConfigLib.pack({
                    _validationFunction: ModuleEntityLib.pack(address(unrelatedValidationModule), uint32(2)),
                    _isGlobal: true,
                    _isSignatureValidation: true,
                    _isUserOpValidation: true
                }),
                new bytes4[](0),
                "",
                unrelatedHooks
            );
        }
        assertEq(_account.isValidSignature(hash, _signBare(hash)), _1271_MAGIC_VALUE);
        assertEq(_account.isValidSignature(hash, _signBareCompact(hash)), _1271_MAGIC_VALUE);

        MockCountModule validationHookModule = new MockCountModule();
        _installNoOpFallbackValidationHook(validationHookModule);
        _assertDoesNotValidate(address(_account), hash, _signBare(hash));
        _assertDoesNotValidate(address(_account), hash, _signBareCompact(hash));

        bytes memory standardSignature =
            _encode1271Signature(FALLBACK_VALIDATION, _signRawHash(vm, _eoaKey, _getSMAReplaySafeHash(_eoa, hash)));
        assertEq(_account.isValidSignature(hash, standardSignature), _1271_MAGIC_VALUE);

        vm.prank(_eoa);
        _account.updateFallbackSignerData(address(0), true);
        _assertDoesNotValidate(address(_account), hash, _signBare(hash));

        vm.prank(_eoa);
        _account.updateFallbackSignerData(address(0), false);
        _assertDoesNotValidate(address(_account), hash, _signBare(hash));

        vm.prank(_eoa);
        _account.updateFallbackSignerData(address(0), true);

        bytes[] memory hookUninstallData = new bytes[](2);
        hookUninstallData[0] = hex"00";
        hookUninstallData[1] = hex"00";
        vm.prank(_eoa);
        _account.uninstallValidation(FALLBACK_VALIDATION, "", hookUninstallData);
        _assertDoesNotValidate(address(_account), hash, _signBare(hash));

        vm.prank(_eoa);
        _account.updateFallbackSignerData(address(0), false);
        assertEq(_account.isValidSignature(hash, _signBare(hash)), _1271_MAGIC_VALUE);
        assertEq(_account.isValidSignature(hash, _signBareCompact(hash)), _1271_MAGIC_VALUE);

        _installNoOpFallbackValidationHook(validationHookModule);
        _assertDoesNotValidate(address(_account), hash, _signBare(hash));
        _assertDoesNotValidate(address(_account), hash, _signBareCompact(hash));
    }

    // The standard signature encoding is unchanged.

    function test_isValidSignature_standardEncoding() public view {
        bytes32 hash = keccak256("hello world");
        bytes memory signature =
            _encode1271Signature(FALLBACK_VALIDATION, _signRawHash(vm, _eoaKey, _getSMAReplaySafeHash(_eoa, hash)));

        // The built-in EOA signature is 66 bytes, so with the standard encoding's 6 bytes of overhead it does not
        // collide with the two lengths reserved for bare signatures.
        assertEq(signature.length, 72);
        assertEq(_account.isValidSignature(hash, signature), _1271_MAGIC_VALUE);
    }

    function test_isValidSignature_standardEncoding_wrongSigner() public view {
        bytes32 hash = keccak256("hello world");
        bytes memory signature = _encode1271Signature(
            FALLBACK_VALIDATION, _signRawHash(vm, owner1Key, _getSMAReplaySafeHash(_eoa, hash))
        );

        assertEq(_account.isValidSignature(hash, signature), _1271_INVALID);
    }

    /// @dev Module signatures are variable-length, so a standard signature can total 64 or 65 bytes. Those
    /// lengths are reserved exactly while raw mode is active and route to the installed module under each state
    /// that deactivates raw mode.
    function test_isValidSignature_standardEncoding_reservedLengthsFollowRawModeState() public {
        ExecutionManifest memory manifest;
        MockModule validationModule = new MockModule(manifest);
        uint32 entityId = 1;
        ModuleEntity validationFunction = ModuleEntityLib.pack(address(validationModule), entityId);

        vm.prank(_eoa);
        _account.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: validationFunction,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: false
            }),
            new bytes4[](0),
            "",
            new bytes[](0)
        );

        vm.mockCall(
            address(validationModule),
            abi.encodeWithSelector(IValidationModule.validateSignature.selector),
            abi.encode(_1271_MAGIC_VALUE)
        );

        bytes32 hash = keccak256("hello world");
        bytes memory signature64 = _encode1271Signature(validationFunction, new bytes(58));
        bytes memory signature65 = _encode1271Signature(validationFunction, new bytes(59));
        assertEq(signature64.length, 64);
        assertEq(signature65.length, 65);
        assertEq(_account.isValidSignature(hash, signature64), _1271_INVALID);
        assertEq(_account.isValidSignature(hash, signature65), _1271_INVALID);

        MockCountModule hookModule = new MockCountModule();
        _installNoOpFallbackValidationHook(hookModule);
        assertEq(_account.isValidSignature(hash, signature64), _1271_MAGIC_VALUE);
        assertEq(_account.isValidSignature(hash, signature65), _1271_MAGIC_VALUE);

        bytes[] memory hookUninstallData = new bytes[](1);
        hookUninstallData[0] = hex"00";
        vm.prank(_eoa);
        _account.uninstallValidation(FALLBACK_VALIDATION, "", hookUninstallData);
        assertEq(_account.isValidSignature(hash, signature64), _1271_INVALID);
        assertEq(_account.isValidSignature(hash, signature65), _1271_INVALID);

        vm.prank(_eoa);
        _account.updateFallbackSignerData(address(0), true);
        assertEq(_account.isValidSignature(hash, signature64), _1271_MAGIC_VALUE);
        assertEq(_account.isValidSignature(hash, signature65), _1271_MAGIC_VALUE);

        vm.prank(_eoa);
        _account.updateFallbackSignerData(address(0), false);
        assertEq(_account.isValidSignature(hash, signature64), _1271_INVALID);
        assertEq(_account.isValidSignature(hash, signature65), _1271_INVALID);

        vm.prank(_eoa);
        _account.updateFallbackSignerData(owner1, false);
        assertEq(_account.isValidSignature(hash, signature64), _1271_MAGIC_VALUE);
        assertEq(_account.isValidSignature(hash, signature65), _1271_MAGIC_VALUE);
    }

    /// @dev Lengths outside the reserved pair are routed to the standard encoding, which a bare ECDSA signature
    /// cannot satisfy.
    function testFuzz_isValidSignature_bareSignature_otherLengths(uint8 extraBytes) public view {
        extraBytes = uint8(bound(extraBytes, 1, 32));

        bytes32 hash = keccak256("hello world");
        bytes memory signature = abi.encodePacked(_signBare(hash), new bytes(extraBytes));

        _assertDoesNotValidate(_eoa, hash, signature);
    }

    // Scope of the change.

    /// @dev Only the EIP-7702 variant may treat `address(this)` as a key holder. In the other semi-modular
    /// variants the fallback signer is an independent key that may also sign for other accounts, and replay-safe
    /// hashing is what binds a signature to a single account.
    function test_isValidSignature_bytecodeSMA_rejectsBareSignature() public {
        address sma = address(factory.createSemiModularAccount(owner1, 0));

        bytes32 hash = keccak256("hello world");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, hash);

        _assertDoesNotValidate(sma, hash, abi.encodePacked(r, s, v));
    }

    /// @dev User operation validation does not reinterpret a directly supplied 64- or 65-byte signature. It still
    /// requires the standard segmented encoding and signature type.
    function test_validateUserOp_rejectsBareSignature() public {
        PackedUserOperation memory userOp = _buildUserOp();

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_eoaKey, userOpHash.toEthSignedMessageHash());

        _assertUserOpSignatureRejected(userOp, userOpHash, abi.encodePacked(r, s, v));
        _assertUserOpSignatureRejected(
            userOp, userOpHash, abi.encodePacked(r, bytes32(uint256(s) | (uint256(v - 27) << 255)))
        );
    }

    /// @dev UserOperation validation does not parse a bare outer signature. Its fallback `CONTRACT_OWNER` type
    /// must also reject the account itself as owner to prevent recursive ERC-1271 validation.
    function test_userOp_contractOwnerEncodingRejectedWhenFallbackSignerIsSelf() public {
        address recipient = makeAddr("contractOwnerUserOpRecipient");

        for (uint256 i = 0; i < 2; ++i) {
            PackedUserOperation memory userOp = _buildUserOp();
            userOp.callData = abi.encodeCall(IModularAccount.execute, (recipient, 1 wei, ""));

            bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
            bytes32 digest = userOpHash.toEthSignedMessageHash();
            bytes memory bareSignature = i == 0 ? _signBare(digest) : _signBareCompact(digest);
            bytes memory wrappedBareSignature =
                _encodeSignature(abi.encodePacked(uint8(SignatureType.CONTRACT_OWNER), bareSignature));

            userOp.signature = wrappedBareSignature;
            PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
            userOps[0] = userOp;

            vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
            entryPoint.handleOps(userOps, beneficiary);
        }

        assertEq(recipient.balance, 0);
    }

    /// @dev Deferred actions retain their existing envelope and account-scoped EIP-712 digest, but cannot use
    /// `CONTRACT_OWNER` to recurse through the account's own ERC-1271 entry point.
    function test_deferredAction_contractOwnerEncodingRejectedWhenFallbackSignerIsSelf() public {
        address recipient = makeAddr("contractOwnerDeferredActionRecipient");

        for (uint256 i = 0; i < 2; ++i) {
            PackedUserOperation memory userOp = _buildContractOwnerDeferredAction(recipient, i == 1);
            PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
            userOps[0] = userOp;

            vm.expectRevert(
                abi.encodeWithSelector(
                    IEntryPoint.FailedOpWithRevert.selector,
                    0,
                    "AA23 reverted",
                    abi.encodeWithSelector(ModularAccountBase.DeferredActionSignatureInvalid.selector)
                )
            );
            entryPoint.handleOps(userOps, beneficiary);
        }

        assertEq(recipient.balance, 0);
    }

    /// @dev A signature-only, non-global validation with no selector access cannot turn its ERC-1271 capability
    /// into the native fallback's global UserOperation authority by nesting itself inside a self-referencing
    /// `CONTRACT_OWNER` signature.
    function test_userOp_selfContractOwnerCannotPromoteSignatureOnlyValidation() public {
        uint32 entityId = 42;
        (address sessionSigner, uint256 sessionSignerKey) = makeAddrAndKey("signatureOnlySessionSigner");
        ModuleEntity sessionValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), entityId);

        vm.prank(_eoa);
        _account.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: sessionValidation,
                _isGlobal: false,
                _isSignatureValidation: true,
                _isUserOpValidation: false
            }),
            new bytes4[](0),
            abi.encode(entityId, sessionSigner),
            new bytes[](0)
        );

        address recipient = makeAddr("contractOwnerEscalationRecipient");
        bytes memory drainCall = abi.encodeCall(IModularAccount.execute, (recipient, 99 ether, ""));

        // The validation is intentionally inapplicable to this UserOperation when selected directly.
        PackedUserOperation memory directUserOp = _buildUserOp();
        directUserOp.nonce = _encodeNextNonce(_eoa, sessionValidation, false);
        directUserOp.callData = drainCall;
        bytes32 directUserOpHash = entryPoint.getUserOpHash(directUserOp);
        bytes memory directSignature =
            _encodeSignature(_signRawHash(vm, sessionSignerKey, directUserOpHash.toEthSignedMessageHash()));
        directUserOp.signature = directSignature;
        PackedUserOperation[] memory directUserOps = new PackedUserOperation[](1);
        directUserOps[0] = directUserOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    ModularAccountBase.ValidationFunctionMissing.selector, IModularAccount.execute.selector
                )
            )
        );
        entryPoint.handleOps(directUserOps, beneficiary);

        // The same key is valid for ERC-1271, but self-CONTRACT_OWNER must not let that proof inherit the
        // fallback validation's global authority.
        PackedUserOperation memory wrappedUserOp = _buildUserOp();
        wrappedUserOp.callData = drainCall;
        bytes32 wrappedUserOpHash = entryPoint.getUserOpHash(wrappedUserOp);
        bytes32 outerDigest = wrappedUserOpHash.toEthSignedMessageHash();
        bytes memory innerSignature = _encode1271Signature(
            sessionValidation,
            _signRawHash(
                vm,
                sessionSignerKey,
                _getModuleReplaySafeHash(_eoa, address(singleSignerValidationModule), outerDigest)
            )
        );
        assertEq(_account.isValidSignature(outerDigest, innerSignature), _1271_MAGIC_VALUE);

        wrappedUserOp.signature =
            _encodeSignature(abi.encodePacked(uint8(SignatureType.CONTRACT_OWNER), innerSignature));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = wrappedUserOp;

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(userOps, beneficiary);

        assertEq(recipient.balance, 0);
        assertEq(address(_account).balance, 100 ether);
    }

    /// @dev Rejecting self-reference does not change `CONTRACT_OWNER` support for a distinct contract fallback
    /// signer.
    function test_userOp_contractOwnerEncodingSupportsDistinctContractFallbackSigner() public {
        MockERC1271ContractSigner contractSigner = new MockERC1271ContractSigner(owner1);
        vm.prank(_eoa);
        _account.updateFallbackSignerData(address(contractSigner), false);

        address recipient = makeAddr("distinctContractOwnerRecipient");
        PackedUserOperation memory userOp = _buildUserOp();
        userOp.callData = abi.encodeCall(IModularAccount.execute, (recipient, 1 wei, ""));

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = _encodeSignature(abi.encodePacked(uint8(SignatureType.CONTRACT_OWNER), r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, beneficiary);

        assertEq(recipient.balance, 1 wei);
    }

    function test_userOp_standardEncoding() public {
        address recipient = makeAddr("recipient");

        _runUserOpFrom(_eoa, _eoaKey, abi.encodeCall(IModularAccount.execute, (recipient, 1 wei, "")), hex"");

        assertEq(recipient.balance, 1 wei);
    }

    // Helpers.

    function _signBare(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_eoaKey, hash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev ERC-2098 compact representation, packing the parity of `v` into the top bit of `s`.
    function _signBareCompact(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_eoaKey, hash);
        return abi.encodePacked(r, bytes32(uint256(s) | (uint256(v - 27) << 255)));
    }

    function _buildContractOwnerDeferredAction(address recipient, bool compact)
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = _buildUserOp();
        userOp.nonce = _encodeNextNonce(_eoa, FALLBACK_VALIDATION, true, true);

        bytes memory deferredAction = abi.encodeCall(IModularAccount.execute, (recipient, 1 wei, ""));
        uint48 deferredActionDeadline = 0;
        bytes32 deferredActionDigest =
            _getDeferredInstallStruct(account1, userOp.nonce, deferredActionDeadline, deferredAction);
        bytes memory bareSignature =
            compact ? _signBareCompact(deferredActionDigest) : _signBare(deferredActionDigest);
        bytes memory deferredActionSignature = abi.encodePacked(uint8(SignatureType.CONTRACT_OWNER), bareSignature);

        ValidationLocator deferredActionValidation = ValidationLocatorLib.packFromModuleEntity({
            _moduleEntity: FALLBACK_VALIDATION,
            _isGlobal: true,
            _hasDeferredAction: false
        });
        bytes memory deferredActionData =
            _packDeferredInstallData(deferredActionDeadline, deferredActionValidation, deferredAction);

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory userOpSignature =
            _encodeSignature(_signRawHash(vm, _eoaKey, userOpHash.toEthSignedMessageHash()));
        userOp.signature =
            _encodeDeferredInstallUOSignature(deferredActionData, deferredActionSignature, userOpSignature);
    }

    function _buildUserOp() internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: _eoa,
            nonce: _encodeNextNonce(_eoa, FALLBACK_VALIDATION, true),
            initCode: hex"",
            callData: abi.encodeCall(IModularAccount.execute, (beneficiary, 0 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _installNoOpFallbackValidationHook(MockCountModule hookModule) internal {
        HookConfig hookConfig =
            HookConfigLib.packValidationHook({_module: address(hookModule), _entityId: uint32(1)});
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(hookConfig, hex"00");

        vm.prank(_eoa);
        _account.installValidation(
            ValidationConfigLib.pack({
                _validationFunction: FALLBACK_VALIDATION,
                _isGlobal: true,
                _isSignatureValidation: true,
                _isUserOpValidation: true
            }),
            new bytes4[](0),
            "",
            hooks
        );
    }

    function _assertUserOpSignatureRejected(
        PackedUserOperation memory userOp,
        bytes32 userOpHash,
        bytes memory signature
    ) internal {
        userOp.signature = signature;

        vm.prank(address(entryPoint));
        (bool success, bytes memory returnData) =
            address(_account).call(abi.encodeCall(IAccount.validateUserOp, (userOp, userOpHash, 0)));

        // Either validation reverts while decoding, or its low 160 bits report SIG_VALIDATION_FAILED. A nonzero
        // time range alone is not a signature failure.
        if (success) {
            assertEq(returnData.length, 32);
            assertEq(uint160(abi.decode(returnData, (uint256))), uint160(1));
        }
    }

    /// @dev Asserts that `isValidSignature` does not return the success magic value. A revert is an acceptable
    /// outcome here, so the call is made without expecting a specific result.
    function _assertDoesNotValidate(address account, bytes32 hash, bytes memory signature) internal view {
        (bool success, bytes memory returnData) =
            account.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, signature)));

        if (success) {
            assertEq(returnData.length, 32);
            assertTrue(abi.decode(returnData, (bytes4)) != _1271_MAGIC_VALUE);
        }
    }
}
