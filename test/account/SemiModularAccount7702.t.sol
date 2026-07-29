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

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccount7702} from "../../src/account/SemiModularAccount7702.sol";
import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";

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

    // Rejected bare signatures. ERC-1271 requires the failure magic value rather than a revert, and gas
    // estimation in dApps depends on it: the original report surfaced as an unrelated estimation failure
    // because validation reverted while decoding the signature.

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
        assertEq(_account.isValidSignature(hash, _signBare(hash)), _1271_INVALID);
        assertEq(_account.isValidSignature(hash, _signBareCompact(hash)), _1271_INVALID);
    }

    function test_isValidSignature_bareSignature_fallbackSignerRotated() public {
        vm.prank(_eoa);
        _account.updateFallbackSignerData(owner1, false);

        bytes32 hash = keccak256("hello world");
        assertEq(_account.isValidSignature(hash, _signBare(hash)), _1271_INVALID);

        // The rotated-to signer still validates through the standard encoding.
        bytes memory signature = _encode1271Signature(
            FALLBACK_VALIDATION, _signRawHash(vm, owner1Key, _getSMAReplaySafeHash(_eoa, hash))
        );
        assertEq(_account.isValidSignature(hash, signature), _1271_MAGIC_VALUE);
    }

    // The standard signature encoding is unchanged.

    function test_isValidSignature_standardEncoding() public view {
        bytes32 hash = keccak256("hello world");
        bytes memory signature = _encode1271Signature(
            FALLBACK_VALIDATION, _signRawHash(vm, _eoaKey, _getSMAReplaySafeHash(_eoa, hash))
        );

        // The standard encoding carries at least 6 bytes of overhead on top of the inner signature, so it can
        // never collide with the two lengths reserved for bare signatures.
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

    /// @dev The bare path is scoped to `isValidSignature`. User operation validation - and with it deferred
    /// action installation, which authorizes arbitrary self-calls - still requires the standard encoding.
    function test_validateUserOp_rejectsBareSignature() public {
        PackedUserOperation memory userOp = _buildUserOp();

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_eoaKey, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        (bool success, bytes memory returnData) =
            address(_account).call(abi.encodeCall(IAccount.validateUserOp, (userOp, userOpHash, 0)));

        // Either validation reverts while decoding, or it reports failure. It must not report success.
        if (success) {
            assertEq(returnData.length, 32);
            assertTrue(abi.decode(returnData, (uint256)) != 0);
        }
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
