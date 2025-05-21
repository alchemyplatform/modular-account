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

import {console} from "forge-std/Test.sol";

import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {WebAuthn} from "webauthn-sol/src/WebAuthn.sol";
import {Utils, WebAuthnInfo} from "webauthn-sol/test/Utils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {WebAuthnValidationModule} from "../../src/modules/validation/WebAuthnValidationModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {CODELESS_ADDRESS} from "../utils/TestConstants.sol";

contract WebAuthnValidationModuleTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    WebAuthnValidationModule public module;
    address payable public account;
    uint32 public entityId = 1;
    // Example key from Coinbase Smart Wallet
    uint256 public passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    // set up
    uint256 public x =
        7_502_113_173_249_205_849_150_263_876_338_372_749_490_801_285_004_484_536_397_160_563_583_087_717_331;
    uint256 public y =
        11_950_572_268_732_037_161_698_627_499_273_938_409_251_473_964_035_323_628_613_441_431_942_511_740_588;

    // EP Constants
    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    function setUp() public override {
        module = new WebAuthnValidationModule();
        account = payable(account1);
        vm.prank(address(entryPoint));
        ModularAccount(account).installValidation(
            ValidationConfigLib.pack(address(module), entityId, true, true, true),
            new bytes4[](0),
            abi.encode(entityId, x, y),
            new bytes[](0)
        );
    }

    function test_isValidSignature() external view {
        bytes32 message = keccak256("message");
        bytes32 challenge = module.replaySafeHash(account, message);

        assertTrue(
            ModularAccountBase(account).isValidSignature(message, _get1271SigForChallenge(challenge, 0, 0))
                == 0x1626ba7e
        );
    }

    // fuzz message
    function testFuzz_pass_isValidSignature(bytes32 message) public view {
        bytes32 challenge = module.replaySafeHash(account, message);

        assertTrue(
            ModularAccountBase(account).isValidSignature(message, _get1271SigForChallenge(challenge, 0, 0))
                == 0x1626ba7e
        );
    }

    // Fuzz sig
    function testFuzz_fail_isValidSignature(bytes32 message, uint256 sigR, uint256 sigS) external view {
        bytes32 challenge = module.replaySafeHash(account, message);

        // make sure r, s values isn't the right one by accident. checking 1 should be enough
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);
        (bytes32 r,) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        vm.assume(r != bytes32(sigR));

        // build a correctly formatted sig and test it
        vm.assume(sigR != 0); // because we special case r=0 and s=0 in the helper function
        bytes memory forgedSig = _get1271SigForChallenge(challenge, sigR, sigS);

        assertTrue(ModularAccountBase(account).isValidSignature(message, forgedSig) == 0xFFFFFFFF);
    }

    function _get1271SigForChallenge(bytes32 challenge, uint256 overrideSigR, uint256 overrideSigS)
        internal
        view
        returns (bytes memory)
    {
        // Origin is coinbase only, but for a test it should be fine
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        return _encode1271Signature(
            ModuleEntityLib.pack(address(module), entityId),
            abi.encode(
                WebAuthn.WebAuthnAuth({
                    authenticatorData: webAuthn.authenticatorData,
                    clientDataJSON: webAuthn.clientDataJSON,
                    typeIndex: 1,
                    challengeIndex: 23,
                    r: overrideSigR != 0 ? overrideSigR : uint256(r),
                    s: overrideSigS != 0 ? overrideSigS : uint256(s)
                })
            )
        );
    }

    function test_uoValidation() external withSMATest {
        PackedUserOperation memory uo;
        uo.sender = account;
        uo.nonce = _encodeNextNonce(account, ModuleEntityLib.pack(address(module), entityId), true);
        uo.callData = abi.encodeCall(ModularAccountBase.execute, (CODELESS_ADDRESS, 0, new bytes(0)));
        bytes32 uoHash = entryPoint.getUserOpHash(uo);
        console.log(string.concat("UserOpHash: ", vm.toString(uoHash)));
        uo.signature =
            hex"ff000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000001700000000000000000000000000000000000000000000000000000000000000019b3af9ac358cfa64966bb94b94908bf98fbd9097bc237c2eabfb00d43a20ca9a07af5178c10c64e98d00b625ca2842f3c561f300e77a51d54b30aa0e8d9dd01d000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009d7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22307838613637343862653766613133643363613331323165363133636636386632323261303832333465383761623662313830313530663630343939353931323077222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303030222c2263726f73734f726967696e223a66616c73657d000000";

        vm.prank(address(entryPoint));
        assertEq(ModularAccountBase(account).validateUserOp(uo, uoHash, 0), _SIG_VALIDATION_PASSED);
    }

    // function test_signature_now() external withSMATest {
    //     // create a user op
    //     PackedUserOperation memory uo;
    //     uo.sender = account;
    //     uo.nonce = _encodeNextNonce(account, ModuleEntityLib.pack(address(module), 0), true);
    //     uo.callData = abi.encodeCall(ModularAccountBase.execute, (CODELESS_ADDRESS, 0, new bytes(0)));
    //     bytes32 _uoHash = entryPoint.getUserOpHash(uo);
    //     bytes32 uoHash = hex"ef7e52ba2b5e06054a510e9ccd6b022bc2c98ec94bcd7c84b3deff62a27472d6";
    //     uo.signature =
    //         hex"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000001f90c4a2def47659f545bc2582136b387a530b6f76ee3fedd9837c52da5996096522229ecd1dff20e1dc0c61c0c15d68a9d3850027552c509039f5544fec07702000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009d7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22307865663765353262613262356530363035346135313065396363643662303232626332633938656339346263643763383462336465666636326132373437326477222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303030222c2263726f73734f726967696e223a66616c73657d000000";

    //     assertEq(ModularAccountBase(account).validateUserOp(uo, uoHash, 0), _SIG_VALIDATION_PASSED);
    // }

    function testFuzz_uoValidation_shouldFail(uint256 sigR, uint256 sigS) external {
        PackedUserOperation memory uo;
        uo.sender = account;
        uo.nonce = _encodeNextNonce(account, ModuleEntityLib.pack(address(module), entityId), true);
        uo.callData = abi.encodeCall(ModularAccountBase.execute, (CODELESS_ADDRESS, 0, new bytes(0)));
        bytes32 uoHash = entryPoint.getUserOpHash(uo);

        // make sure r, s values isn't the right one by accident. checking 1 should be enough
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(uoHash.toEthSignedMessageHash());
        (bytes32 r,) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        vm.assume(r != bytes32(sigR));

        // build a correctly formatted sig and test it
        vm.assume(sigR != 0); // because we special case r=0 and s=0 in the helper function
        uo.signature = _getUOSigForChallenge(uoHash.toEthSignedMessageHash(), sigR, sigS);

        vm.prank(address(entryPoint));
        assertEq(ModularAccountBase(account).validateUserOp(uo, uoHash, 0), _SIG_VALIDATION_FAILED);
    }

    function _getUOSigForChallenge(bytes32 challenge, uint256 overrideSigR, uint256 overrideSigS)
        internal
        view
        returns (bytes memory)
    {
        // Origin is coinbase only, but for a test it should be fine
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        return _encodeSignature(
            abi.encode(
                WebAuthn.WebAuthnAuth({
                    authenticatorData: webAuthn.authenticatorData,
                    clientDataJSON: webAuthn.clientDataJSON,
                    typeIndex: 1,
                    challengeIndex: 23,
                    r: overrideSigR != 0 ? overrideSigR : uint256(r),
                    s: overrideSigS != 0 ? overrideSigS : uint256(s)
                })
            )
        );
    }
}
