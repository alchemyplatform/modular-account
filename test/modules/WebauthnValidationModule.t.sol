// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ModuleEntityLib} from "@erc6900/reference-implementation/helpers/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/helpers/ValidationConfigLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {WebAuthn} from "webauthn-sol/src/WebAuthn.sol";
import {Utils, WebAuthnInfo} from "webauthn-sol/test/Utils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {ModularAccountBase} from "../../src/account/ModularAccountBase.sol";
import {WebauthnValidationModule} from "../../src/modules/validation/WebauthnValidationModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {CODELESS_ADDRESS} from "../utils/TestConstants.sol";

contract WebauthnValidationModuleTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    WebauthnValidationModule public module;
    address payable public account;
    uint32 public entityId = 1;
    // Example key from Coinbase Smart Wallet
    uint256 public passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    uint256 public x =
        12_673_873_082_346_130_924_691_454_452_779_514_193_164_883_897_088_292_420_374_917_853_190_248_779_330;
    uint256 public y =
        18_542_991_761_951_108_740_563_055_453_066_386_026_290_576_689_311_603_472_268_584_080_832_751_656_013;

    // EP Constants
    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    function setUp() public override {
        module = new WebauthnValidationModule();
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

    function test_fail_isValidSignature(bytes32 message, uint256 sigR, uint256 sigS) external view {
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
        uo.callData = abi.encodeCall(ModularAccountBase.execute, (CODELESS_ADDRESS, 0, new bytes(0)));

        bytes32 uoHash = entryPoint.getUserOpHash(uo);
        uo.signature = _getUOSigForChallenge(uoHash.toEthSignedMessageHash(), 0, 0);

        vm.prank(address(entryPoint));
        assertEq(ModularAccountBase(account).validateUserOp(uo, uoHash, 0), _SIG_VALIDATION_PASSED);
    }

    function test_uoValidaton_shouldFail(uint256 sigR, uint256 sigS) external {
        PackedUserOperation memory uo;
        uo.sender = account;
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
            ModuleEntityLib.pack(address(module), entityId),
            uint8(1),
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
