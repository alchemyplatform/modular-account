// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccount} from "../../src/account/SemiModularAccount.sol";
import {AccountFactory} from "../../src/factory/AccountFactory.sol";

import {FALLBACK_VALIDATION} from "../../src/helpers/Constants.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";

import {ValidationConfig, ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {MockUserOpValidationModule} from "../../test/mocks/modules/ValidationModuleMocks.sol";
import {ModuleSignatureUtils} from "../../test/utils/ModuleSignatureUtils.sol";

import {BenchmarkBase} from "../BenchmarkBase.sol";

abstract contract ModularAccountBenchmarkBase is BenchmarkBase, ModuleSignatureUtils {
    using ValidationConfigLib for ValidationConfig;

    bytes32 private constant _INSTALL_VALIDATION_TYPEHASH = keccak256(
        "InstallValidation(bytes25 validationConfig,bytes4[] selectors,bytes installData,bytes[] hooks,"
        "uint256 nonce,uint48 deadline)"
    );

    AccountFactory public factory;
    ModularAccount public accountImpl;
    SemiModularAccount public semiModularImpl;
    SingleSignerValidationModule public singleSignerValidationModule;

    ModularAccount public account1;

    ModuleEntity public signerValidation;
    address internal _mockValidation;

    constructor(string memory accountImplName) BenchmarkBase(accountImplName) {
        accountImpl = _deployModularAccount(IEntryPoint(entryPoint));
        semiModularImpl = _deploySemiModularAccount(IEntryPoint(entryPoint));
        singleSignerValidationModule = _deploySingleSignerValidationModule();

        _mockValidation = address(new MockUserOpValidationModule());

        factory = new AccountFactory(
            entryPoint, accountImpl, semiModularImpl, address(singleSignerValidationModule), address(this)
        );
    }

    function _deployAccount1() internal {
        account1 = factory.createAccount(owner1, 0, 0);
        signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), 0);
    }

    function _deploySemiModularAccount1() internal {
        account1 = factory.createSemiModularAccount(owner1, 0);
        signerValidation = FALLBACK_VALIDATION;
    }

    // Internal Helpers
    function _buildFullDeferredInstallSig(
        bool isSemiModular,
        ModularAccount account,
        uint256 nonce,
        uint48 deadline
    ) internal view returns (bytes memory) {
        /**
         * Deferred validation signature structure:
         * bytes 0-23: Outer validation moduleEntity (the validation used to validate the installation of the inner
         * validation)
         * byte 24   : Validation flags (rightmost bit == isGlobal, second-to-rightmost bit ==
         * isDeferredValidationInstall)
         *
         * This is where things diverge, if this is a deferred validation install, rather than using the remaining
         * signature data as validation data, we decode it as follows:
         *
         * bytes 25-28            : uint32, abi-encoded parameters length (e.g. 100)
         * bytes 29-128 (example) : abi-encoded parameters
         * bytes 129-132          : deferred install validation sig length (e.g. 68)
         * bytes 133-200 (example): install validation sig data (the data passed to the outer validation to
         * validate the deferred installation)
         * bytes 201...           : signature data passed to the newly installed deferred validation to validate
         * the UO
         */
        uint8 outerValidationFlags = 3;

        ValidationConfig deferredConfig = ValidationConfigLib.pack({
            _module: _mockValidation,
            _entityId: uint32(0),
            _isGlobal: true,
            _isSignatureValidation: false,
            _isUserOpValidation: true
        });

        bytes memory deferredInstallData =
            abi.encode(deferredConfig, new bytes4[](0), "", new bytes[](0), nonce, deadline);

        bytes32 domainSeparator;

        // Needed for initCode txs
        if (address(account).code.length > 0) {
            domainSeparator = account.domainSeparator();
        } else {
            domainSeparator = _computeDomainSeparatorNotDeployed(account);
        }

        bytes32 structHash = keccak256(
            abi.encode(
                _INSTALL_VALIDATION_TYPEHASH, deferredConfig, new bytes4[](0), "", new bytes[](0), nonce, deadline
            )
        );
        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        bytes32 replaySafeHash = isSemiModular
            ? _getSmaReplaySafeHash(account, typedDataHash)
            : singleSignerValidationModule.replaySafeHash(address(account), typedDataHash);

        bytes memory deferredInstallSig = _getDeferredInstallSig(replaySafeHash);

        bytes memory innerUoValidationSig = _packValidationResWithIndex(255, hex"1234");

        bytes memory encodedDeferredInstall = abi.encodePacked(
            signerValidation,
            outerValidationFlags,
            uint32(deferredInstallData.length),
            deferredInstallData,
            uint32(deferredInstallSig.length),
            deferredInstallSig,
            innerUoValidationSig
        );

        return encodedDeferredInstall;
    }

    function _computeDomainSeparatorNotDeployed(ModularAccount account) internal view returns (bytes32) {
        bytes32 domainSeparatorTypehash = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
        return keccak256(abi.encode(domainSeparatorTypehash, block.chainid, address(account)));
    }

    function _getSmaReplaySafeHash(ModularAccount account, bytes32 typedDataHash)
        internal
        view
        returns (bytes32)
    {
        if (address(account).code.length > 0) {
            return SemiModularAccount(payable(account)).replaySafeHash(typedDataHash);
        } else {
            // precompute it as the SMA is not yet deployed
            // for SMA, the domain separator used for the deferred validation installation is the same as the one
            // used to compute the replay safe hash.
            return MessageHashUtils.toTypedDataHash({
                domainSeparator: _computeDomainSeparatorNotDeployed(account),
                structHash: _hashStruct(typedDataHash)
            });
        }
    }

    function _getDeferredInstallSig(bytes32 replaySafeHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, replaySafeHash);

        bytes memory rawDeferredInstallSig = abi.encodePacked(r, s, v);

        bytes memory deferredInstallSig = _packValidationResWithIndex(255, rawDeferredInstallSig);
        return deferredInstallSig;
    }

    function _hashStruct(bytes32 hash) internal pure virtual returns (bytes32) {
        bytes32 replaySafeTypehash = keccak256("ReplaySafeHash(bytes32 hash)"); // const 0x.. in contract
        bytes32 res;
        assembly ("memory-safe") {
            mstore(0x00, replaySafeTypehash)
            mstore(0x20, hash)
            res := keccak256(0, 0x40)
        }
        return res;
    }
}
