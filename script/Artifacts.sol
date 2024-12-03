// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ModularAccount} from "../src/account/ModularAccount.sol";
import {SemiModularAccount7702} from "../src/account/SemiModularAccount7702.sol";
import {SemiModularAccountBytecode} from "../src/account/SemiModularAccountBytecode.sol";
import {SemiModularAccountStorageOnly} from "../src/account/SemiModularAccountStorageOnly.sol";
import {AccountFactory} from "../src/factory/AccountFactory.sol";
import {ExecutionInstallDelegate} from "../src/helpers/ExecutionInstallDelegate.sol";
import {AllowlistModule} from "../src/modules/permissions/AllowlistModule.sol";
import {NativeTokenLimitModule} from "../src/modules/permissions/NativeTokenLimitModule.sol";
import {PaymasterGuardModule} from "../src/modules/permissions/PaymasterGuardModule.sol";
import {TimeRangeModule} from "../src/modules/permissions/TimeRangeModule.sol";
import {SingleSignerValidationModule} from "../src/modules/validation/SingleSignerValidationModule.sol";
import {WebAuthnValidationModule} from "../src/modules/validation/WebAuthnValidationModule.sol";

// Contains all deployment artifacts
// - AccountFactory
// - AllowlistModule
// - ExecutionInstallDelegate
// - ModularAccount
// - NativeTokenLimitModule
// - PaymasterGuardModule
// - SemiModularAccount7702
// - SemiModularAccountBytecode
// - SemiModularAccountStorageOnly
// - SingleSignerValidationModule
// - TimeRangeModule
// - WebAuthnValidationModule
abstract contract Artifacts {
    function _getAccountFactoryInitcode(
        IEntryPoint entryPoint,
        ModularAccount accountImpl,
        SemiModularAccountBytecode semiModularImpl,
        address singleSignerValidationModule,
        address webAuthnValidationModule,
        address owner
    ) internal pure returns (bytes memory) {
        return bytes.concat(
            type(AccountFactory).creationCode,
            abi.encode(
                entryPoint,
                accountImpl,
                semiModularImpl,
                singleSignerValidationModule,
                webAuthnValidationModule,
                owner
            )
        );
    }

    function _deployAccountFactory(
        bytes32 salt,
        IEntryPoint entryPoint,
        ModularAccount accountImpl,
        SemiModularAccountBytecode semiModularImpl,
        address singleSignerValidationModule,
        address webAuthnValidationModule,
        address owner
    ) internal returns (AccountFactory) {
        return new AccountFactory{salt: salt}(
            entryPoint, accountImpl, semiModularImpl, singleSignerValidationModule, webAuthnValidationModule, owner
        );
    }

    function _getAllowlistModuleInitcode() internal pure returns (bytes memory) {
        return type(AllowlistModule).creationCode;
    }

    function _deployAllowlistModule(bytes32 salt) internal returns (AllowlistModule) {
        return new AllowlistModule{salt: salt}();
    }

    function _getExecutionInstallDelegateInitcode() internal pure returns (bytes memory) {
        return type(ExecutionInstallDelegate).creationCode;
    }

    function _deployExecutionInstallDelegate(bytes32 salt) internal returns (ExecutionInstallDelegate) {
        return new ExecutionInstallDelegate{salt: salt}();
    }

    function _getModularAccountInitcode(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(type(ModularAccount).creationCode, abi.encode(entryPoint, executionInstallDelegate));
    }

    function _deployModularAccount(
        bytes32 salt,
        IEntryPoint entryPoint,
        ExecutionInstallDelegate executionInstallDelegate
    ) internal returns (ModularAccount) {
        return new ModularAccount{salt: salt}(entryPoint, executionInstallDelegate);
    }

    function _getNativeTokenLimitModuleInitcode() internal pure returns (bytes memory) {
        return type(NativeTokenLimitModule).creationCode;
    }

    function _deployNativeTokenLimitModule(bytes32 salt) internal returns (NativeTokenLimitModule) {
        return new NativeTokenLimitModule{salt: salt}();
    }

    function _getPaymasterGuardModuleInitcode() internal pure returns (bytes memory) {
        return type(PaymasterGuardModule).creationCode;
    }

    function _deployPaymasterGuardModule(bytes32 salt) internal returns (PaymasterGuardModule) {
        return new PaymasterGuardModule{salt: salt}();
    }

    function _getSemiModularAccount7702Initcode(
        IEntryPoint entryPoint,
        ExecutionInstallDelegate executionInstallDelegate
    ) internal pure returns (bytes memory) {
        return bytes.concat(
            type(SemiModularAccount7702).creationCode, abi.encode(entryPoint, executionInstallDelegate)
        );
    }

    function _deploySemiModularAccount7702(
        bytes32 salt,
        IEntryPoint entryPoint,
        ExecutionInstallDelegate executionInstallDelegate
    ) internal returns (SemiModularAccount7702) {
        return new SemiModularAccount7702{salt: salt}(entryPoint, executionInstallDelegate);
    }

    function _getSemiModularAccountBytecodeInitcode(
        IEntryPoint entryPoint,
        ExecutionInstallDelegate executionInstallDelegate
    ) internal pure returns (bytes memory) {
        return bytes.concat(
            type(SemiModularAccountBytecode).creationCode, abi.encode(entryPoint, executionInstallDelegate)
        );
    }

    function _deploySemiModularAccountBytecode(
        bytes32 salt,
        IEntryPoint entryPoint,
        ExecutionInstallDelegate executionInstallDelegate
    ) internal returns (SemiModularAccountBytecode) {
        return new SemiModularAccountBytecode{salt: salt}(entryPoint, executionInstallDelegate);
    }

    function _getSemiModularAccountStorageOnlyInitcode(
        IEntryPoint entryPoint,
        ExecutionInstallDelegate executionInstallDelegate
    ) internal pure returns (bytes memory) {
        return bytes.concat(
            type(SemiModularAccountStorageOnly).creationCode, abi.encode(entryPoint, executionInstallDelegate)
        );
    }

    function _deploySemiModularAccountStorageOnly(
        bytes32 salt,
        IEntryPoint entryPoint,
        ExecutionInstallDelegate executionInstallDelegate
    ) internal returns (SemiModularAccountStorageOnly) {
        return new SemiModularAccountStorageOnly{salt: salt}(entryPoint, executionInstallDelegate);
    }

    function _getSingleSignerValidationModuleInitcode() internal pure returns (bytes memory) {
        return type(SingleSignerValidationModule).creationCode;
    }

    function _deploySingleSignerValidationModule(bytes32 salt) internal returns (SingleSignerValidationModule) {
        return new SingleSignerValidationModule{salt: salt}();
    }

    function _getTimeRangeModuleInitcode() internal pure returns (bytes memory) {
        return type(TimeRangeModule).creationCode;
    }

    function _deployTimeRangeModule(bytes32 salt) internal returns (TimeRangeModule) {
        return new TimeRangeModule{salt: salt}();
    }

    function _getWebAuthnValidationModuleInitcode() internal pure returns (bytes memory) {
        return type(WebAuthnValidationModule).creationCode;
    }
}
