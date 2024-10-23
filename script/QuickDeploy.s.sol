// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {console2 as console} from "forge-std/src/Console2.sol";
import {Script} from "forge-std/src/Script.sol";

import {ModularAccount} from "src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "src/account/SemiModularAccountBytecode.sol";
import {SemiModularAccountStorageOnly} from "src/account/SemiModularAccountStorageOnly.sol";
import {AccountFactory} from "src/factory/AccountFactory.sol";

// Validation Modules
import {SingleSignerValidationModule} from "src/modules/validation/SingleSignerValidationModule.sol";
import {WebAuthnValidationModule} from "src/modules/validation/WebAuthnValidationModule.sol";

// Permission Modules
import {AllowlistModule} from "src/modules/permissions/AllowlistModule.sol";
import {NativeTokenLimitModule} from "src/modules/permissions/NativeTokenLimitModule.sol";
import {PaymasterGuardModule} from "src/modules/permissions/PaymasterGuardModule.sol";
import {TimeRangeModule} from "src/modules/permissions/TimeRangeModule.sol";

contract QuickDeployScript is Script {
    IEntryPoint internal _entryPoint = IEntryPoint(address(type(uint160).max));

    Deployment[] internal _deployments;

    struct Deployment {
        string name;
        address addr;
    }

    struct AccountDeployments {
        address ma;
        address smaBytecode;
        address smaStorage;
    }

    struct ValidationModuleDeployments {
        address ssv;
        address webAuthn;
    }

    struct PermissionModuleDeployments {
        address allowlist;
        address nativeTokenLimit;
        address paymasterGuard;
        address timeRange;
    }

    struct ModuleDeployments {
        ValidationModuleDeployments validationDeployments;
        PermissionModuleDeployments permissionDeployments;
    }

    function run() public {
        vm.startBroadcast(vm.envUint("TEST_PRIVATE_KEY"));
        address owner = vm.addr(vm.envUint("TEST_PRIVATE_KEY"));

        // Deploy account impls
        AccountDeployments memory accountDeployments = _deployAccounts();

        // Deploy modules
        ModuleDeployments memory moduleDeployments = _deployModules();

        // Deploy the factory
        _withDeployLog(
            "Account Factory",
            address(
                new AccountFactory(
                    _entryPoint,
                    ModularAccount(payable(accountDeployments.ma)),
                    SemiModularAccountBytecode(payable(accountDeployments.smaBytecode)),
                    address(moduleDeployments.validationDeployments.ssv),
                    owner
                )
            )
        );

        _logDeployments();
        vm.stopBroadcast();
    }

    function _deployAccounts() internal returns (AccountDeployments memory result) {
        result.ma = _withDeployLog("Modular Account", address(new ModularAccount(_entryPoint)));

        result.smaBytecode = _withDeployLog("SMA Bytecode", address(new SemiModularAccountBytecode(_entryPoint)));

        result.smaStorage = _withDeployLog("SMA Storage", address(new SemiModularAccountStorageOnly(_entryPoint)));
    }

    function _deployModules() internal returns (ModuleDeployments memory result) {
        result.validationDeployments.ssv =
            _withDeployLog("Single Signer Validation", address(new SingleSignerValidationModule()));
        result.validationDeployments.webAuthn =
            _withDeployLog("WebAuthn Validation", address(new WebAuthnValidationModule()));

        // Permission Modules
        result.permissionDeployments.allowlist =
            _withDeployLog("Allowlist Permission Module", address(new AllowlistModule()));

        result.permissionDeployments.nativeTokenLimit =
            _withDeployLog("Native Token Limit Permission Module", address(new NativeTokenLimitModule()));

        result.permissionDeployments.paymasterGuard =
            _withDeployLog("Paymaster Guard Permission Module", address(new PaymasterGuardModule()));

        result.permissionDeployments.timeRange =
            _withDeployLog("Time Range Permission Module", address(new TimeRangeModule()));
    }

    // Would be nice if we could pass an arbitrary contract type and cast to address, but alas.
    function _withDeployLog(string memory name, address addr) internal returns (address) {
        _deployments.push(Deployment(name, addr));
        return addr;
    }

    function _logDeployments() internal view {
        for (uint256 i = 0; i < _deployments.length; ++i) {
            string memory finalName = string(abi.encodePacked(_deployments[i].name, ":"));

            console.log(finalName, _deployments[i].addr);
        }
    }
}
