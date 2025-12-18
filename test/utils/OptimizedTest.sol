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

pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";

import {ExecutionInstallDelegate} from "../../src/helpers/ExecutionInstallDelegate.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

/// @dev This contract provides functions to deploy optimized (via IR) precompiled contracts. By compiling just
/// the source contracts (excluding the test suite) via IR, and using the resulting bytecode within the tests
/// (built without IR), we can avoid the significant overhead of compiling the entire test suite via IR.
///
/// To use the optimized precompiled contracts, the project must first be built with the "optimized-build" profile
/// to populate the artifacts in the `out-optimized` directory. Then use the "optimized-test" or
/// "optimized-test-deep" profile to run the tests.
///
/// To bypass this behavior for coverage or debugging, use the "default" profile.
abstract contract OptimizedTest is Test {
    function _isOptimizedTest() internal view returns (bool) {
        string memory profile = vm.envOr("FOUNDRY_PROFILE", string("default"));
        return _isStringEq(profile, "optimized-test-deep") || _isStringEq(profile, "optimized-test");
    }

    function _isStringEq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }

    function _deployModularAccount(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
        internal
        returns (ModularAccount)
    {
        return _isOptimizedTest()
            ? ModularAccount(
                payable(deployCode(
                        "out-optimized/ModularAccount.sol/ModularAccount.json",
                        abi.encode(entryPoint, executionInstallDelegate)
                    ))
            )
            : new ModularAccount(entryPoint, executionInstallDelegate);
    }

    function _deploySemiModularAccountBytecode(
        IEntryPoint entryPoint,
        ExecutionInstallDelegate executionInstallDelegate
    ) internal returns (SemiModularAccountBytecode) {
        return _isOptimizedTest()
            ? SemiModularAccountBytecode(
                payable(deployCode(
                        "out-optimized/SemiModularAccountBytecode.sol/SemiModularAccountBytecode.json",
                        abi.encode(entryPoint, executionInstallDelegate)
                    ))
            )
            : new SemiModularAccountBytecode(entryPoint, executionInstallDelegate);
    }

    function _deploySingleSignerValidationModule() internal returns (SingleSignerValidationModule) {
        return _isOptimizedTest()
            ? SingleSignerValidationModule(
                deployCode("out-optimized/SingleSignerValidationModule.sol/SingleSignerValidationModule.json")
            )
            : new SingleSignerValidationModule();
    }

    function _deployExecutionInstallDelegate() internal returns (ExecutionInstallDelegate) {
        return _isOptimizedTest()
            ? ExecutionInstallDelegate(
                deployCode("out-optimized/ExecutionInstallDelegate.sol/ExecutionInstallDelegate.json")
            )
            : new ExecutionInstallDelegate();
    }

    function _deployEntryPoint090() internal returns (EntryPoint) {
        address deployedEntryPointAddr = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;
        address deployedSenderCreatorAddr = 0x0A630a99Df908A81115A3022927Be82f9299987e;
        bytes memory bytecode = vm.readFileBinary("test/bin/EntryPoint090.bytecode");
        vm.etch(deployedEntryPointAddr, bytecode);
        bytecode = vm.readFileBinary("test/bin/SenderCreator090.bytecode");
        vm.etch(deployedSenderCreatorAddr, bytecode);
        return EntryPoint(payable(deployedEntryPointAddr));
    }
}
