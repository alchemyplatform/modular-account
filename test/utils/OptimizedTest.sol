// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/src/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {ModularAccount} from "../../src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "../../src/account/SemiModularAccountBytecode.sol";

import {TokenReceiverModule} from "../../src/modules/TokenReceiverModule.sol";
import {ECDSAValidationModule} from "../../src/modules/validation/ECDSAValidationModule.sol";

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

    function _deployModularAccount(IEntryPoint entryPoint) internal returns (ModularAccount) {
        return _isOptimizedTest()
            ? ModularAccount(
                payable(deployCode("out-optimized/ModularAccount.sol/ModularAccount.json", abi.encode(entryPoint)))
            )
            : new ModularAccount(entryPoint);
    }

    function _deploySemiModularAccount(IEntryPoint entryPoint) internal returns (SemiModularAccountBytecode) {
        return _isOptimizedTest()
            ? SemiModularAccountBytecode(
                payable(
                    deployCode(
                        "out-optimized/SemiModularAccountBytecode.sol/SemiModularAccountBytecode.json",
                        abi.encode(entryPoint)
                    )
                )
            )
            : new SemiModularAccountBytecode(entryPoint);
    }

    function _deployTokenReceiverModule() internal returns (TokenReceiverModule) {
        return _isOptimizedTest()
            ? TokenReceiverModule(deployCode("out-optimized/TokenReceiverModule.sol/TokenReceiverModule.json"))
            : new TokenReceiverModule();
    }

    function _deployECDSAValidationModule() internal returns (ECDSAValidationModule) {
        return _isOptimizedTest()
            ? ECDSAValidationModule(deployCode("out-optimized/ECDSAValidationModule.sol/ECDSAValidationModule.json"))
            : new ECDSAValidationModule();
    }

    function _deployEntryPoint070() internal returns (EntryPoint) {
        address deployedEntryPointAddr = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
        address deployedSenderCreatorAddr = 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C;
        bytes memory bytecode = vm.readFileBinary("test/bin/EntryPoint070.bytecode");
        vm.etch(deployedEntryPointAddr, bytecode);
        bytecode = vm.readFileBinary("test/bin/SenderCreator070.bytecode");
        vm.etch(deployedSenderCreatorAddr, bytecode);
        return EntryPoint(payable(deployedEntryPointAddr));
    }
}
