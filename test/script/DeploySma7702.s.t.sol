// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {DeploySma7702Script} from "../../script/DeploySma7702.s.sol";
import {SemiModularAccount7702} from "../../src/account/SemiModularAccount7702.sol";

import {OptimizedTest} from "../utils/OptimizedTest.sol";

contract DeploySma7702Test is OptimizedTest {
    DeploySma7702Script internal _deploySma7702Script;

    address public entryPoint;
    address public executionInstallDelegate;
    address public semiModularAccount7702Impl;

    function setUp() public {
        _deploySma7702Script = new DeploySma7702Script();

        bytes32 zeroSalt = bytes32(0);

        entryPoint = address(_deployEntryPoint070());

        executionInstallDelegate = makeAddr("ExecutionInstallDelegate");

        semiModularAccount7702Impl = Create2.computeAddress(
            zeroSalt,
            keccak256(
                bytes.concat(
                    type(SemiModularAccount7702).creationCode, abi.encode(entryPoint, executionInstallDelegate)
                )
            ),
            CREATE2_FACTORY
        );

        vm.setEnv("ENTRYPOINT", vm.toString(entryPoint));
        vm.setEnv("EXECUTION_INSTALL_DELEGATE", vm.toString(executionInstallDelegate));
        vm.setEnv("SEMI_MODULAR_ACCOUNT_7702_IMPL", vm.toString(semiModularAccount7702Impl));

        string memory zeroSaltString = vm.toString(zeroSalt);

        vm.setEnv("SEMI_MODULAR_ACCOUNT_7702_IMPL_SALT", zeroSaltString);

        // Spoof as though the profile is set to "optimized-build".
        vm.setEnv("FOUNDRY_PROFILE", "optimized-build");
    }

    function test_deploySma7702Script() public {
        _deploySma7702Script.setUp();

        _deploySma7702Script.run();

        assertEq(SemiModularAccount7702(payable(semiModularAccount7702Impl)).accountId(), "alchemy.sma-7702.1.1.0");
    }
}
