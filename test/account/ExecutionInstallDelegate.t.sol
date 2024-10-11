// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ExecutionInstallDelegate} from "../../src/helpers/ExecutionInstallDelegate.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

contract ExecutionInstallDelegateTest is AccountTestBase {
    function test_fail_directCall_delegateCallOnly() public {
        ExecutionInstallDelegate delegate = new ExecutionInstallDelegate();
        ExecutionManifest memory emptyManifest;

        vm.expectRevert(ExecutionInstallDelegate.OnlyDelegateCall.selector);
        delegate.installExecution({module: address(0), manifest: emptyManifest, moduleInstallData: ""});
    }
}
