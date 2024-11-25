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
