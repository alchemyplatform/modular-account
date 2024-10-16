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

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {ModuleBase} from "../../../src/modules/ModuleBase.sol";

contract DirectCallModule is ModuleBase, IExecutionHookModule {
    bool public preHookRan = false;
    bool public postHookRan = false;

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function directCall() external returns (bytes memory) {
        return IModularAccount(msg.sender).execute(address(this), 0, abi.encodeCall(this.getData, ()));
    }

    function getData() external pure returns (bytes memory) {
        return hex"04546b";
    }

    function moduleId() external pure override returns (string memory) {
        return "erc6900.direct-call-module.1.0.0";
    }

    function preExecutionHook(uint32, address sender, uint256, bytes calldata)
        external
        override
        returns (bytes memory)
    {
        require(sender == address(this), "mock direct call pre execution hook failed");
        preHookRan = true;
        return abi.encode(keccak256(hex"04546b"));
    }

    function postExecutionHook(uint32, bytes calldata preExecHookData) external override {
        require(
            abi.decode(preExecHookData, (bytes32)) == keccak256(hex"04546b"),
            "mock direct call post execution hook failed"
        );
        postHookRan = true;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ModuleBase, IERC165)
        returns (bool)
    {
        return interfaceId == type(IExecutionHookModule).interfaceId || super.supportsInterface(interfaceId);
    }
}
