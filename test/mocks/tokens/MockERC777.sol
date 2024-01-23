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

pragma solidity ^0.8.22;

import {IERC777} from "@openzeppelin/contracts/token/ERC777/IERC777.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";

contract MockERC777 is IERC777 {
    string public override name;
    string public override symbol;
    uint256 public override granularity;
    uint256 public override totalSupply;
    mapping(address => uint256) public override balanceOf;

    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        return transferFrom(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        IERC777Recipient(to).tokensReceived(msg.sender, from, to, amount, bytes(""), bytes(""));
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function send(address to, uint256 amount, bytes calldata) public override {
        transferFrom(msg.sender, to, amount);
    }

    function burn(uint256 amount, bytes calldata) external {
        transferFrom(msg.sender, address(0), amount);
    }

    function isOperatorFor(address, address) external pure returns (bool) {
        return false;
    }

    // solhint-disable-next-line no-empty-blocks
    function authorizeOperator(address) external {}
    // solhint-disable-next-line no-empty-blocks
    function revokeOperator(address) external {}
    // solhint-disable-next-line no-empty-blocks
    function defaultOperators() external view returns (address[] memory a) {}
    // solhint-disable-next-line no-empty-blocks
    function operatorSend(address, address, uint256, bytes calldata, bytes calldata) external {}
    // solhint-disable-next-line no-empty-blocks
    function operatorBurn(address, uint256, bytes calldata, bytes calldata) external {}
}
