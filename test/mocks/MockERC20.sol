// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("MockERC20", "MERC") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
