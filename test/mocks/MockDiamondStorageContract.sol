// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.26;

import {AccountStorageInitializable} from "../../src/account/AccountStorageInitializable.sol";

contract MockDiamondStorageContract is AccountStorageInitializable {
    constructor() {
        _disableInitializers();
    }

    // solhint-disable-next-line no-empty-blocks
    function initialize() external initializer {}
}
