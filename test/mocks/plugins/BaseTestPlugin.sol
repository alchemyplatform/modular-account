// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {PluginMetadata} from "../../../src/interfaces/IPlugin.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";

contract BaseTestPlugin is BasePlugin {
    // Don't need to implement this in each context
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        revert NotImplemented(msg.sig, 0);
    }
}
