// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {SemiModularAccountBase} from "../account/SemiModularAccountBase.sol";
import {KnownSelectorsLib} from "./KnownSelectorsLib.sol";

/// @dev Library to help to check if a selector is a know function selector of the SemiModularAccountBase or
/// ModularAccount contract
library SemiModularKnownSelectorsLib {
    function isNativeFunction(bytes4 selector) internal pure returns (bool) {
        return KnownSelectorsLib.isNativeFunction(selector)
            || selector == SemiModularAccountBase.updateFallbackSignerData.selector
            || selector == SemiModularAccountBase.getFallbackSignerData.selector
            || selector == SemiModularAccountBase.replaySafeHash.selector;
    }
}
