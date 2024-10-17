// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModularAccountView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {ModularAccountBase} from "../account/ModularAccountBase.sol";

/// @title Native Function Delegate
/// @author Alchemy
/// @dev This is a simple contract meant to be delegatecalled to determine whether a ModularAccountBase function
/// selector is native to the account implementation.
contract NativeFunctionDelegate {
    function isNativeFunction(uint32 selector) external pure returns (bool) {
        return
        // check against IAccount methods
        selector == uint32(IAccount.validateUserOp.selector)
        // check against IModularAccount methods
        || selector == uint32(IModularAccount.installExecution.selector)
            || selector == uint32(IModularAccount.uninstallExecution.selector)
            || selector == uint32(IModularAccount.installValidation.selector)
            || selector == uint32(IModularAccount.uninstallValidation.selector)
            || selector == uint32(IModularAccount.execute.selector)
            || selector == uint32(IModularAccount.executeBatch.selector)
            || selector == uint32(IModularAccount.executeWithRuntimeValidation.selector)
            || selector == uint32(IModularAccount.accountId.selector)
        // check against IERC165 methods
        || selector == uint32(IERC165.supportsInterface.selector)
        // check against UUPSUpgradeable methods
        || selector == uint32(UUPSUpgradeable.proxiableUUID.selector)
            || selector == uint32(UUPSUpgradeable.upgradeToAndCall.selector)
        // check against IModularAccountView methods
        || selector == uint32(IModularAccountView.getExecutionData.selector)
            || selector == uint32(IModularAccountView.getValidationData.selector)
        // check against ModularAccount methods
        || selector == uint32(ModularAccountBase.performCreate.selector);
    }
}
