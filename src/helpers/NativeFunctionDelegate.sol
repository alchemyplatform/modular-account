// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IModularAccountView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";
import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IModularAccountBase} from "../interfaces/IModularAccountBase.sol";

/// @title Native Function Delegate
/// @author Alchemy
/// @dev This is a simple contract meant to be delegatecalled to determine whether a ModularAccountBase function
/// selector is native to the account implementation.
contract NativeFunctionDelegate {
    function isNativeFunction(uint32 selector) external pure returns (bool) {
        return
        // check against IAccount methods
        selector == uint32(IAccount.validateUserOp.selector)
        // check against ModularAccount methods
        || selector == uint32(IModularAccount.installExecution.selector)
            || selector == uint32(IModularAccount.uninstallExecution.selector)
            || selector == uint32(IModularAccount.installValidation.selector)
            || selector == uint32(IModularAccount.uninstallValidation.selector)
            || selector == uint32(IModularAccount.execute.selector)
            || selector == uint32(IModularAccount.executeBatch.selector)
            || selector == uint32(IModularAccount.executeWithRuntimeValidation.selector)
            || selector == uint32(IModularAccount.accountId.selector)
            || selector == uint32(IAccountExecute.executeUserOp.selector)
            || selector == uint32(IModularAccountBase.performCreate.selector)
            || selector == uint32(IModularAccountBase.invalidateDeferredValidationInstallNonce.selector)
            || selector == uint32(IERC1271.isValidSignature.selector)
        // check against IModularAccountView methods
        || selector == uint32(IModularAccountView.getExecutionData.selector)
            || selector == uint32(IModularAccountView.getValidationData.selector)
        // check against IERC165 methods
        || selector == uint32(IERC165.supportsInterface.selector)
        // check against UUPSUpgradeable methods
        || selector == uint32(UUPSUpgradeable.proxiableUUID.selector)
            || selector == uint32(UUPSUpgradeable.upgradeToAndCall.selector)
        // Check against token receiver methods
        || selector == uint32(IERC721Receiver.onERC721Received.selector)
            || selector == uint32(IERC1155Receiver.onERC1155Received.selector)
            || selector == uint32(IERC1155Receiver.onERC1155BatchReceived.selector);
    }
}
